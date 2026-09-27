/*
 * runner.js - one file at a time, with a verdict at the end.
 *
 * The runner is the parent process and holds all the test code. It boots a
 * device host per file against a freshly restored device state, runs that
 * file's suite, tears the host down, and moves on. Nothing is shared between
 * files except the run directory - which is what removes the cross
 * contamination that forced the old kit to be run by hand, one file per
 * invocation.
 *
 * Fail-fast is the default. Three watchdogs bound a run - a per-test deadline
 * (the harness owns it), a no-progress inactivity budget, and a run-level
 * maximum - and all three cancel through a signal every device wait honours, so
 * a watchdog stops the work rather than merely reporting on work that is still
 * going.
 */
'use strict';

const fs = require('fs');
const path = require('path');

const harness = require('./harness');
const fixtures = require('./fixtures');
const { Reporter, EXIT } = require('./report');
const { TIMEOUTS } = require('./config');
const { detect } = require('./capabilities');
const { RUNS_ROOT, TEST_ROOT } = require('./paths');
const { EmulatedTransport, FATAL } = require('./device/emulated');
const { HardwareTransport } = require('./device/hardware');
const { Device } = require('./device');

/* ---- discovery ----------------------------------------------------------- */

function listSections() {
  if (!fs.existsSync(TEST_ROOT)) return [];
  return fs.readdirSync(TEST_ROOT)
    .filter((d) => fs.statSync(path.join(TEST_ROOT, d)).isDirectory())
    .sort();
}

function filesIn(dir) {
  return fs.readdirSync(dir)
    .filter((f) => f.endsWith('.test.js'))
    .sort()
    .map((f) => path.join(dir, f));
}

/**
 * Turn command-line targets into an ordered file list.
 * A target is a section name ('01-protocol'), a directory, or a single file.
 * With none, every section runs in order - the sections are numbered so that
 * order is visible in the tree rather than encoded somewhere else.
 */
function resolveTargets(targets = []) {
  if (!targets.length) {
    return listSections().flatMap((s) => filesIn(path.join(TEST_ROOT, s)));
  }

  const out = [];
  for (const target of targets) {
    const candidates = [target, path.join(TEST_ROOT, target), path.resolve(target)];
    const hit = candidates.find((c) => fs.existsSync(c));
    if (!hit) throw new Error(`no such test target: ${target}`);
    out.push(...(fs.statSync(hit).isDirectory() ? filesIn(hit) : [path.resolve(hit)]));
  }
  return out;
}

/** Load a file's registrations without running anything. */
function loadFile(file) {
  harness.clear();
  delete require.cache[require.resolve(file)];
  require(file);
  return harness.getRegisteredSuites();
}

/* ---- watchdogs ----------------------------------------------------------- */

/*
 * A watchdog must report WHERE it was blocked - which request was pending, when
 * the last device output arrived, what it was waiting for - because otherwise a
 * stalled transport and a genuinely slow device look identical, which is the
 * failure mode this whole kit is designed to eliminate.
 */
class Watchdogs {
  constructor({ inactivityMs, runMaxMs, onFire }) {
    this.inactivityMs = inactivityMs;
    this.runMaxMs = runMaxMs;
    this.onFire = onFire || (() => {});
    this.controller = new AbortController();
    this.fired = null;
    this.startedAt = Date.now();
    this.lastProgress = Date.now();
    this.device = null;
    this._timer = null;
  }

  get signal() { return this.controller.signal; }

  touch() { this.lastProgress = Date.now(); }

  start() {
    this._timer = setInterval(() => this._check(), 1000);
    this._timer.unref();
  }

  stop() {
    if (this._timer) clearInterval(this._timer);
    this._timer = null;
  }

  _lastActivity() {
    /* Any traffic counts, not just the debug console: typing a backup is 46
     * seconds of keyboard reports with nothing on the console, and that is a
     * device working, not a device stalled. */
    const consoleAt = (this.device && this.device.log.lastAppendAt) || 0;
    const trafficAt = (this.device && this.device.lastTrafficAt) || 0;
    return Math.max(this.lastProgress, consoleAt, trafficAt);
  }

  _check() {
    if (this.fired) return;
    const now = Date.now();

    if (this.runMaxMs && now - this.startedAt > this.runMaxMs) {
      return this._fire('run-max',
        `the run exceeded its ${Math.round(this.runMaxMs / 1000)}s maximum`);
    }

    const idle = now - this._lastActivity();
    if (this.inactivityMs && idle > this.inactivityMs) {
      return this._fire('inactivity',
        `no progress for ${Math.round(idle / 1000)}s (budget ${Math.round(this.inactivityMs / 1000)}s)`);
    }
    return undefined;
  }

  _fire(kind, reason) {
    const where = this.device ? this.device.snapshot() : null;
    this.fired = {
      kind,
      reason,
      pending: where ? where.pending : [],
      lastOutputAgoMs: where && where.lastOutputAt ? Date.now() - where.lastOutputAt : null,
      generation: where ? where.generation : null,
    };
    this.stop();
    this.onFire(this.fired);
    this.controller.abort(new Error(`${kind} watchdog: ${reason}`));
  }
}

/* ---- the run ------------------------------------------------------------- */

function newRunDir(runsRoot = RUNS_ROOT) {
  const now = new Date();
  const stamp = now.toISOString().replace(/[-:]/g, '').replace(/\..+$/, '').replace('T', '-');
  const runId = `${stamp}-${process.pid}`;
  return { runDir: path.join(runsRoot, runId), runId };
}

/**
 * @param {object} opts
 *   targets     string[]  sections, directories or files
 *   testFilter  (testName, suiteName) => boolean
 *   adapter     'emulated' | 'hardware'
 *   quiet       do not echo the log to stdout
 * @returns {Promise<{code:number, reporter:Reporter}>}
 */
async function run(opts = {}) {
  const { runDir, runId } = newRunDir(opts.runsRoot);
  const reporter = new Reporter({ runDir, runId, quiet: opts.quiet });
  const adapter = opts.adapter || 'emulated';
  const caps = detect({ adapter });

  const counts = { passed: 0, failed: 0, skipped: 0 };
  const finish = (status, reason, code) => {
    watchdogs.stop();
    return { code: reporter.finish({ status, reason, code, counts }), reporter };
  };

  const watchdogs = new Watchdogs({
    inactivityMs: opts.inactivityMs || TIMEOUTS.INACTIVITY,
    runMaxMs: opts.runMaxMs || TIMEOUTS.RUN_MAX,
    onFire: (info) => {
      reporter.log(`WATCHDOG ${info.kind}: ${info.reason}`);
      reporter.log(`  pending   : ${info.pending.length ? info.pending.join('; ') : 'nothing'}`);
      reporter.log(`  last output: ${info.lastOutputAgoMs === null ? 'never' : `${info.lastOutputAgoMs}ms ago`}`);
      reporter.log(`  generation : ${info.generation}`);
    },
  });

  reporter.log(`run ${runId}`);
  reporter.log(`adapter    : ${adapter}`);
  reporter.log(`mmap rung  : ${caps.rung.name} (vm.mmap_min_addr=${caps.rung.minAddr})`);
  for (const cap of caps.list()) {
    reporter.log(`  ${cap.ok ? 'yes' : 'no '} ${cap.name}${cap.ok ? '' : ` - ${cap.why}`}`);
  }

  let files;
  try {
    files = resolveTargets(opts.targets);
  } catch (err) {
    reporter.log(`ERROR ${err.message}`);
    return finish('aborted', err.message, EXIT.RUNNER_ERROR);
  }

  if (!files.length) {
    return finish('aborted', 'no test files matched', EXIT.RUNNER_ERROR);
  }
  reporter.log(`files      : ${files.length}`);

  watchdogs.start();

  for (const file of files) {
    const rel = shortName(file);
    const section = rel.split(path.sep)[0];
    watchdogs.touch();
    reporter.update({ section, file: rel, suite: null, test: null, status: 'loading' });
    reporter.log(`\n--- ${rel}`);

    /* A file that will not load is a runner error, not a device verdict. */
    let suites;
    try {
      suites = loadFile(file);
    } catch (err) {
      reporter.log(`ERROR could not load ${rel}: ${err.stack || err.message}`);
      return finish('aborted', `could not load ${rel}: ${err.message}`, EXIT.RUNNER_ERROR);
    }

    if (!suites.length) {
      return finish('aborted', `${rel} registered no suites`, EXIT.RUNNER_ERROR);
    }
    if (suites.length > 1) {
      return finish('aborted',
        `${rel} registered ${suites.length} suites; files are flat - one suite per file`,
        EXIT.RUNNER_ERROR);
    }

    const meta = suites[0].meta || {};
    const outcome = await runOneFile({
      file, rel, section, meta, caps, runDir, runId, reporter, watchdogs, counts, opts, adapter,
    });

    if (outcome.stop) {
      watchdogs.stop();
      return { code: reporter.finish({ ...outcome.end, counts }), reporter };
    }
  }

  watchdogs.stop();
  const code = counts.failed > 0 ? EXIT.TEST_FAILURE : EXIT.PASS;
  return finish(
    'finished',
    counts.failed > 0 ? `${counts.failed} test(s) failed` : 'all tests passed',
    code
  );
}

/**
 * Run one file. Returns {stop:false} to continue, or {stop:true, end:{...}} with
 * the run-ending verdict.
 */
async function runOneFile(ctx) {
  const { rel, meta, caps, runDir, reporter, watchdogs, counts, opts, adapter } = ctx;
  const emulated = adapter === 'emulated';

  /*
   * A file whose capabilities are not met is SKIPPED with a stated reason, not
   * failed. Its tests still appear in the results - a result set that silently
   * omits tests cannot be compared against what the file said it covered.
   */
  const missing = caps.missing(meta.requires || []);
  if (missing) {
    reporter.log(`skipping ${rel}: it ${missing}`);
    const results = await harness.run({ skipAll: missing, log: (m) => reporter.log(`  ${m}`) });
    tally(counts, results);
    reporter.update({ passed: counts.passed, failed: counts.failed, skipped: counts.skipped });
    return { stop: false };
  }

  /*
   * A file can declare that it needs no device at all - `device: false`.
   *
   * The sanity section is all such files: they check the kit's own pure-JS
   * oracles (CBOR, the keystroke decoder, the framing, the backup format)
   * against known answers. Booting a device host for them would cost a second
   * each and prove nothing - and worse, it would make the cheapest tests in the
   * tree depend on the most expensive machinery in it.
   */
  if (meta.device === false) {
    reporter.log('device     : not required by this file');
    reporter.update({ status: 'running' });

    const results = await harness.run({
      device: null,
      log: (m) => reporter.log(`  ${m}`),
      timeoutMs: opts.timeoutMs || TIMEOUTS.PER_TEST,
      failFast: true,
      testFilter: opts.testFilter,
      testOrder: opts.testOrder,
      onTestStart: ({ suiteName, testName }) => {
        watchdogs.touch();
        reporter.update({ suite: suiteName, test: testName, status: 'running' });
      },
      onTestEnd: ({ result, suiteName, testName }) => {
        watchdogs.touch();
        /* The device-free path needs the same ledger as the device one - the
         * controls gate is about assertions, not about transports. */
        if (opts.controlLedger) {
          opts.controlLedger.push({
            file: rel, negative: !!meta.negative, suite: suiteName, test: testName,
            status: result.status,
            controls: result.controls || [], absents: result.absents || [],
          });
        }
        reporter.update({ status: result.status });
      },
    });

    tally(counts, results);
    reporter.update({ passed: counts.passed, failed: counts.failed, skipped: counts.skipped });
    if (!results.aborted) return { stop: false };

    const failed = failedTestOf(results);
    reporter.failure({
      file: rel,
      suite: results.aborted.suiteName,
      test: results.aborted.testName,
      error: failed && failed.error,
      reason: results.aborted.reason,
      device: null,
    });

    return {
      stop: true,
      end: watchdogs.fired
        ? {
          status: 'aborted',
          reason: `${watchdogs.fired.kind} watchdog: ${watchdogs.fired.reason}`,
          code: EXIT.WATCHDOG,
        }
        : { status: 'finished', reason: results.aborted.reason, code: EXIT.TEST_FAILURE },
    };
  }

  const fileDir = path.join(runDir, 'files', rel.replace(/[\\/]/g, '__').replace(/\.test\.js$/, ''));
  const storageDir = path.join(fileDir, 'storage');
  fs.mkdirSync(fileDir, { recursive: true });

  const fixtureFailed = (err) => {
    reporter.log(`ERROR fixture '${meta.state}' for ${rel}: ${err.stack || err.message}`);
    return {
      stop: true,
      end: {
        status: 'aborted',
        reason: `fixture '${meta.state}' would not build: ${err.message}`,
        code: EXIT.RUNNER_ERROR,
      },
    };
  };

  /*
   * Emulated: the state is restored as images BEFORE the device boots, so each
   * file starts from a fresh copy. Hardware: there is no image to push, so the
   * device is booted first and brought to the state afterwards by the same
   * state module's check-and-apply. That ordering difference is the whole
   * reason a state exports two functions.
   */
  if (emulated) {
    reporter.update({ status: 'preparing device state' });
    try {
      const prepared = await fixtures.prepare(meta.state, storageDir, {
        /*
         * Every fixture step is progress. A fixture is BUILT on a device of its
         * own, whose console and traffic the watchdog does not see, and it was
         * touched only once the build had finished - so a build longer than the
         * inactivity budget was killed mid-way as a stall. On Windows the
         * 'initialized' fixture (three PIN commits, then a reboot) takes ~35 s
         * against a 30 s budget: 01-protocol aborted in 03-wipe's fixture and
         * 05-security while booting, every time the fixture was not cached. A
         * build that truly hangs still stops logging, and is still caught.
         */
        log: (m) => { reporter.log(`  fixture: ${m}`); watchdogs.touch(); },
        capabilities: caps,
      });
      reporter.log(`state      : ${prepared.state}${prepared.restored ? ` (restored ${prepared.digest})` : ''}`);
      watchdogs.touch();
    } catch (err) {
      return fixtureFailed(err);
    }
  }

  /*
   * A file that declares it needs a kernel device node gets one: on the
   * emulated adapter that means raising the USB gadget in front of this run's
   * own device host, rather than pointing the tests at a daemon somebody else
   * is using. The capability check above has already established the gadget is
   * free, so by here it is a question of asking for it.
   *
   * The list matters. Keying this off `kernel-hid` alone meant that renaming a
   * file's requirement to the narrower `client-access` silently stopped the
   * gadget being raised - and the tests then failed with "hidapi sees 0",
   * which is a confusing way to learn about a typo in a capability name.
   */
  const NEEDS_BUS = ['kernel-hid', 'client-access', 'bus-detach'];
  const needsGadget = emulated && (meta.requires || []).some((r) => NEEDS_BUS.includes(r));

  const transport = emulated
    ? new EmulatedTransport({ runDir: fileDir, storageDir, gadget: needsGadget })
    : new HardwareTransport();

  if (needsGadget) reporter.log('bus        : raising the USB gadget for this file');
  const device = new Device(transport, { capabilities: caps, signals: [watchdogs.signal] });
  watchdogs.device = device;

  transport.on('selected', (d) => reporter.log(
    `device     : ${d.gadget ? 'EMULATOR GADGET' : 'physical key'} at ${d.usbPath}, ` +
    `interfaces ${d.interfaces.join(',')}`));
  transport.on('interface-unavailable', (i) => reporter.log(
    `  interface ${i.iface} unavailable (${i.reason}) - tests needing it will fail honestly`));
  transport.on('bus-detach', (d) => reporter.log(`  device left the USB bus (generation ${d.generation})`));
  /*
   * THE TWO TRANSITIONS THAT USED TO HAPPEN IN SILENCE.
   *
   * The hardware adapter closes every handle on a read error and then reopens
   * them if sysfs still shows the device - deliberately WITHOUT counting a
   * restart, because a stalled read on a device that never left the bus is not
   * a reboot and inventing one would corrupt every test that counts
   * generations. That is right, but it was also unlogged, so the one case where
   * it is WRONG - a genuine reboot whose bus absence is shorter than the
   * 3-sample debounce, or whose sysfs entry never lapses - was invisible.
   *
   * A restore is where that matters: it reboots as its completion, so a
   * swallowed reboot presents as `waitForReboot` timing out against a device
   * that is plainly alive and has plainly relocked. Seen once on 2026-08-06 in
   * `10-backup-restore`, which passed on a rerun - and there was nothing in the
   * log to say which of the two had happened. Now there is.
   */
  transport.on('interfaces-reopened', (d) => reporter.log(
    `  interfaces reopened WITHOUT counting a restart (still generation ${d.generation}) - ` +
    'the device never lapsed from sysfs, so this was read as a stalled handle rather ' +
    'than a reboot. If a reboot was expected here, this is where it went'));
  transport.on('interface-error', (i) => reporter.log(
    `  interface ${i.iface === null ? '(reopen)' : i.iface} errored: ${i.reason}`));
  transport.on('map-retry', (r) =>
    reporter.log(`  device host retry ${r.attempt}: the emulated flash could not be mapped`));
  transport.on('restart', (r) => reporter.log(`  device rebooted (generation ${r.generation})`));
  transport.on('fatal', (f) => reporter.log(`  DEVICE FATAL ${f.kind}: ${f.reason}`));

  const stopDevice = async () => {
    watchdogs.device = null;
    try { await transport.stop(); } catch { /* going away anyway */ }
  };

  reporter.update({ status: 'booting device' });
  try {
    await transport.start();
    /* Booted is not listening: the firmware drops debug input while it runs its
     * startup fades, so a file whose first test presses a button would lose it.
     * Pay the probe once here rather than in every file. */
    await device.waitReady();
    reporter.log(`device     : booted, generation ${transport.generation}` +
      (transport.socketElsewhere ? ` (socket at ${transport.socketPath})` : ''));
  } catch (err) {
    reporter.log(`ERROR device host: ${err.message}`);
    /*
     * A boot that a WATCHDOG cancelled is not a host that died - see
     * watchdogVerdict(). This used to fall straight into HOST_DIED, so a
     * run-max firing during a boot reported exit 5 while its own reason string
     * named the watchdog.
     *
     * The watchdog's code, and the boot kept in the sentence: which watchdog
     * fired is the verdict, and that it caught a device coming up rather than a
     * test running is the part somebody needs to know next.
     */
    const fired = watchdogVerdict(watchdogs);
    const verdict = deviceVerdict(transport, watchdogs)
      || (fired && { ...fired, reason: `${fired.reason}, while the device host was booting` })
      || {
        code: EXIT.HOST_DIED,
        reason: `the device host never finished booting: ${err.message}`,
      };
    reporter.failure({ file: rel, suite: meta.name || rel, test: '(boot)', reason: verdict.reason, device });
    await stopDevice();
    return { stop: true, end: { status: 'aborted', ...verdict } };
  }

  if (!emulated && meta.state) {
    reporter.update({ status: 'preparing device state' });
    try {
      const applied = await fixtures.ensureOnDevice(meta.state, device, {
        log: (m) => { reporter.log(`  fixture: ${m}`); watchdogs.touch(); },   /* see prepare() above */
      });
      reporter.log(`state      : ${applied.state}${applied.applied ? ' (applied to the key)' : ' (already)'}`);
      watchdogs.touch();
    } catch (err) {
      await stopDevice();
      return fixtureFailed(err);
    }
  }

  reporter.update({ status: 'running', generation: transport.generation });

  const results = await harness.run({
    device,
    log: (m) => reporter.log(`  ${m}`),
    timeoutMs: opts.timeoutMs || TIMEOUTS.PER_TEST,
    failFast: true,
    testFilter: opts.testFilter,
    testOrder: opts.testOrder,
    onTestStart: ({ suiteName, testName }) => {
      watchdogs.touch();
      reporter.update({
        suite: suiteName, test: testName, status: 'running',
        generation: transport.generation, pending: device.pending.list(),
      });
    },
    onTestEnd: ({ result, suiteName, testName }) => {
      watchdogs.touch();
      /*
       * The control ledger, carried up so `--controls` can judge without
       * re-running anything. Recorded for EVERY test rather than only for
       * declared-negative files, because "which tests prove their instrument"
       * is worth being able to ask of any of them.
       */
      if (opts.controlLedger) {
        opts.controlLedger.push({
          file: rel,
          negative: !!meta.negative,
          suite: suiteName,
          test: testName,
          status: result.status,
          controls: result.controls || [],
          absents: result.absents || [],
        });
      }
      reporter.update({
        status: result.status, generation: transport.generation,
        pending: device.pending.list(),
      });
    },
  });

  tally(counts, results);
  reporter.update({ passed: counts.passed, failed: counts.failed, skipped: counts.skipped });

  /* Report the failure before tearing the device down: the snapshot is only
   * worth anything while the device is still there to be asked. */
  if (results.aborted) {
    const failed = failedTestOf(results);
    reporter.failure({
      file: rel,
      suite: results.aborted.suiteName,
      test: results.aborted.testName,
      error: failed && failed.error,
      reason: results.aborted.reason,
      device,
    });
  }

  await stopDevice();

  if (!results.aborted) return { stop: false };

  /*
   * Precedence matters: a firmware crash CAUSES the test failure that follows
   * it, and reporting the effect instead of the cause is how a run ends up
   * blaming the test that happened to be running.
   */
  const deviceProblem = deviceVerdict(transport, watchdogs);
  if (deviceProblem) return { stop: true, end: { status: 'aborted', ...deviceProblem } };

  const fired = watchdogVerdict(watchdogs);
  if (fired) return { stop: true, end: { status: 'aborted', ...fired } };

  if (results.aborted.kind === 'test-timeout' || results.aborted.kind === 'uncancellable-test') {
    return {
      stop: true,
      end: { status: 'aborted', reason: results.aborted.reason, code: EXIT.WATCHDOG },
    };
  }

  return {
    stop: true,
    end: { status: 'finished', reason: results.aborted.reason, code: EXIT.TEST_FAILURE },
  };
}

function deviceVerdict(transport, watchdogs) {
  /* A device the watchdog killed is not a device that died on its own: stopping
   * the host is how a watchdog ends a wedged run, and classifying that as an
   * external kill would hide the watchdog behind exit 5. */
  if (!transport.fatal || watchdogs.fired) return null;

  const { kind, reason } = transport.fatal;
  if (kind === FATAL.FIRMWARE_CRASH) {
    return { reason, code: EXIT.FIRMWARE_CRASH };
  }
  return { reason, code: EXIT.HOST_DIED };
}

/**
 * The verdict a fired watchdog carries, or null if none fired.
 *
 * ONE function rather than a branch at each site, because the divergence this
 * replaces was caused by exactly that. deviceVerdict() above returns null when a
 * watchdog has fired, so that the watchdog gets to speak instead of exit 5 -
 * and the boot-failure path then fell straight through its `||` into a
 * hardcoded EXIT.HOST_DIED, doing the very thing that comment forbids. The
 * post-file path had the branch; the boot path never got it.
 *
 * Measured, 2026-08-05: a run-max that fired while a device host was booting
 * reported `code=5` with `reason="the device host never finished booting: ...:
 * run-max watchdog: the run exceeded its 900s maximum"`. The sentence was right
 * and the code was wrong, which is worse than both being wrong - 5 means "the
 * run produced no verdict", 3 means "a watchdog fired", and README's whole claim
 * is that the code tells them apart without reading anything.
 *
 * Pure, and exported for `00-sanity/05-exit-classification` - the same argument
 * that file already makes for classifyExit(): the cases that matter most are the
 * ones a normal run almost never produces, so they are checked directly rather
 * than waiting for a 900-second run to exercise a branch.
 *
 * @param {{fired: ?{kind: string, reason: string, pending: string[]}}} watchdogs
 * @returns {?{code: number, reason: string}}
 */
function watchdogVerdict(watchdogs) {
  const fired = watchdogs && watchdogs.fired;
  if (!fired) return null;
  const pending = fired.pending && fired.pending.length
    ? ` (pending: ${fired.pending.join('; ')})`
    : '';
  return {
    code: EXIT.WATCHDOG,
    reason: `${fired.kind} watchdog: ${fired.reason}${pending}`,
  };
}

/*
 * A file's name in log lines and run directories. Files inside the test tree
 * get their section-relative path; a file from somewhere else - a scratch
 * reproduction, a one-off - keeps its absolute path, because a relative one
 * from here is a wall of "../.." that names nothing.
 */
function shortName(file) {
  const rel = path.relative(TEST_ROOT, file);
  return rel.startsWith('..') ? file : rel;
}

function tally(counts, results) {
  counts.passed += results.passed;
  counts.failed += results.failed;
  counts.skipped += results.skipped;
}

function failedTestOf(results) {
  for (const suite of results.suites) {
    for (const test of suite.tests) {
      if (test.status === 'failed' || test.status === 'timeout') return test;
    }
  }
  return null;
}

/** Enumerate what would run, without touching the device. */
function list(targets = []) {
  const files = resolveTargets(targets);
  return files.map((file) => {
    const rel = shortName(file);
    try {
      const suites = loadFile(file);
      return { file: rel, ok: true, suites };
    } catch (err) {
      return { file: rel, ok: false, error: err.message, suites: [] };
    }
  });
}

module.exports = { run, list, resolveTargets, listSections, watchdogVerdict, EXIT };
