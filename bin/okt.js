#!/usr/bin/env node
/*
 * okt - the command line for the OnlyKey test kit.
 *
 *   okt run [target...]     run a section, a directory or a single file
 *   okt list [target...]    enumerate what would run, without a device
 *   okt caps                what this host can reach, and why not
 *   okt fixture <state>
  okt flash [hexfile]  [--no-reboot] [--delay <ms>]     build (or rebuild) a cached device state
 *   okt flash [hex]         program a key sitting in its HalfKay bootloader
 *
 * With no target, every section runs in order. Sections are numbered so that
 * order is visible in the tree rather than encoded somewhere else.
 *
 * The exit code is the verdict and needs nothing else read to interpret:
 *
 *   0  finished, everything passed
 *   1  finished, at least one test failed - the only code that means the device
 *      behaved and the software did not
 *   2  the firmware crashed
 *   3  a watchdog fired (per-test deadline, inactivity, or run maximum)
 *   4  harness or runner error - the kit failed before it could judge anything
 *   5  the device host died for a reason that is not the firmware's fault
 *
 * 0-3 are verdicts about the device. 4 and 5 say the run did not produce a
 * verdict at all, and that distinction is the whole point.
 */
'use strict';

const { EXIT } = require('../lib/report');

function usage() {
  console.log(`usage:
  okt run [target...]  [--hardware] [--test <substring>] [--isolate] [--reverse]
                       [--keep-going] [--controls] [--timeout <ms>] [--quiet]
  okt list [target...]
  okt caps
  okt fixture <state>
  okt flash [hexfile]  [--no-reboot] [--delay <ms>]
  okt byhand           [--only <id,id>] [--list] [--save-baseline]

okt byhand is section 06-byhand, and only runs this way - never with okt run.
It runs the real tools (python onlykey-cli, lib-agent, onlykey-js, gpg,
ssh-keygen) against a PHYSICAL key that is plugged in and LOCKED. You unlock
it with the PIN and press Enter once; after that you only press the key's
button when a red PRESS NOW appears. It stops at the first failure, and the
whole run is in runs/byhand-latest.log. The kit opens nothing, so the tools
get the key to themselves. --list shows the steps; --only runs some by id.
Each step's result is compared with test/06-byhand/baseline.json; a run of
every step that passes can replace it with --save-baseline.

targets are section names (01-protocol), directories, or single files.

--test runs the tests whose "<suite> <test>" contains the substring, which is
how a single endpoint is debugged on its own. A /regex/flags value is also
accepted, for when one endpoint's name contains another's:
--test '/\\bversion\\b/' selects "version" without also selecting "fwversion".

--isolate runs each selected test in ITS OWN device session and reports any that
cannot stand alone. It is the gate for new files, and costs a boot per test.

--reverse runs each file's tests back to front in one ordinary session. It costs
one run and catches the other order fault: a test that is BROKEN BY an earlier
one passes alone and passes in file order, so --isolate cannot see it. Between
the natural order, --reverse and --isolate, both directions are covered.

--keep-going runs past a file whose test FAILED, to the next file, instead of
ending the run there - so a known failure cannot hide the files after it. The
run still stops on anything that means the instrument is broken (the device
host dying, a watchdog, a timeout, a fixture that will not build). Use it for
baselines: every file is counted, and the summary names the failing files.

--controls is the gate for NEGATIVE assertions. A test that says "the device did
not reveal X" is worthless if the instrument was broken - the absence and the
bug look identical - so a file declaring negative:true in its suite metadata
must prove its instrument in every test, with assert.control(). This reports any
test in such a file that registered none. See test/05-security/README.md.

--hardware drives a physical key over /dev/hidraw instead of the emulator. The
emulator's USB gadget is excluded by default because it is indistinguishable
from a key by VID/PID; OKT_ALLOW_GADGET=yes targets it deliberately, and
OKT_USB_PATH picks one when several are attached.

exit codes: 0 pass  1 test failure  2 firmware crash  3 watchdog
            4 runner error  5 device host died`);
}

function parse(argv) {
  const out = {
    command: argv[2] || 'help', targets: [], filter: null,
    timeoutMs: null, quiet: false, adapter: 'emulated',
    reboot: true, delayMs: null, isolate: false, reverse: false, controls: false,
    keepGoing: false, only: [], list: false, saveBaseline: false,
  };
  for (let i = 3; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--test') out.filter = argv[++i];
    else if (a === '--timeout') out.timeoutMs = parseInt(argv[++i], 10);
    else if (a === '--quiet') out.quiet = true;
    else if (a === '--isolate') out.isolate = true;
    else if (a === '--reverse') out.reverse = true;
    else if (a === '--keep-going') out.keepGoing = true;
    else if (a === '--controls') out.controls = true;
    else if (a === '--hardware') out.adapter = 'hardware';
    else if (a === '--no-reboot') out.reboot = false;
    else if (a === '--delay') out.delayMs = parseInt(argv[++i], 10);
    else if (a === '--emulated') out.adapter = 'emulated';
    else if (a === '--only') out.only = String(argv[++i] || '').split(',').filter(Boolean);
    else if (a === '--list') out.list = true;
    else if (a === '--save-baseline') out.saveBaseline = true;
    else if (a === '--help' || a === '-h') { usage(); process.exit(0); }
    else if (a.startsWith('-')) { console.error(`unknown option: ${a}`); process.exit(EXIT.RUNNER_ERROR); }
    else out.targets.push(a);
  }
  return out;
}

/**
 * Turn a --test value into a predicate over "<suite> <test>".
 *
 * Substring by default, which is what a person types. `/re/flags` compiles as a
 * regular expression instead, and that escape hatch exists for one specific
 * reason rather than for generality: substring cannot separate an endpoint
 * whose name contains another endpoint's. Across onlykey-cli's 37 subcommands
 * there is exactly one such pair - `version` inside `fwversion` - so
 * `--test version` selects both and no amount of careful test naming fixes it.
 *
 *   --test getlabels          one test  (getkeylabels does not contain it)
 *   --test version            two       (fwversion contains version)
 *   --test '/\bversion\b/'    one
 */
function makeFilter(spec) {
  if (!spec) return undefined;

  const re = /^\/(.*)\/([a-z]*)$/.exec(spec);
  if (re) {
    const rx = new RegExp(re[1], re[2]);
    return (testName, suiteName) => rx.test(`${suiteName} ${testName}`);
  }
  return (testName, suiteName) => `${suiteName} ${testName}`.includes(spec);
}

/**
 * Run every selected test ALONE, in its own device session.
 *
 * `--test` already runs one test on its own, which is the debugging workflow
 * this exists to protect. What it cannot do is tell you whether that workflow
 * still WORKS: a test that quietly depends on an earlier one in its file passes
 * in a normal run and fails only when somebody isolates it, which is exactly
 * the moment they are already debugging something else. The dependency is
 * usually an unlock, and it surfaces as a timeout waiting for a device that was
 * never unlocked - a failure that names nothing.
 *
 * So this runs the file once per test, each with a fresh fixture and a fresh
 * boot, and reports which ones cannot stand alone. It is not for ordinary runs:
 * N boots costs roughly N x 2s and every test pays for its own setup. Use it
 * after adding tests, and when a file's isolation is in doubt.
 *
 * Each pass gets its own run directory, so the failing one's log is already on
 * disk under its own name rather than interleaved with the rest.
 */
/*
 * The controls gate: every test in a declared-negative file must prove its
 * instrument.
 *
 * WHAT IT CAN CHECK, and the limit is the honest part. A runner cannot look at
 * `assert.equal(count, 0)` and know it is a claim about an absence, so this
 * does not find negative assertions - it checks that files which DECLARE they
 * make them (`negative: true` in the suite metadata) have a positive control in
 * every test. `assert.absent()` already refuses to pass without one; this
 * catches the test that asserted an absence some other way and never proved
 * anything worked.
 *
 * One ordinary run, not a run per test - the ledger is collected as the tests
 * execute, so this costs what a normal run costs.
 */
async function runControls(args) {
  const { run } = require('../lib/runner');
  const { EXIT: CODES } = require('../lib/report');

  const ledger = [];
  const { code } = await run({
    targets: args.targets,
    adapter: args.adapter,
    quiet: true,
    timeoutMs: args.timeoutMs || undefined,
    testFilter: makeFilter(args.filter),
    controlLedger: ledger,
  });

  const declared = ledger.filter((e) => e.negative);
  if (!declared.length) {
    console.log('--controls: no file in this target declares `negative: true`, ' +
      'so there is nothing for this gate to check.');
    console.log('A section that asserts absences should say so in its suite ' +
      'metadata; see test/05-security/README.md.');
    return code;
  }

  const naked = declared.filter((e) => e.status === 'passed' && !e.controls.length);
  console.log(`--controls: ${declared.length} test(s) in declared-negative files\n`);
  for (const e of declared) {
    const mark = e.controls.length ? 'ok  ' : 'NONE';
    console.log(`  ${mark}  ${e.file}  ${e.test}`);
    for (const c of e.controls) console.log(`          control: ${c}`);
    for (const a of e.absents) console.log(`          absence: ${a}`);
  }

  if (naked.length) {
    console.log(`\n--controls: ${naked.length} test(s) proved no instrument:`);
    for (const e of naked) console.log(`  ${e.file}  ${e.test}`);
    console.log('\nAn absence asserted by a test that proved nothing works is ' +
      'indistinguishable from a broken instrument. Add assert.control().');
    return CODES.TEST_FAILURE;
  }

  console.log('\n--controls: every declared-negative test proved its instrument');
  return code;
}

async function runIsolated(args) {
  const { run, list } = require('../lib/runner');
  const { EXIT: CODES } = require('../lib/report');
  const match = makeFilter(args.filter);

  const wanted = [];
  for (const entry of list(args.targets)) {
    if (!entry.ok) {
      console.error(`${entry.file}  !! ${entry.error}`);
      return CODES.RUNNER_ERROR;
    }
    for (const suite of entry.suites) {
      for (const t of suite.tests) {
        if (match && !match(t.name, suite.name)) continue;
        wanted.push({ file: entry.file, suite: suite.name, test: t.name });
      }
    }
  }

  if (!wanted.length) {
    console.error('--isolate matched no tests');
    return CODES.RUNNER_ERROR;
  }

  console.log(`--isolate: ${wanted.length} test(s), one device session each\n`);

  const failed = [];
  let worst = 0;
  for (const [i, w] of wanted.entries()) {
    process.stdout.write(`[${i + 1}/${wanted.length}] ${w.file}  ${w.test} ... `);

    const { code } = await run({
      targets: args.targets,
      adapter: args.adapter,
      quiet: true,                            // the per-run log file is the record
      timeoutMs: args.timeoutMs || undefined,
      testFilter: (testName, suiteName) => testName === w.test && suiteName === w.suite,
    });

    /*
     * A pass here means the test needed nothing that ran before it. Anything
     * else is reported with its own run directory, because that is where the
     * failure block and the device output already are.
     */
    console.log(code === 0 ? 'alone: ok' : `ALONE: FAILED (exit ${code})`);
    if (code !== 0) { failed.push(w); worst = Math.max(worst, code); }
  }

  console.log('');
  if (!failed.length) {
    console.log(`--isolate: all ${wanted.length} test(s) stand alone`);
    return 0;
  }

  console.log(`--isolate: ${failed.length} of ${wanted.length} cannot run alone:`);
  for (const w of failed) console.log(`  ${w.file}  ${w.test}`);
  console.log('\nEach of these depends on something an earlier test in its file did.');
  return worst;
}

async function main() {
  const args = parse(process.argv);

  switch (args.command) {
    case 'run': {
      const { run } = require('../lib/runner');
      if (args.controls) { process.exit(await runControls(args)); }
      if (args.isolate) { process.exit(await runIsolated(args)); }

      const { code } = await run({
        targets: args.targets,
        adapter: args.adapter,
        quiet: args.quiet,
        timeoutMs: args.timeoutMs || undefined,
        testFilter: makeFilter(args.filter),
        testOrder: args.reverse ? 'reverse' : 'natural',
        keepGoing: args.keepGoing,
      });
      process.exit(code);
      break;
    }

    case 'list': {
      const { list } = require('../lib/runner');
      const { detect } = require('../lib/capabilities');
      const caps = detect({ adapter: args.adapter });

      console.log(`mmap rung: ${caps.rung.name} (vm.mmap_min_addr=${caps.rung.minAddr})`);
      for (const cap of caps.list()) {
        console.log(`  ${cap.ok ? '[x]' : '[ ]'} ${cap.name}${cap.ok ? '' : ` - ${cap.why}`}`);
      }
      console.log('');

      let files = 0;
      let tests = 0;
      for (const entry of list(args.targets)) {
        if (!entry.ok) {
          console.log(`${entry.file}  !! ${entry.error}`);
          continue;
        }
        files++;
        for (const suite of entry.suites) {
          const meta = suite.meta || {};
          const bits = [];
          if (meta.state) bits.push(`state=${meta.state}`);
          if (meta.requires && meta.requires.length) bits.push(`requires=${meta.requires.join(',')}`);
          const missing = caps.missing(meta.requires || []);
          console.log(`${entry.file}  ${suite.name}${bits.length ? `  [${bits.join(' ')}]` : ''}` +
            `${missing ? `  -> SKIPPED: it ${missing}` : ''}`);
          for (const t of suite.tests) {
            tests++;
            console.log(`    - ${t.name}`);
          }
        }
      }
      console.log(`\n${files} file(s), ${tests} test(s)`);
      break;
    }

    case 'caps': {
      const { detect } = require('../lib/capabilities');
      const caps = detect({ adapter: args.adapter });
      console.log(`adapter: ${caps.adapter}`);
      console.log(`rung: ${caps.rung.name} (vm.mmap_min_addr=${caps.rung.minAddr})`);
      for (const cap of caps.list()) {
        console.log(`  ${cap.ok ? '[x]' : '[ ]'} ${cap.name}${cap.ok ? '' : `\n        ${cap.why}`}`);
      }
      break;
    }

    case 'fixture': {
      const state = args.targets[0];
      if (!state) { usage(); process.exit(EXIT.RUNNER_ERROR); }
      const fixtures = require('../lib/fixtures');
      const { detect } = require('../lib/capabilities');
      const result = await fixtures.ensure(state, {
        log: (m) => console.log(`  ${m}`),
        capabilities: detect({ adapter: 'emulated' }),
      });
      console.log(`${state}: ${result.built ? 'built' : 'cached'} at ${result.dir}`);
      break;
    }

    case 'flash': {
      const { flash, waitForKey } = require('../lib/flash');
      const { DEFAULT_HEX } = require('../lib/paths');
      const hex = args.targets[0] || DEFAULT_HEX;

      if (!args.targets[0]) console.log(`using the sibling builder's output: ${hex}`);
      const result = flash(hex, {
        reboot: args.reboot,
        delayMs: args.delayMs || undefined,
        log: (m) => console.log(`  ${m}`),
      });

      if (args.reboot) {
        console.log(waitForKey()
          ? '  key is back on the bus'
          : '  key did NOT come back on the bus - check it');
      }
      console.log(`flashed ${result.blocks} blocks via ${result.devPath}`);
      break;
    }

    case 'byhand': {
      const { runByHand } = require('../lib/byhand');
      process.exit(await runByHand({ only: args.only, list: args.list, saveBaseline: args.saveBaseline }));
      break;
    }

    case 'help':
    default:
      usage();
      process.exit(args.command === 'help' ? 0 : EXIT.RUNNER_ERROR);
  }
}

main().catch((err) => {
  /*
   * The message, not the stack. Most of what surfaces here is an instruction
   * to the operator - tap the bootloader button, plug the key in, point at a
   * hex that exists - and a ten-frame trace buries it. OKT_DEBUG=1 brings the
   * trace back for the times it is genuinely a bug in the kit.
   */
  console.error(`okt: ${err && err.message ? err.message : err}`);
  if (process.env.OKT_DEBUG && err && err.stack) console.error(err.stack);
  process.exit(EXIT.RUNNER_ERROR);
});
