/*
 * harness.js - suites, tests, assertions, and a run that returns a verdict.
 *
 * This started life driving tests from inside an app and is kept deliberately,
 * because its shape is already the right one and is the reason mocha is not
 * wanted here: suites and tests are plain registrations, assertions are a few
 * small functions rather than a chained expectation language, everything a test
 * needs is injected into it rather than reached for through globals, and a run
 * returns a data structure instead of printing at a human. That last property
 * is what the whole reporting design rests on - the run result IS the verdict,
 * so the exit code and the sentinel line are read off it rather than
 * reconstructed from output.
 *
 * There are no before/after hooks and there will not be. That is the same
 * decision as starting long-lived services from visible test files: a hook is
 * an invisible step, and an invisible step is exactly what makes a wedge
 * unattributable.
 *
 * Usage:
 *   const h = require('../../lib/harness');
 *   h.describe('suite name', { state: 'initialized', requires: ['crypto'] }, () => {
 *     h.it('does something', async ({ device, assert, signal, skip }) => { ... });
 *   });
 */
'use strict';

/* ---- registry ----------------------------------------------------------- */

let suites = [];
let currentSuite = null;

/**
 * @param {string} name
 * @param {object|function} metaOrFn  suite metadata, or the body
 * @param {function} [maybeFn]        the body, when metadata was given
 *
 * Metadata is what lets the runner prepare the device and skip a file with a
 * stated reason rather than failing it obscurely:
 *   state     name of the device state this file needs ('blank', 'initialized')
 *   requires  capability names (see lib/capabilities.js)
 *   timeoutMs per-test deadline for this file, overriding the run default
 */
function describe(name, metaOrFn, maybeFn) {
  const fn = typeof metaOrFn === 'function' ? metaOrFn : maybeFn;
  const meta = typeof metaOrFn === 'function' ? {} : (metaOrFn || {});
  if (typeof fn !== 'function') {
    throw new Error(`describe('${name}') needs a body function`);
  }

  const suite = { name, meta, tests: [] };
  suites.push(suite);
  currentSuite = suite;
  try {
    fn();
  } finally {
    currentSuite = null;
  }
}

function it(name, fn) {
  if (!currentSuite) throw new Error('it() must be called inside describe()');
  if (typeof fn !== 'function') throw new Error(`it('${name}') needs a body function`);
  currentSuite.tests.push({ name, fn });
}

/*
 * Registration is a side effect of loading a file, which is fine because the
 * runner loads exactly one file at a time - and clears the registry between
 * them. That per-file isolation is also what keeps one suite's failure from
 * renumbering another's.
 */
function clear() {
  suites = [];
  currentSuite = null;
}

function getRegisteredSuites() {
  return suites.map((s) => ({
    name: s.name,
    meta: s.meta,
    tests: s.tests.map((t) => ({ name: t.name })),
  }));
}

/* ---- assertions ---------------------------------------------------------
 * Grows only as tests actually need it. Every message says what was expected
 * and what was seen, because the message is all a post-mortem reader gets.
 */

class AssertionError extends Error {
  constructor(message) {
    super(message);
    this.name = 'AssertionError';
  }
}

/** Thrown by ctx.skip(). Carried, not swallowed - a skip needs its reason. */
class SkipError extends Error {
  constructor(reason) {
    super(reason || 'skipped');
    this.name = 'SkipError';
    this.reason = reason || 'skipped';
  }
}

function ok(cond, msg) {
  if (!cond) throw new AssertionError(msg || 'expected a truthy value');
}

function equal(a, b, msg) {
  if (a !== b) throw new AssertionError(msg || `expected ${fmt(b)}, got ${fmt(a)}`);
}

function notEqual(a, b, msg) {
  if (a === b) throw new AssertionError(msg || `expected anything but ${fmt(b)}`);
}

function match(value, re, msg) {
  const text = String(value);
  if (!re.test(text)) {
    throw new AssertionError(
      msg || `expected /${re.source}/ to match, in: ${fmt(tailOf(text, 400))}`
    );
  }
}

function includes(haystack, needle, msg) {
  if (!String(haystack).includes(needle)) {
    throw new AssertionError(
      msg || `expected to find ${fmt(needle)}, in: ${fmt(tailOf(String(haystack), 400))}`
    );
  }
}

/**
 * Two byte strings, equal.
 *
 * Buffer.compare() in an equal() says "expected 0, got 1", which for a
 * kilobyte of key material is no help at all. What a reader needs is the first
 * offset that differs, because on a structured value the offset IS the
 * diagnosis - a 1216-byte X-Wing recipient that first differs at 1184 is a
 * correct pk_M with a wrong pk_X, and one that differs at 0 is neither.
 */
function bytes(actual, expected, msg) {
  const a = Buffer.from(actual);
  const b = Buffer.from(expected);
  const prefix = msg ? `${msg}: ` : '';
  if (a.length !== b.length) {
    throw new AssertionError(`${prefix}expected ${b.length} bytes, got ${a.length}`);
  }
  const at = a.compare(b) === 0 ? -1 : firstDiff(a, b);
  if (at >= 0) {
    throw new AssertionError(
      `${prefix}differs at byte ${at} of ${a.length}: ` +
      `expected ${window(b, at)}, got ${window(a, at)}`
    );
  }
}

function firstDiff(a, b) {
  for (let i = 0; i < a.length; i += 1) if (a[i] !== b[i]) return i;
  return -1;
}

/** Eight bytes from `at`, so the failure shows context and not one octet. */
function window(buf, at) {
  const end = Math.min(buf.length, at + 8);
  return `${buf.subarray(at, end).toString('hex')}${end < buf.length ? '…' : ''}`;
}

/** Asserts that `fn` rejects (or throws), and returns the error for inspection. */
async function rejects(fn, re, msg) {
  let err = null;
  try {
    await fn();
  } catch (e) {
    err = e;
  }
  if (!err) throw new AssertionError(msg || 'expected a rejection, got none');
  if (re) match(err.message || String(err), re, msg);
  return err;
}

/* ---- controls, and the absences that depend on them ---------------------- */

/*
 * NO NEGATIVE ASSERTION COUNTS UNLESS A POSITIVE CONTROL IN THE SAME TEST FIRES.
 *
 * This is section 5's second harness prerequisite, and it exists because a
 * suite built on "the device did not reveal X" is a suite where a BROKEN
 * INSTRUMENT READS AS A PASS. This kit has produced five of those, and every
 * one looked like a clean result at the time:
 *
 *   | what read as an absence | what it actually was |
 *   |---|---|
 *   | no plaintext in the RSA slot tail | `readyForKeygen()` RESTARTS, and a reboot zeroes the global holding the residue |
 *   | still none, second attempt | `flash.bin` is word-reversed - the search had the wrong byte order |
 *   | silence from an unknown vendor id | a CTAPHID error frame on the vendor interface |
 *   | "the Tools tab has six anchors and nothing else" | a regex that stopped at the first `<dialog>` |
 *   | run 20260806-122122 had "zero interface errors" | the runner did not subscribe to that event until nine minutes later |
 *   | "the device did not stage an HMAC response" | a keyboard_buffer wiped five seconds after it landed |
 *
 * The first two would have closed a real finding as "nothing there". The last
 * three were mine, in one day, with the rule already written down.
 *
 * `01-protocol/22-rsa-slot-tail` is the pattern this generalises: it writes a
 * known marker through a path that is NOT encrypted, finds it, and only then
 * believes an absence elsewhere in the same dump. Prove the instrument in the
 * same test, or the absence means nothing.
 *
 * WHAT THIS CAN AND CANNOT ENFORCE, said plainly because the limit matters.
 * A runner cannot look at `assert.equal(count, 0)` and know it is a claim about
 * absence - so this does not detect negative assertions, it gives them a form.
 * `assert.absent()` REFUSES to pass unless `assert.control()` has already fired
 * in the same test. Using a plain assertion instead still works and is still
 * unchecked; what the `--controls` gate adds is that a file which DECLARES it
 * makes negative assertions (`negative: true`) fails if any of its tests
 * registered no control at all. The discipline is the author's. The gate makes
 * forgetting it visible, which is all a gate can do.
 */
class MissingControlError extends AssertionError {}

/* Set per test by run(); null outside one, so a stray call says so. */
let controlLedger = null;

/**
 * Record that a positive control FIRED - the instrument works.
 *
 * @param {string} what  what this proves is working, in words
 * @param {*} [cond]     optional condition; when given it must be truthy
 */
function control(what, cond = true) {
  if (!controlLedger) {
    throw new AssertionError('assert.control() called outside a test');
  }
  if (!cond) {
    throw new AssertionError(
      `the positive control did not fire: ${what}. Nothing this test says ` +
      'about an absence can be believed until it does');
  }
  controlLedger.fired.push(what);
}

/**
 * Assert that something is ABSENT, which only counts if a control has fired.
 *
 * @param {*} cond      truthy when the thing really is absent
 * @param {string} msg  what is absent, and why that matters
 */
function absent(cond, msg = 'expected an absence') {
  if (!controlLedger) {
    throw new AssertionError('assert.absent() called outside a test');
  }
  controlLedger.absents.push(msg);
  if (!controlLedger.fired.length) {
    throw new MissingControlError(
      `${msg} - REFUSED: no positive control fired in this test, so an absence ` +
      'here is equally consistent with a broken instrument. Call ' +
      'assert.control() with something that proves the instrument works first');
  }
  if (!cond) throw new AssertionError(msg);
}

const assert = {
  ok, equal, notEqual, match, includes, bytes, rejects,
  control, absent,
  AssertionError, MissingControlError,
};

/* ---- running ------------------------------------------------------------ */

/**
 * Run every registered suite.
 *
 * @param {object} context injected into every test, plus:
 *   timeoutMs   per-test deadline (0 disables)
 *   graceMs     how long a cancelled test may take to unwind before the run
 *               is declared unresponsive
 *   failFast    stop at the first failure (default true)
 *   skipAll     reason string - record every test as skipped without running it
 *   testFilter  (testName, suiteName) => boolean
 *   testOrder   'natural' (default) | 'reverse' - the order to run a suite's
 *               tests in. See the note above the reordering itself.
 *   onTestStart / onTestUpdate / onTestEnd
 *
 * @returns {Promise<object>} results, including `aborted` when the run stopped
 *          early. The caller reads its exit code off this - it never prints.
 */
async function run(context = {}) {
  const {
    timeoutMs = 0,
    graceMs = 2000,
    failFast = true,
    skipAll = null,
    testFilter,
    testOrder = 'natural',
    onTestStart,
    onTestEnd,
    onTestUpdate,
  } = context;

  const log = typeof context.log === 'function'
    ? context.log
    : (...args) => { try { console.log('[harness]', ...args); } catch { /* ignore */ } };

  const results = {
    suites: [],
    passed: 0,
    failed: 0,
    skipped: 0,
    aborted: null,      // {kind, reason, suiteName, testName}
    startedAt: Date.now(),
    durationMs: 0,
  };

  outer:
  for (const suite of suites) {
    const suiteRes = { name: suite.name, meta: suite.meta, tests: [] };
    results.suites.push(suiteRes);
    log(`suite: ${suite.name}`);

    const suiteTimeout = Number.isFinite(suite.meta && suite.meta.timeoutMs)
      ? suite.meta.timeoutMs
      : timeoutMs;

    /*
     * The order a suite's tests run in, and why it is worth being able to
     * change.
     *
     * There are two ways a test can be wrong about order, and they need
     * different instruments. A test that DEPENDS on an earlier one fails when
     * run alone, which is what `okt run <file> --isolate` measures. A test that
     * is BROKEN BY an earlier one passes alone and passes in the natural order
     * too, right up until something is inserted before it - and --isolate
     * cannot see that at all, because alone is exactly the case that works.
     *
     * Reversing catches the second kind, and it catches precisely what the
     * natural order does not: if A leaves state that spoils B, then A-then-B
     * already fails; if B leaves state that spoils A, only B-then-A does.
     * Between them the two orders cover both directions, and reversing costs
     * one ordinary run rather than one boot per test.
     *
     * Reverse rather than shuffle on purpose: a failure has to be reproducible
     * by rerunning the same command, and a shuffle would need a seed carried
     * around to give that.
     */
    const tests = testOrder === 'reverse' ? [...suite.tests].reverse() : suite.tests;

    for (const t of tests) {
      const testRes = {
        name: t.name,
        status: 'skipped',
        reason: null,
        error: null,
        durationMs: 0,
        startedAt: null,
      };
      suiteRes.tests.push(testRes);

      /*
       * A filtered-out test is recorded as skipped with its reason rather than
       * dropped from the results. A result set that silently omits tests cannot
       * be compared against the file's own listing, which is what tells a
       * reader that a run covered what it claimed to.
       */
      if (typeof testFilter === 'function' && !testFilter(t.name, suite.name)) {
        testRes.reason = 'filtered out';
        results.skipped++;
        continue;
      }

      if (skipAll) {
        testRes.reason = skipAll;
        results.skipped++;
        log(`  -    ${t.name} (${skipAll})`);
        continue;
      }

      testRes.startedAt = Date.now();
      emit(onTestStart, { suiteName: suite.name, testName: t.name });
      emit(onTestUpdate, { suiteName: suite.name, testName: t.name, status: 'running' });

      /*
       * A real cancellation path.
       *
       * The old shape raced the test against a timer and let the loser keep
       * running - so a "timed out" test carried on driving the device while the
       * runner moved to the next one, and the next failure belonged to nobody.
       *
       * Now the timeout aborts a controller that every device wait honours, so
       * the test's own pending promise rejects and the test unwinds. If it does
       * not unwind within graceMs it is unresponsive to cancellation and the
       * run stops rather than continuing alongside it: there is no way to kill
       * a running async function, so the only honest outcomes are "it stopped"
       * and "the run is over".
       */
      const controller = new AbortController();
      controlLedger = { fired: [], absents: [] };
      const testCtx = {
        ...context,
        assert,
        signal: controller.signal,
        skip: (reason) => { throw new SkipError(reason); },
      };

      let timer = null;
      let graceTimer = null;
      let timedOut = false;
      let unresponsive = false;

      const settled = (async () => t.fn(testCtx))();
      /* Nothing awaits this copy synchronously; keep Node from reporting it as
       * an unhandled rejection while the grace window is still open. */
      settled.catch(() => {});

      /*
       * The grace window has to be part of what is AWAITED, not something
       * checked afterwards. Awaiting the test itself and then asking whether it
       * unwound never gets to the asking: an uncancellable test never settles,
       * so the await never returns and the whole run hangs on precisely the
       * case the grace window exists to catch. Measured, before this was a
       * race: exit 3 arrived never, and the inactivity watchdog fired into a
       * runner that could not act on it.
       */
      const expired = suiteTimeout > 0
        ? new Promise((resolve) => {
          timer = setTimeout(() => {
            timedOut = true;
            controller.abort(new Error(`test exceeded ${suiteTimeout}ms`));
            graceTimer = setTimeout(() => { unresponsive = true; resolve(); }, graceMs);
          }, suiteTimeout);
        })
        : null;

      try {
        if (expired) await Promise.race([settled, expired]);
        else await settled;

        if (unresponsive) throw new Error(`ignored cancellation for ${graceMs}ms`);
        /* Finished, but only after the deadline - still a timeout. */
        if (timedOut) throw new Error(`test exceeded ${suiteTimeout}ms`);

        testRes.status = 'passed';
        results.passed++;
        log(`  ok   ${t.name}`);
      } catch (err) {
        if (err instanceof SkipError) {
          testRes.status = 'skipped';
          testRes.reason = err.reason;
          results.skipped++;
          log(`  -    ${t.name} (${err.reason})`);
        } else if (timedOut) {
          testRes.status = 'timeout';
          testRes.reason = `no result within ${suiteTimeout}ms`;
          testRes.error = errText(err);
          results.failed++;
          log(`  TIME ${t.name} - ${testRes.reason}`);
        } else {
          testRes.status = 'failed';
          testRes.error = errText(err);
          results.failed++;
          log(`  FAIL ${t.name} - ${testRes.error}`);
        }
      } finally {
        if (timer) clearTimeout(timer);
        if (graceTimer) clearTimeout(graceTimer);
        testRes.durationMs = Date.now() - testRes.startedAt;
        /*
         * Carried on the RESULT so the --controls gate can read it without
         * re-running anything, and cleared immediately so a call from outside a
         * test says so rather than landing in the previous test's ledger.
         */
        testRes.controls = controlLedger ? controlLedger.fired : [];
        testRes.absents = controlLedger ? controlLedger.absents : [];
        controlLedger = null;
      }

      emit(onTestUpdate, {
        suiteName: suite.name, testName: t.name,
        status: testRes.status, error: testRes.error, reason: testRes.reason,
      });
      emit(onTestEnd, { suiteName: suite.name, testName: t.name, result: testRes });

      if (timedOut) {
        /*
         * Two different endings. A test that honours its signal has unwound by
         * now and the run stops with a plain timeout. One that has not is STILL
         * RUNNING - there is no way to kill a running async function - so
         * carrying on would mean two tests driving the same device, and the
         * only honest thing left is to end the run and say why.
         */
        results.aborted = {
          kind: unresponsive ? 'uncancellable-test' : 'test-timeout',
          reason: unresponsive
            ? `${suite.name} / ${t.name}: ignored cancellation for ${graceMs}ms after ` +
              `its ${suiteTimeout}ms deadline - the run cannot continue alongside it`
            : `${suite.name} / ${t.name}: no result within ${suiteTimeout}ms`,
          suiteName: suite.name,
          testName: t.name,
        };
        break outer;
      }

      if (failFast && testRes.status === 'failed') {
        results.aborted = {
          kind: 'fail-fast',
          reason: `${suite.name} / ${t.name} failed`,
          suiteName: suite.name,
          testName: t.name,
        };
        break outer;
      }
    }
  }

  /*
   * A stopped run still has to account for the tests it never reached.
   * Dropping them makes the result set uncomparable with the file's own
   * listing, and "4 tests, 1 failed" then quietly means something different
   * from "4 tests, 1 failed, 3 never ran".
   */
  if (results.aborted) {
    for (const suite of suites) {
      let suiteRes = results.suites.find((s) => s.name === suite.name);
      if (!suiteRes) {
        suiteRes = { name: suite.name, meta: suite.meta, tests: [] };
        results.suites.push(suiteRes);
      }
      for (const t of suite.tests) {
        if (suiteRes.tests.some((x) => x.name === t.name)) continue;
        suiteRes.tests.push({
          name: t.name,
          status: 'skipped',
          reason: 'not run - the run stopped before reaching it',
          error: null,
          durationMs: 0,
          startedAt: null,
        });
        results.skipped++;
      }
    }
  }

  results.durationMs = Date.now() - results.startedAt;
  return results;
}

/* ---- helpers ------------------------------------------------------------ */

function emit(fn, payload) {
  if (typeof fn !== 'function') return;
  try { fn(payload); } catch { /* a reporter must never fail a test */ }
}

function errText(e) {
  if (!e) return String(e);
  if (e instanceof AssertionError) return e.message;
  return e.stack || e.message || String(e);
}

function fmt(v) {
  if (typeof v === 'string') return JSON.stringify(v);
  if (Buffer.isBuffer(v)) {
    return `<Buffer ${v.subarray(0, 32).toString('hex')}${v.length > 32 ? '…' : ''}>`;
  }
  return String(v);
}

function tailOf(text, n) {
  return text.length <= n ? text : `…${text.slice(-n)}`;
}

module.exports = {
  describe, it, run, clear, getRegisteredSuites,
  assert, ok, equal, notEqual, match, includes, bytes, rejects,
  AssertionError, SkipError,
};
