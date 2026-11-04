/*
 * config.js - the handful of constants the whole kit agrees on.
 */
'use strict';

const path = require('path');
const os = require('os');

/*
 * Test PINs. Buttons are 1-6, so digits are restricted to 1-6, and all three
 * must be distinct - the firmware chains primary -> secondary -> self-destruct
 * PIN entry as one continuous setup flow, and a repeat would commit the wrong
 * one somewhere in the middle without saying so.
 *
 * These are for the emulator and for disposable hardware. Nothing here should
 * ever be pointed at a key somebody uses.
 */
const PINS = {
  primary: '1111111',
  secondary: '2222222',
  selfDestruct: '6666666',
};

/*
 * The wait budgets.
 *
 * PER_TEST is a deadline, and it is deliberately not generous: everything in
 * section 1 is either an in-process round trip or a reboot, and a reboot
 * measures at ~2.2s including the firmware's own provisioning work.
 *
 * INACTIVITY is the interesting one - it is a no-progress budget, not a total
 * one. An operation that keeps making observable progress may take as long as
 * it needs; silence is what fails. That distinction is what lets it be short:
 * a total cap has to be sized for the slowest legitimate operation, whereas an
 * inactivity cap only has to be sized for the longest legitimate GAP, which
 * does not grow with payload size.
 *
 * RUN_MAX IS A MEASURED CEILING, and the measurements are here so it reads as
 * one rather than as a round number somebody liked. It was 15 minutes, which
 * was enough until it silently was not: the 2026-08-05 17:35Z full sweep took
 * 879s against it - twenty-one seconds of headroom that nobody knew was the
 * margin - and the next full run aborted at 903s with 225 passed and 0 failed.
 *
 * What the tree actually costs, per section, each figure from a run rather than
 * from arithmetic:
 *
 *   00-sanity      <1s     device: false throughout       (17:35Z sweep)
 *   01-protocol    707s    112 tests                      (22:10Z run)
 *   02-cli         435s    101 tests                      (17:35Z sweep)
 *   03-gui         211s    78 tests, browser tier included (22:00Z sweep)
 *   04-app         ~2s     one stub                       (17:35Z sweep)
 *                  ----
 *                  ~1356s / 22.6 minutes
 *
 * So 30 minutes, which is 1.33x the measured need. Two things make that safe
 * rather than merely generous. INACTIVITY is what actually catches a wedge - a
 * hung device call goes silent and dies in 30 seconds regardless of what this
 * says - so RUN_MAX is the backstop for the case a wedged run keeps TALKING,
 * which is rare and does not need a tight bound. And a cap that aborts a
 * healthy run is worse than one that is loose, because it reports as a failure
 * of the kit rather than as a budget.
 *
 * The eventual shape is a per-SECTION budget rather than a per-run one - see
 * TODO. A whole-run cap has to be resized every time the tree grows, which is
 * how this one went stale without anybody touching it.
 *
 * DONE 2026-09-30: IT IS PER SECTION NOW (Watchdogs.startSection), because it
 * went stale again exactly as predicted. 01-protocol has grown from 112 tests to
 * ~150, and on the Ubuntu VM (emulated USB gadget) a run of 01 + 02-cli + 03-gui
 * was stopped at 1800s with 142 passed and 0 genuinely failed, still inside 01 -
 * 02 and 03 never ran. Re-measured the same day:
 *
 *   01-protocol    ~1200s  Windows okvhid (01 + a skipped 02-cli: 1222s run)
 *   01-protocol    >1800s  Ubuntu VM gadget (143 of ~150 done at 1801s)
 *
 * So RUN_MAX is now the budget of ONE SECTION: 45 minutes, 1.5x the slowest
 * host's 01. Re-measure (per section, per host) before changing it again.
 */
const TIMEOUTS = {
  PER_TEST: 60_000,
  INACTIVITY: 30_000,
  /* PER SECTION since 2026-09-30 (the name is kept for callers). Measured: the
   * VM's 01-protocol needs more than 1800s. See the note above before changing
   * this - and re-measure rather than doubling it. */
  RUN_MAX: 45 * 60_000,
  BOOT: 20_000,
};

/* Built fixtures are cached OUTSIDE the test tree, keyed by fingerprint. */
const CACHE_ROOT = process.env.OKT_CACHE_DIR ||
  path.join(process.env.XDG_CACHE_HOME || path.join(os.homedir(), '.cache'), 'onlykey-testing');

/* The emulated device's storage files, and the only two sizes that are valid. */
const IMAGE_SIZES = {
  'flash.bin': 262144,
  'eeprom.bin': 2048,
};

module.exports = { PINS, TIMEOUTS, CACHE_ROOT, IMAGE_SIZES };
