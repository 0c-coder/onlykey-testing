'use strict';
/*
 * THE TESTS THAT TRAVEL WITH THE FIRMWARE PATCHES (Brad, 2026-10-28: "if I send a patch, Tim should get the test that
 * fails before the patch and passes after it - showing the issue in the test, and fixing the issue in the patch").
 *
 * A maintainer patch (node-onlykey-emulator scripts/versions/patches-<version>/<NNNN>-<name>/) carries its own test in
 * tests/kit.test.js, beside the .patch and its README, the way a plugin carries its tests. Each is strict: it asserts the
 * fixed behaviour, so on the release as published it FAILS - its message names the bug - and with the patch it PASSES.
 * 01-protocol stays the firmware protocol of the release itself, which every build passes, patched or not.
 *
 * Which patches' tests run:
 *   OKT_PATCHES=0013,0015 (or all)  those, on whatever firmware is under test - to see a bug on the release, or a fix on
 *                                   a build that carries it. "all" leaves out a held patch (a HOLD file) unless named.
 *   unset                           the patches the firmware under test carries, which must pass: an emulator's
 *                                   .stage/build.json `fixes`; a hard key's OKT_FIRMWARE_FIXES (whoever flashed it says)
 * The patch folders: OKT_PATCHES_DIR, else the emulator's patches-<version> for the version it is built from (a hard
 * key: OKT_FIRMWARE_VERSION, else 3.1.0).
 */
const fs = require('node:fs');
const path = require('node:path');
const { describe, it } = require('../../lib/harness');
const { emulatorRoot } = require('../../lib/paths');
const { pluginCtx } = require('../../lib/plugin-ctx');

/* a hard key runs serially with --hardware on the command line; the emulator's build.json describes the emulator only */
const hardware = process.argv.includes('--hardware');

function built() {
  try {
    return JSON.parse(fs.readFileSync(path.join(emulatorRoot().dir, '.stage', 'build.json'), 'utf8'));
  } catch (_) {
    return {};
  }
}

const build = hardware ? {} : built();
const version = String((hardware ? process.env.OKT_FIRMWARE_VERSION : build.version) || '3.1.0').replace(/^v/, '');
const dir = process.env.OKT_PATCHES_DIR
  || (() => { try { return path.join(emulatorRoot().dir, 'scripts', 'versions', `patches-${version}`); } catch (_) { return null; } })();
const folders = dir && fs.existsSync(dir) ? fs.readdirSync(dir).filter((f) => /^\d{4}-/.test(f)).sort() : [];
const numberOf = (folder) => folder.slice(0, 4);

const asked = String(process.env.OKT_PATCHES || '').split(',').map((s) => s.trim()).filter(Boolean);
const carried = hardware
  ? String(process.env.OKT_FIRMWARE_FIXES || '').split(',').map((s) => s.trim()).filter(Boolean)
  : (Array.isArray(build.fixes) ? build.fixes.map(String) : []);
const held = (folder) => fs.existsSync(path.join(dir, folder, 'HOLD'));
const wanted = asked.length
  ? folders.filter((f) => (asked.includes('all') && !held(f)) || asked.includes(numberOf(f)))
  : folders.filter((f) => carried.includes(numberOf(f)));
const withTests = wanted.filter((f) => fs.existsSync(path.join(dir, f, 'tests', 'kit.test.js')));

describe(`the firmware patches' own tests (${withTests.map(numberOf).join(', ') || 'none'})`,
  { state: 'initialized', timeoutMs: 600000, requires: ['crypto'] }, () => {
    const ctx = pluginCtx({ debug: hardware ? process.env.OKT_FIRMWARE_DEBUG !== '0' : build.debug === true });
    for (const f of withTests) require(path.join(dir, f, 'tests', 'kit.test.js'))({ it }, ctx);
    const untested = wanted.filter((f) => !withTests.includes(f));
    if (untested.length) {
      it(`every patch named has its test (${untested.map(numberOf).join(', ')})`, async ({ assert }) => {
        assert.fail(`no tests/kit.test.js in ${untested.join(', ')} - a patch goes out with the test that shows its bug`);
      });
    }
    if (!wanted.length) {
      it('the firmware patches\' own tests', async ({ skip }) => {
        skip(asked.length
          ? `OKT_PATCHES=${asked.join(',')} names no patch folder in ${dir || '(no patches folder)'}`
          : `the firmware under test carries no patches (${hardware ? 'OKT_FIRMWARE_FIXES' : '.stage/build.json fixes'}: none) - OKT_PATCHES=all runs their tests anyway`);
      });
    }
  });
