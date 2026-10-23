'use strict';
/*
 * SOFT-KEY FIRMWARE PLUGINS on the emulator - their own tests, SIDE-LOADED.
 *
 * Owner, 2026-10-01: experimental firmware features are plugins, each in its
 * own folder WITH ITS TESTS; the emulator builds them without depending on
 * ok-rn, and neither does this kit. node-onlykey-emulator, built with
 *   OKEMU_PLUGINS=<names> [OKEMU_PLUGINS_DIR=<a plugins folder>]
 * (its own emulator/plugins/ holds the hello demo)
 * records in emulator/.stage/build.json which plugins it staged and the folder
 * they came from. This file reads that and registers each plugin's
 * <pluginsDir>/<name>/tests/kit.test.js - so a plugin's tests run only against
 * an emulator that has the plugin, and leave with the plugin's folder. Against
 * a base emulator the one test here skips and says why.
 *
 * A plugin test gets the kit through `ctx` (IFACE, okmsg, PINS, requireLib, kit), never by a
 * relative path into this repo.
 */
const fs = require('node:fs');
const path = require('node:path');
const { describe, it } = require('../../lib/harness');
const { IFACE, okmsg } = require('../../lib/device');
const { PINS } = require('../../lib/config');
const { emulatorRoot } = require('../../lib/paths');

function staged() {
  try {
    const built = JSON.parse(fs.readFileSync(path.join(emulatorRoot().dir, '.stage', 'build.json'), 'utf8'));
    return {
      plugins: Array.isArray(built.plugins) ? built.plugins : [],
      dir: typeof built.pluginsDir === 'string' ? built.pluginsDir : null,
      /* a DEBUG build: some plugin requests exist only there (config's OKSETCONFIG) */
      debug: built.debug === true,
    };
  } catch (_) {
    return { plugins: [], dir: null, debug: false };
  }
}

/*
 * requireLib: the kit's OWN pinned node-onlykey-lib, by public subpath - a plugin's
 * test checks the firmware against the library the kit runs, never a copy of its own.
 */
const ctx = {
  IFACE, okmsg, PINS,
  requireLib: (id) => require(id),
  /* the same library's FILE path (a plugin test that hands a lib program to a child process, e.g. git's gpg.program) */
  resolveLib: (id) => require.resolve(id),
  /*
   * the kit's own helpers a plugin test may need: the device backup (a plugin's
   * backup section rides on it), and pqc (readyForKeygen: config mode, for
   * loading the keys a plugin test signs or decrypts with)
   */
  kit: {
    backup: require('../../lib/device/backup'), pqc: require('../../lib/pqc'),
    /* the lib composed over the kit's emulator, in-process (lib/libstack.js) - for a plugin test that runs lib code against the firmware */
    libstack: require('../../lib/libstack'),
    /* the kit's CTAP2 layer and WebAuthn tunnel: a plugin proves what it REFUSES over CTAP (config) */
    ctap2: require('../../lib/device/ctap2'), tunnel: require('../../lib/device/tunnel'),
  },
};
const { plugins, dir, debug } = staged();
ctx.build = { debug };
const sideLoaded = plugins
  .map((name) => ({ name, file: dir ? path.join(dir, name, 'tests', 'kit.test.js') : null }))
  .filter((p) => p.file && fs.existsSync(p.file));

/*
 * 5 minutes a test: a plugin test may drive a whole typed backup and restore.
 * `requires: ['emulated']` (owner, 2026-10-02): plugins are soft-key features, so
 * their tests never run against a hard key. build.json says what the EMULATOR on
 * disk stages, not what the kit is talking to - a hardware run with an Edge
 * emulator build still on disk would otherwise send Edge's tests (a backup and a
 * restore among them) to a hard key that has no Edge. A plugin a hard key may get
 * one day (Edge, maybe; never OKGETCONFIG) gets its own hard-key gate then - the
 * second describe below.
 */
describe('soft-key firmware plugins on the emulator (side-loaded tests)', { state: 'initialized', timeoutMs: 300000, requires: ['emulated'] }, () => {
  for (const p of sideLoaded) require(p.file)({ it }, ctx);
  if (!sideLoaded.length) {
    it('side-loaded plugin tests', async ({ skip }) => {
      skip(plugins.length
        ? `the emulator stages ${plugins.join(', ')}, but no tests/kit.test.js was found under ${dir || '(no pluginsDir recorded)'}`
        : 'this emulator was built without plugins (e.g. OKEMU_PLUGINS=hello npm run rebuild in the emulator)');
    });
  }
});

/*
 * The HARD-KEY gate: a developer key flashed with a plugin build (Edge's
 * tools/build-hardkey.sh). A hard key carries no build.json and the kit cannot
 * ask it which plugins it has, so the person running the kit NAMES them:
 *   OKT_HARDKEY_PLUGINS=edge  OKT_HARDKEY_PLUGINS_DIR=<the plugins folder>
 * and nothing is guessed - unnamed, nothing runs. Naming a plugin the key does not
 * have sends its tests (a backup and a restore among them) to a key without it,
 * which is why the opt-in is explicit and per run. Presses go through the debug
 * console, as for every hard-key test.
 */
const hardNamed = (process.env.OKT_HARDKEY_PLUGINS || '').split(',').map((s) => s.trim()).filter(Boolean);
const hardDir = process.env.OKT_HARDKEY_PLUGINS_DIR || null;
const hardLoaded = hardNamed
  .map((name) => ({ name, file: hardDir ? path.join(hardDir, name, 'tests', 'kit.test.js') : null }))
  .filter((p) => p.file && fs.existsSync(p.file));

describe('firmware plugins on a hard key (side-loaded tests)', { state: 'initialized', timeoutMs: 300000, requires: ['hard-key'] }, () => {
  /* a hard key built by build-hardkey.sh is a DEBUG build: the kit drives it through its console */
  const hardCtx = { ...ctx, build: { debug: true } };
  for (const p of hardLoaded) require(p.file)({ it }, hardCtx);
  if (!hardLoaded.length) {
    it('side-loaded plugin tests', async ({ skip }) => {
      skip(hardNamed.length
        ? `OKT_HARDKEY_PLUGINS names ${hardNamed.join(', ')}, but no tests/kit.test.js was found under ${hardDir || '(set OKT_HARDKEY_PLUGINS_DIR)'}`
        : 'no plugins named for this hard key (OKT_HARDKEY_PLUGINS=edge OKT_HARDKEY_PLUGINS_DIR=<plugins folder>, for a key flashed with a plugin build)');
    });
  }
});
