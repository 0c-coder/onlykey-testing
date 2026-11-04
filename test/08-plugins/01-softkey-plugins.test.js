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
 * A plugin test gets the kit through `ctx` (lib/plugin-ctx.js: IFACE, okmsg, PINS,
 * requireLib, kit), never by a relative path into this repo.
 */
const fs = require('node:fs');
const path = require('node:path');
const { describe, it } = require('../../lib/harness');
const { emulatorRoot } = require('../../lib/paths');
const { pluginCtx } = require('../../lib/plugin-ctx');

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

const { plugins, dir, debug } = staged();
const ctx = pluginCtx({ debug });
const sideLoaded = plugins
  .map((name) => ({ name, file: dir ? path.join(dir, name, 'tests', 'kit.test.js') : null }))
  .filter((p) => p.file && fs.existsSync(p.file));

/*
 * 5 minutes a test: a plugin test may drive a whole typed backup and restore.
 * `requires: ['emulated']` (owner, 2026-10-02): plugins are soft-key features, so
 * their tests never run against a hard key FROM HERE. build.json says what the
 * EMULATOR on disk stages, not what the kit is talking to - a hardware run with an
 * Edge emulator build still on disk would otherwise send Edge's tests (a backup and
 * a restore among them) to a hard key that has no Edge. A plugin a hard key may get
 * (Edge, on a developer key) runs through its own hard-key gate instead: 37.
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
