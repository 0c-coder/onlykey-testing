'use strict';
/*
 * FIRMWARE PLUGINS on a HARD key - their own tests, SIDE-LOADED: 38's hard-key gate
 * (38 runs them on the emulator, from its build.json).
 *
 * For a developer key flashed with a plugin build (Edge's tools/build-hardkey.sh). A
 * hard key carries no build.json and the kit cannot ask it which plugins it has, so
 * the person running the kit NAMES them:
 *   OKT_HARDKEY_PLUGINS=edge  OKT_HARDKEY_PLUGINS_DIR=<the plugins folder>
 * and nothing is guessed - unnamed, the one test here skips. Naming a plugin the key
 * does not have sends its tests (a backup and a restore among them) to a key without
 * it, which is why the opt-in is explicit and per run. Presses go through the debug
 * console, as for every hard-key test.
 */
const fs = require('node:fs');
const path = require('node:path');
const { describe, it } = require('../../lib/harness');
const { pluginCtx } = require('../../lib/plugin-ctx');

const named = (process.env.OKT_HARDKEY_PLUGINS || '').split(',').map((s) => s.trim()).filter(Boolean);
const dir = process.env.OKT_HARDKEY_PLUGINS_DIR || null;
const loaded = named
  .map((name) => ({ name, file: dir ? path.join(dir, name, 'tests', 'kit.test.js') : null }))
  .filter((p) => p.file && fs.existsSync(p.file));
/* a hard key built by build-hardkey.sh is a DEBUG build: the kit drives it through its console */
const ctx = pluginCtx({ debug: true });

describe('firmware plugins on a hard key (side-loaded tests)', { state: 'initialized', timeoutMs: 300000, requires: ['hard-key'] }, () => {
  for (const p of loaded) require(p.file)({ it }, ctx);
  if (!loaded.length) {
    it('side-loaded plugin tests', async ({ skip }) => {
      skip(named.length
        ? `OKT_HARDKEY_PLUGINS names ${named.join(', ')}, but no tests/kit.test.js was found under ${dir || '(set OKT_HARDKEY_PLUGINS_DIR)'}`
        : 'no plugins named for this hard key (OKT_HARDKEY_PLUGINS=edge OKT_HARDKEY_PLUGINS_DIR=<plugins folder>, for a key flashed with a plugin build)');
    });
  }
});
