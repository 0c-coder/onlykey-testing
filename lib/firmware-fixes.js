'use strict';
/*
 * WHICH RC FIXES THE FIRMWARE UNDER TEST CARRIES - the maintainer patches node-onlykey-emulator stages on a release
 * (scripts/versions/patches-<version>/, fixes-<version>.js) and plugins/edge/tools/build-hardkey.sh `git am`s for a
 * developer hard key. A test whose answer a fix changes asks this, so one test covers the firmware as the maintainer
 * ships it AND as we run it:
 *
 *   - an emulator records what it staged: .stage/build.json `fixes` (e.g. ["0012", "0013"]);
 *   - a hard key cannot say, so whoever flashed it does: OKT_FIRMWARE_FIXES=0012,0013. Unset means none - the
 *     firmware as the maintainer ships it (his test hex).
 *
 * build.json describes the emulator ON DISK, never a hard key, so it is read only when the device under test is the
 * emulator (its transport alone can expectFatal()).
 */
const fs = require('node:fs');
const path = require('node:path');
const { emulatorRoot } = require('./paths');

function firmwareFixes(device) {
  const emulated = !!device && !!device.transport && typeof device.transport.expectFatal === 'function';
  if (!emulated) return String(process.env.OKT_FIRMWARE_FIXES || '').split(',').map((s) => s.trim()).filter(Boolean);
  try {
    const built = JSON.parse(fs.readFileSync(path.join(emulatorRoot().dir, '.stage', 'build.json'), 'utf8'));
    return Array.isArray(built.fixes) ? built.fixes.map(String) : [];
  } catch (_) {
    return [];
  }
}

module.exports = { firmwareFixes };
