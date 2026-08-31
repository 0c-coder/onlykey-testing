/*
 * paths.js - where everything is, and what to say when it is not there.
 *
 * This kit is its own repository and sits beside the other checkouts - the
 * emulator among them - in one workspace folder, each a swap slot rather than a
 * dependency, so nothing here may assume anything about where it was cloned.
 * The emulator is found at ../node-onlykey-emulator/emulator relative to the kit
 * root, with OKEMU_ROOT overriding.
 *
 * When neither resolves we say which paths we tried. A bare MODULE_NOT_FOUND
 * from three frames down inside require() names a file nobody asked for and
 * hides the one question that matters: where did it look?
 */
'use strict';

const fs = require('fs');
const path = require('path');

/* lib/ -> kit root. */
const KIT_ROOT = path.resolve(__dirname, '..');

/*
 * The checkouts directory - the parent of this repo. python-onlykey,
 * OnlyKey-Firmware, libraries and the venv all hang off it. Used for
 * fixture fingerprinting and by the later sections; section 1 needs none of it.
 */
const CHECKOUTS_ROOT = path.resolve(KIT_ROOT, '..');

function emulatorCandidates() {
  const out = [];
  if (process.env.OKEMU_ROOT) out.push(path.resolve(process.env.OKEMU_ROOT));
  /* ../ is the workspace folder; the emulator is a sibling checkout in it. */
  out.push(path.resolve(KIT_ROOT, '..', 'node-onlykey-emulator', 'emulator'));
  return out;
}

/** Does this directory look like a built emulator? */
function inspectEmulator(dir) {
  const index = path.join(dir, 'index.js');
  const addon = path.join(dir, 'build', 'Release', 'onlykey_emulator.node');
  return {
    dir,
    hasIndex: fs.existsSync(index),
    hasAddon: fs.existsSync(addon),
    index,
    addon,
  };
}

let cached = null;

/**
 * Resolve the emulator checkout, or throw an error that names every path tried
 * and says which part was missing.
 * @returns {{dir:string, index:string, addon:string}}
 */
function emulatorRoot() {
  if (cached) return cached;

  const tried = emulatorCandidates().map(inspectEmulator);
  const found = tried.find((c) => c.hasIndex && c.hasAddon);
  if (found) {
    cached = { dir: found.dir, index: found.index, addon: found.addon };
    return cached;
  }

  /*
   * Distinguish "wrong directory" from "right directory, not built yet". They
   * have completely different fixes and the same symptom.
   */
  const unbuilt = tried.find((c) => c.hasIndex && !c.hasAddon);
  if (unbuilt) {
    throw new Error(
      `found the emulator at ${unbuilt.dir} but it is not built - ` +
      `${path.relative(unbuilt.dir, unbuilt.addon)} is missing. ` +
      `Run  npm install && npm run build  there first.`
    );
  }

  throw new Error(
    'could not find the OnlyKey emulator. Tried:\n' +
    tried.map((c) => `  ${c.dir}${c.hasIndex ? ' (index.js present)' : ''}`).join('\n') +
    '\nSet OKEMU_ROOT to the emulator checkout, or place this kit beside it ' +
    'in the workspace folder.'
  );
}

/** require() the emulator's own module, from wherever it turned out to live. */
function requireEmulatorModule(rel) {
  return require(path.join(emulatorRoot().dir, rel));
}

/*
 * Where the sibling Arduino/Teensy builder drops its hex. Only a default - the
 * flasher takes a path - but having it means `okt flash` needs no arguments in
 * the layout this kit actually lives in.
 */
const DEFAULT_HEX = path.join(
  CHECKOUTS_ROOT, 'arduino-1.6.5-r5-teensy_127', 'builds', 'OnlyKey.cpp.hex'
);

module.exports = {
  KIT_ROOT,
  CHECKOUTS_ROOT,
  DEFAULT_HEX,
  TEST_ROOT: path.join(KIT_ROOT, 'test'),
  RUNS_ROOT: path.join(KIT_ROOT, 'runs'),
  DEVICE_HOST: path.join(KIT_ROOT, 'lib', 'host', 'device-host.js'),
  emulatorRoot,
  requireEmulatorModule,
};
