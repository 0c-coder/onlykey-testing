/*
 * fixtures/index.js - device state, built once and restored per file.
 *
 * This is what removes the cross-contamination that forced the old kit to be
 * run one file at a time by hand. A state is defined once (states/*.js) and has
 * two consumers: on the emulator its apply() runs once in a builder and the
 * resulting flash and eeprom images are cached, and each test file then boots
 * from a fresh copy; on hardware the same module checks the device and runs the
 * real setup flow when the check fails, because a physical key cannot have an
 * image pushed into it.
 *
 * Four limits of snapshot restore are worth knowing before reading a result:
 *
 *   - A snapshot always boots LOCKED. The unlocked/initialized/configmode flags
 *     and the PIN hashes are RAM, rebuilt in setup(); snapshots skip
 *     provisioning, not unlocking, so every file still pays one PIN entry.
 *   - FSEC is not in flash.bin. It lives in an anonymous peripheral mapping
 *     written fresh every boot, so it latches to the already-provisioned value
 *     and the firmware's one-time provisioning branch never runs. No factory
 *     key derivation, no firmware hash in EEPROM, no security lock bits - see
 *     the `attestation` capability.
 *   - Time is RAM-only and rebased every boot, so anything counter or TOTP
 *     derived needs the time re-sent after every boot, snapshot or not.
 *   - The fingerprint covers the built firmware, so a rebuild invalidates the
 *     cache automatically. The old kit's on-disk caches went stale after a
 *     reflash and there is no reason to inherit that.
 */
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const { CACHE_ROOT, IMAGE_SIZES } = require('../config');
const { emulatorRoot, CHECKOUTS_ROOT } = require('../paths');
const { EmulatedTransport } = require('../device/emulated');
const { Device } = require('../device');

const FIXTURE_ROOT = path.join(CACHE_ROOT, 'fixtures');
const BUILD_ROOT = path.join(CACHE_ROOT, 'build');
const IMAGES = Object.keys(IMAGE_SIZES);

function loadState(name) {
  const file = path.join(__dirname, 'states', `${name}.js`);
  if (!fs.existsSync(file)) {
    const available = fs.readdirSync(path.join(__dirname, 'states'))
      .filter((f) => f.endsWith('.js')).map((f) => f.replace(/\.js$/, ''));
    throw new Error(`unknown device state '${name}'; have: ${available.join(', ')}`);
  }
  return require(file);
}

/* ---- fingerprint --------------------------------------------------------
 * Anything that changes what a boot DOES has to be in here, or a stale image
 * gets restored and the firmware gets blamed for behaviour it no longer has.
 */

function gitRev(dir) {
  try {
    const rev = execFileSync('git', ['-C', dir, 'rev-parse', '--short', 'HEAD'],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
    const dirty = execFileSync('git', ['-C', dir, 'status', '--porcelain'],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim().length > 0;
    return `${rev}${dirty ? '-dirty' : ''}`;
  } catch {
    return 'no-git';
  }
}

function hashFile(file) {
  const h = crypto.createHash('sha256');
  h.update(fs.readFileSync(file));
  return h.digest('hex');
}

function fingerprint(stateName) {
  const root = emulatorRoot();
  const parts = {};

  /*
   * The built firmware archive, by content. It is the product of every upstream
   * source file, so hashing it covers a source edit that was actually compiled
   * in - which is the only kind that can change a boot.
   */
  const archive = path.join(root.dir, 'build', 'Release', 'okemu_firmware.a');
  parts.firmware = fs.existsSync(archive) ? hashFile(archive) : `missing:${hashFile(root.addon)}`;

  /* The revisions, which do not affect correctness of the key above but make a
   * cache directory readable when something has gone wrong. */
  parts.firmwareRev = gitRev(path.join(CHECKOUTS_ROOT, 'OnlyKey-Firmware'));
  parts.librariesRev = gitRev(path.join(CHECKOUTS_ROOT, 'libraries'));

  /* And the state module itself: its apply() is what produced the images. */
  parts.state = hashFile(path.join(__dirname, 'states', `${stateName}.js`));

  /* And the model: a DUO is provisioned differently and its images are its own
   * (lib/model.js). */
  parts.model = require('../model').deviceModel();

  const digest = crypto.createHash('sha256')
    .update(JSON.stringify(parts)).digest('hex').slice(0, 12);

  return { digest, parts };
}

/* ---- building ------------------------------------------------------------ */

function imagesValid(dir) {
  return IMAGES.every((name) => {
    const file = path.join(dir, name);
    return fs.existsSync(file) && fs.statSync(file).size === IMAGE_SIZES[name];
  });
}

async function withDevice(dir, fn) {
  const transport = new EmulatedTransport({
    runDir: dir,
    storageDir: path.join(dir, 'storage'),
    runId: 'fixture',
  });
  const device = new Device(transport);
  try {
    await transport.start();
    return await fn(device);
  } finally {
    await transport.stop();
  }
}

/**
 * Make sure the named state's images exist in the cache, building them if the
 * fingerprint says they are missing or stale.
 * @returns {Promise<{dir:string, built:boolean, digest:string}>}
 */
async function ensure(stateName, { log = () => {}, capabilities = null } = {}) {
  const state = loadState(stateName);
  const { digest, parts } = fingerprint(stateName);
  const dir = path.join(FIXTURE_ROOT, `${stateName}-${digest}`);

  if (imagesValid(dir)) {
    log(`fixture '${stateName}' is cached (${digest})`);
    return { dir, built: false, digest };
  }

  if (capabilities && state.requires) {
    const missing = capabilities.missing(state.requires);
    if (missing) throw new Error(`cannot build fixture '${stateName}': it ${missing}`);
  }

  log(`building fixture '${stateName}' (${digest}) - not cached`);

  const buildDir = path.join(BUILD_ROOT, `${stateName}-${process.pid}`);
  fs.rmSync(buildDir, { recursive: true, force: true });
  fs.mkdirSync(path.join(buildDir, 'storage'), { recursive: true });

  await withDevice(buildDir, async (device) => {
    await state.apply(device, { adapter: 'emulated', log });
  });

  const produced = path.join(buildDir, 'storage');
  for (const name of IMAGES) {
    const file = path.join(produced, name);
    if (!fs.existsSync(file)) throw new Error(`fixture build produced no ${name}`);
    const size = fs.statSync(file).size;
    if (size !== IMAGE_SIZES[name]) {
      throw new Error(`fixture build produced a ${size}-byte ${name}, expected ${IMAGE_SIZES[name]}`);
    }
  }

  /* Assemble beside the target and rename into place, so a cache directory
   * either exists complete or does not exist. */
  const staging = `${dir}.tmp-${process.pid}`;
  fs.rmSync(staging, { recursive: true, force: true });
  fs.mkdirSync(staging, { recursive: true });
  for (const name of IMAGES) fs.copyFileSync(path.join(produced, name), path.join(staging, name));
  fs.writeFileSync(path.join(staging, 'meta.json'), JSON.stringify({
    state: stateName, digest, parts, builtAt: new Date().toISOString(),
  }, null, 2));

  /* Another run built the same fixture meanwhile (okt run --jobs: two workers can start on one uncached fixture): keep
   * its copy - a worker may be restoring from it right now - and drop this one. */
  if (imagesValid(dir)) {
    fs.rmSync(staging, { recursive: true, force: true });
    fs.rmSync(buildDir, { recursive: true, force: true });
    log(`fixture '${stateName}' was built by another run meanwhile - using that one`);
    return { dir, built: false, digest };
  }
  fs.rmSync(dir, { recursive: true, force: true });
  fs.renameSync(staging, dir);
  fs.rmSync(buildDir, { recursive: true, force: true });

  log(`fixture '${stateName}' built`);
  return { dir, built: true, digest };
}

/**
 * Copy a cached state into a run's storage directory.
 *
 * Copy to a temp name, assert the size, then rename. The firmware's loader
 * validates size and NOTHING else, and on any mismatch - too short or too long
 * - it truncates the file to zero and rewrites the whole thing with 0xFF. So a
 * half-copied snapshot does not come back half-restored; it comes back as a
 * factory-blank device, and the test that then fails gets blamed on the
 * firmware.
 */
function restore(fixtureDir, storageDir) {
  fs.mkdirSync(storageDir, { recursive: true });

  for (const name of IMAGES) {
    const from = path.join(fixtureDir, name);
    const size = fs.statSync(from).size;
    if (size !== IMAGE_SIZES[name]) {
      throw new Error(`cached ${name} is ${size} bytes, expected ${IMAGE_SIZES[name]} - refusing to restore`);
    }

    const tmp = path.join(storageDir, `.${name}.tmp-${process.pid}`);
    fs.copyFileSync(from, tmp);

    const copied = fs.statSync(tmp).size;
    if (copied !== IMAGE_SIZES[name]) {
      fs.rmSync(tmp, { force: true });
      throw new Error(`copy of ${name} is ${copied} bytes, expected ${IMAGE_SIZES[name]}`);
    }

    fs.renameSync(tmp, path.join(storageDir, name));
  }
}

/**
 * Prepare `storageDir` for a file that asked for `stateName`.
 * 'blank' needs no images at all - an empty directory IS a blank device, and
 * writing 0xFF images to say so would only add a way to get it wrong.
 */
async function prepare(stateName, storageDir, opts = {}) {
  fs.mkdirSync(storageDir, { recursive: true });
  for (const name of IMAGES) fs.rmSync(path.join(storageDir, name), { force: true });

  if (!stateName || stateName === 'blank') {
    return { state: 'blank', restored: false };
  }

  const { dir, built, digest } = await ensure(stateName, opts);
  restore(dir, storageDir);
  return { state: stateName, restored: true, built, digest, dir };
}

/**
 * Bring a LIVE device into the named state.
 *
 * The hardware path, and the reason a state module exports two functions
 * instead of one. There is no image to push into a physical key, so the state
 * has to be reached the way a person would reach it - check first, and only run
 * the real setup flow if the check fails. That check is also what keeps a run
 * from re-provisioning a key that was already provisioned, which on hardware
 * costs a wipe nobody asked for.
 */
async function ensureOnDevice(stateName, device, opts = {}) {
  const { log = () => {}, signal } = opts;
  if (!stateName) return { state: 'any', applied: false };

  const state = loadState(stateName);
  if (await state.check(device)) {
    log(`device is already '${stateName}'`);
    return { state: stateName, applied: false };
  }

  log(`bringing the device to '${stateName}'`);
  await state.apply(device, { adapter: device.transport.kind, log, signal });

  if (!(await state.check(device))) {
    throw new Error(`applied '${stateName}' but the device does not report it`);
  }
  return { state: stateName, applied: true };
}

module.exports = {
  ensure, restore, prepare, ensureOnDevice, fingerprint, loadState, withDevice, FIXTURE_ROOT,
};
