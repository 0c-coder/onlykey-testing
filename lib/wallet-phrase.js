/*
 * wallet-phrase.js - what the wallet phrase tests share (01-protocol/39-wallet-phrase-*).
 *
 * A Password Manager wallet phrase is derived again from the key every time (lib
 * passwords/src/mnemonic.js: derive on `mnemonic:<name>` -> HKDF -> BIP39 words), never stored.
 * These helpers derive it through the lib exactly as the app does, make the device type its
 * backup, and restore one through the lib.
 */
'use strict';

const path = require('path');

const { IFACE, okmsg } = require('./device');
const { PINS } = require('./config');
const { composeLib } = require('./libstack');
const { mnemonic } = require('node-onlykey-lib/passwords');

const FIXTURE = path.join(__dirname, '..', 'test', '00-sanity', 'fixtures', 'wallet-phrase-backup.json');
/* >= 25 characters, the lib's minimum for a backup passphrase; the fixture is made with it too */
const PASSPHRASE = 'okt wallet phrase backup passphrase';
const NAME = 'okt-vector';
const FIELD_WEB_AGENT_DERIVE_MODE = 30;
const USER_INPUT_NONE = 2;

async function vendorSay(device, signal, msg, fields = {}) {
  const since = device.mark(IFACE.VENDOR);
  device.sendVendor({ msg, ...fields });
  return okmsg.text(await device.waitHid(IFACE.VENDOR,
    { since, match: /Success|Error/, timeoutMs: 10000, signal }));
}

/** Restart out of whatever mode, unlock, config mode. */
async function configMode(device, signal) {
  await device.restart({ signal });
  await device.unlock(PINS.primary, { signal });
  await device.enterConfigMode(PINS.primary, { signal });
}

/**
 * Ready for the tests: the derive answers without a press (field 30 = 2, as
 * 31-derive-decaps-wipe-timer does - on 3.1.0 the mode does not change the derived key, the
 * press-flag byte is 0), and the backup passphrase is set (the lib's UTF-8 key in slot 131).
 */
async function prepare(device, signal, assert) {
  await configMode(device, signal);
  assert.match(await vendorSay(device, signal, okmsg.MSG.OKSETSLOT,
    { slot: 1, field: FIELD_WEB_AGENT_DERIVE_MODE, payload: Buffer.from([USER_INPUT_NONE]) }), /Success/,
  'the device refused the touch-free derive mode');
  const stack = await composeLib(device);
  try {
    await stack.services.device.connect({ timeoutMs: 6000 });
    assert.equal((await stack.services.device.setBackupPassphrase(PASSPHRASE)).encoding, 'utf-8');
  } finally {
    await stack.destroy();
  }
}

/** The device types its backup (the same steps as 35-lib-backup-passphrase-encoding). */
async function typeBackup(device, signal, log) {
  await device.restart({ signal });
  await device.unlock(PINS.primary, { signal });
  let started = false;
  for (let attempt = 1; attempt <= 6 && !started; attempt++) {
    device.log.clear();
    device.keys.clear();
    device.pressLine([{ button: 1, hold: 'hold' }]);
    started = await Promise.any([
      device.log.waitFor(/Backing up Label Number/, { timeoutMs: 5000, signal }),
      device.waitKeystrokes(/-----BEGIN ONLYKEY BACKUP-----/, { timeoutMs: 5000, signal }),
    ]).then(() => true, () => device.keystrokes.length > 0);
    if (!started) log(`hold ${attempt} landed mid-fade and was discarded`);
  }
  if (!started) throw new Error('the device never started a backup in six attempts');
  await device.waitKeystrokes(/-----END ONLYKEY BACKUP-----/, { timeoutMs: 180000, signal });
  return device.keystrokes;
}

/** The wallet phrase for NAME, through the lib as the app derives it (12 words, one string). */
async function phraseOf(device, signal) {
  await device.restart({ signal });
  await device.unlock(PINS.primary, { signal });
  const stack = await composeLib(device);
  try {
    await stack.services.device.connect({ timeoutMs: 6000 });
    const { words } = await mnemonic.deriveMnemonic({ okcrypto: stack.services.okcrypto, name: NAME, out: 'bip39-12', press: false });
    return Array.isArray(words) ? words.join(' ') : String(words);
  } finally {
    await stack.destroy();
  }
}

/** Restore `text` through the lib (config mode, the passphrase); back when the device is up. */
async function restore(device, signal, assert, text) {
  await configMode(device, signal);
  const stack = await composeLib(device);
  await stack.services.device.connect({ timeoutMs: 6000 });
  const before = device.generation;
  let result;
  try {
    result = await stack.services.device.restore(text, { passphrase: PASSPHRASE });
  } finally {
    await stack.destroy();
  }
  assert.equal(result.response, 'Successfully loaded backup', "the device's own verdict");
  await device.waitForReboot({ from: before, timeoutMs: 90000, signal });
  await device.waitReady({ signal });
}

module.exports = { FIXTURE, PASSPHRASE, NAME, mnemonic, prepare, typeBackup, phraseOf, restore };
