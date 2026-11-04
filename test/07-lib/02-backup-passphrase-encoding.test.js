/*
 * node-onlykey-lib's backup passphrase encoding (N-1, owner's decision
 * 2026-09-30), against the real firmware: a passphrase is hashed as UTF-8 from
 * lib 0.4.0 on, and restore({ passphrase }) falls back to the classic App's
 * Latin-1 hash by itself.
 *
 * WHY AGAINST THE FIRMWARE. The firmware never sees the passphrase - only the
 * 32-byte hash in slot 131 - so which encoding made a backup is invisible to
 * it. What the lib relies on is something else: that it can tell, on the host,
 * whether the device will ACCEPT a backup under a given key. It has to,
 * because the device cannot be asked twice - RESTORE answers a wrong key with
 * "Error incorrect backup key set" and restarts (okcore.cpp:6630-6636), and a
 * second attempt needs the PIN and config mode entered on the key again. The
 * lib's suite proves its prediction against a fake written from the lib
 * author's reading of okcore.cpp; this file proves it against the device:
 *
 *   the premise   the device refuses an old backup under the UTF-8 key, in
 *                 its own words, and restarts - sent RAW, no lib involved;
 *   old backup    protected the OLD way (the Latin-1 hash of "pässword...",
 *                 set raw, exactly as the classic App sets it) restores
 *                 through the lib, which reports 'latin-1-legacy';
 *   new backup    protected by the lib's own setBackupPassphrase (UTF-8)
 *                 restores, reported 'utf-8';
 *   wrong         a wrong passphrase is refused with NOTHING sent.
 *
 * Each restore is checked by the slot label coming back, not by the lib's
 * return value alone.
 *
 * SURFACES: the lib over the kit's in-process emulator (lib/libstack.js),
 * vendor + keyboard capture; presses through the debug button harness.
 */
'use strict';

const crypto = require('crypto');

const { describe, it } = require('../../lib/harness');
const { IFACE, okmsg } = require('../../lib/device');
const { PINS } = require('../../lib/config');
const backup = require('../../lib/device/backup');
const { composeLib } = require('../../lib/libstack');

/* >= 25 characters (the lib's and the App's minimum), with U+00E4 in it -
 * the range where Latin-1 and UTF-8 bytes differ. */
const PHRASE = 'pässword pässword pässword';
const latin1Key = crypto.createHash('sha256').update(Buffer.from(PHRASE, 'latin1')).digest();
const utf8Key = crypto.createHash('sha256').update(Buffer.from(PHRASE, 'utf8')).digest();

const BACKUP_KEY_SLOT = 131;
const BACKUP_KEY_TYPE = 161;     // 0x80 backup | 0x20 decryption | 1 Ed25519
const SLOT = 3;                  // 1 is 08/34's, 2 is 10's
const FIELD_LABEL = 1;
const OLD_LABEL = 'n1old';
const NEW_LABEL = 'n1new';
const CLOBBER = 'n1gone';

async function vendorSay(device, signal, msg, fields = {}) {
  const since = device.mark(IFACE.VENDOR);
  device.sendVendor({ msg, ...fields });
  return okmsg.text(await device.waitHid(IFACE.VENDOR,
    { since, match: /Successfully|Error/, timeoutMs: 10000, signal }));
}

function setLabel(device, signal, label) {
  return vendorSay(device, signal, okmsg.MSG.OKSETSLOT,
    { slot: SLOT, field: FIELD_LABEL, payload: label });
}

async function labels(device, signal, expect) {
  const since = device.mark(IFACE.VENDOR);
  device.sendVendor({ msg: okmsg.MSG.OKGETLABELS });
  try {
    const reply = await device.waitHid(IFACE.VENDOR,
      { since, match: new RegExp(expect), timeoutMs: 10000, signal });
    return okmsg.text(reply);
  } catch {
    return '';
  }
}

/** Restart out of whatever mode, unlock, config mode. */
async function configMode(device, signal) {
  await device.restart({ signal });
  await device.unlock(PINS.primary, { signal });
  await device.enterConfigMode(PINS.primary, { signal });
}

/**
 * Have the device type a backup, as 10-backup-restore does (its comments say
 * why each step is there): out of config mode, button 1 held into the backup
 * band, retried when a press lands mid-fade, read until the END marker.
 */
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
  /* 10 minutes, not 3: this backup holds a stored ECC key, and a physical key
   * types at keyboard speed - 4 min 20 s on a developer OnlyKey (2026-10-19),
   * 48 s on the emulator, which no USB host paces. Ending the wait early also
   * left the key still typing, so the next file found it deaf. The wait ends
   * as soon as the backup does. */
  await device.waitKeystrokes(/-----END ONLYKEY BACKUP-----/, { timeoutMs: 600000, signal });
  return device.keystrokes;
}

/** A lib stack, connected, on a device already in config mode. */
async function lib(device) {
  const stack = await composeLib(device);
  await stack.services.device.connect({ timeoutMs: 6000 });
  return stack;
}

/* The slot-131 keys the lib sent, as hex. */
const keysSent = (stack) => stack.vendorWrites()
  .filter((w) => w.data[4] === okmsg.MSG.OKSETPRIV && w.data[5] === BACKUP_KEY_SLOT)
  .map((w) => Buffer.from(w.data.slice(7, 39)).toString('hex'));

describe('node-onlykey-lib backup passphrase: UTF-8, Latin-1 fallback, real firmware', {
  state: 'initialized',
  requires: ['crypto', 'keyboard-capture'],
  negative: true,
  timeoutMs: 1800000,                // two typed backups, each minutes long on a physical key
}, () => {
  let oldBackup = null;
  let newBackup = null;

  it('an OLD backup: the classic App\'s Latin-1 key, set raw, then a typed backup',
    async ({ device, assert, signal, log }) => {
      await configMode(device, signal);
      const said = await vendorSay(device, signal, okmsg.MSG.OKSETPRIV, {
        slot: BACKUP_KEY_SLOT,
        payload: Buffer.concat([Buffer.from([BACKUP_KEY_TYPE]), latin1Key]),
      });
      assert.match(said, /Successfully set Backup Passphrase/, 'the device refused the Latin-1 key');
      assert.ok(!/Error/.test(await setLabel(device, signal, OLD_LABEL)), 'label not stored');

      oldBackup = await typeBackup(device, signal, log);
      const parsed = backup.parse(oldBackup);
      assert.ok(parsed.complete && parsed.storedHash, 'the typed backup is incomplete');
      assert.control("the typed backup's chained hash matches - every keystroke was captured",
        parsed.computedHash.toString('hex') === parsed.storedHash.toString('hex'));
    });

  it('the premise: the device refuses it under the UTF-8 key, in its own words, and restarts',
    async ({ device, assert, signal, log }) => {
      assert.ok(oldBackup, 'no old backup to restore');
      const data = backup.parse(oldBackup).data;

      /*
       * Only sent when the UTF-8 key FAILS the device's one-byte test: about 3
       * times in 256 it passes, and then the device would write garbage into
       * the slots. That case is the lib's "cannot be told apart" refusal, and
       * the raw premise is skipped rather than run into it.
       */
      const { predictRestore } = require('node-onlykey-lib/device').backupkey;
      const predicted = predictRestore(Uint8Array.from(data), Uint8Array.from(utf8Key));
      assert.control("the lib's predictor read the typed backup's Ed25519 trailer",
        predicted.accepted !== null);
      if (predicted.accepted) {
        log('this backup\'s IV lets the UTF-8 key pass the one-byte test (~3/256); premise skipped');
        return;
      }

      await configMode(device, signal);
      assert.match(await vendorSay(device, signal, okmsg.MSG.OKSETPRIV, {
        slot: BACKUP_KEY_SLOT,
        payload: Buffer.concat([Buffer.from([BACKUP_KEY_TYPE]), utf8Key]),
      }), /Successfully set Backup Passphrase/);

      const before = device.generation;
      const since = device.mark(IFACE.VENDOR);
      for (const payload of backup.toRestorePackets(data)) {
        device.sendVendor({ msg: okmsg.MSG.OKRESTORE, payload });
        await device.sleep(50, { signal });
      }
      const reply = await device.waitHid(IFACE.VENDOR,
        { since, match: /Successfully loaded|Error/, timeoutMs: 20000, signal });
      assert.equal(okmsg.text(reply).trim(), 'Error incorrect backup key set');
      await device.waitForReboot({ from: before, timeoutMs: 90000, signal });
      log('refused and restarted: a second attempt would need the PIN and config mode again');
    });

  it('the lib restores the OLD backup through the fallback (latin-1-legacy)',
    async ({ device, assert, signal }) => {
      assert.ok(oldBackup, 'no old backup to restore');
      await configMode(device, signal);
      assert.ok(!/Error/.test(await setLabel(device, signal, CLOBBER)));

      const stack = await lib(device);
      const before = device.generation;
      let result;
      try {
        result = await stack.services.device.restore(oldBackup, { passphrase: PHRASE });
      } finally {
        await stack.destroy();
      }
      assert.equal(result.passphraseEncoding, 'latin-1-legacy');
      assert.equal(result.tried.join(','), 'utf-8,latin-1-legacy');
      assert.equal(result.response, 'Successfully loaded backup', 'the device\'s own verdict');
      assert.control("the recorder caught the lib's slot-131 write", keysSent(stack).length > 0);
      assert.equal(keysSent(stack).join(','), latin1Key.toString('hex'),
        'one key set - the one that opens it - and no refused attempt');

      await device.waitForReboot({ from: before, timeoutMs: 90000, signal });
      await device.waitReady({ signal });
      await device.unlock(PINS.primary, { signal });
      assert.includes(await labels(device, signal, OLD_LABEL), OLD_LABEL,
        'the restored label did not come back');
    });

  it('a NEW backup: the lib sets the UTF-8 key, and restores it (utf-8)',
    async ({ device, assert, signal, log }) => {
      await configMode(device, signal);
      let stack = await lib(device);
      try {
        const set = await stack.services.device.setBackupPassphrase(PHRASE);
        assert.equal(set.encoding, 'utf-8');
        assert.control("the recorder caught the lib's slot-131 write", keysSent(stack).length > 0);
        assert.equal(keysSent(stack).join(','), utf8Key.toString('hex'), 'the lib set the UTF-8 hash');
      } finally {
        await stack.destroy();
      }
      assert.ok(!/Error/.test(await setLabel(device, signal, NEW_LABEL)));

      newBackup = await typeBackup(device, signal, log);
      assert.ok(backup.parse(newBackup).complete, 'the typed backup is incomplete');

      await configMode(device, signal);
      assert.ok(!/Error/.test(await setLabel(device, signal, CLOBBER)));
      stack = await lib(device);
      const before = device.generation;
      let result;
      try {
        result = await stack.services.device.restore(newBackup, { passphrase: PHRASE });
      } finally {
        await stack.destroy();
      }
      assert.equal(result.passphraseEncoding, 'utf-8');
      assert.equal(result.response, 'Successfully loaded backup');

      await device.waitForReboot({ from: before, timeoutMs: 90000, signal });
      await device.waitReady({ signal });
      await device.unlock(PINS.primary, { signal });
      assert.includes(await labels(device, signal, NEW_LABEL), NEW_LABEL,
        'the restored label did not come back');
    });

  it('a wrong passphrase is refused, and NOTHING reaches the device',
    async ({ device, assert, signal }) => {
      assert.ok(newBackup, 'no new backup to restore');
      await configMode(device, signal);
      const stack = await lib(device);
      try {
        const written = stack.vendorWrites().length;
        assert.control('the recorder caught the lib\'s connect', written > 0);

        /*
         * A wrong key passes the device's one-byte test about 3 times in 256,
         * and then the device would take it and write garbage. So the wrong
         * passphrase is one whose BOTH forms fail that test for this backup.
         */
        const { keys, backupkey } = require('node-onlykey-lib/device');
        const data = Uint8Array.from(backup.parse(newBackup).data);
        let wrong = null;
        for (let n = 0; n < 64 && !wrong; n++) {
          const candidate = `pässwört ${n} pässwört pässwört`;
          const opens = keys.backupPassphraseCandidates(candidate)
            .some((c) => backupkey.predictRestore(data, c.key).accepted);
          if (!opens) wrong = candidate;
        }
        assert.ok(wrong, 'no wrong passphrase found that both forms fail');

        let refusal = null;
        try {
          await stack.services.device.restore(newBackup, { passphrase: wrong });
        } catch (err) {
          refusal = err;
        }
        assert.ok(refusal, 'a wrong passphrase was accepted');
        assert.match(refusal.message, /does not open this backup/);
        assert.absent(stack.vendorWrites().length === written,
          'no backup key and no restore packet was sent for a wrong passphrase');
      } finally {
        await stack.destroy();
      }
    });
});
