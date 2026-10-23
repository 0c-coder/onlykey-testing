'use strict';
/*
 * F9 (3.1.0 RC, found 2026-10-23 by Edge's tests on a hard key): a backup of a key holding
 * a composite PQC-PGP key in an RSA slot.
 *
 * libraries 37aa531, onlykey/okcore.cpp backup(): for each RSA slot it copies `type * 128`
 * bytes from rsa_private_key[MAX_RSA_KEY_SIZE = 512]. okcore_flashget_RSA() leaves `type` =
 * KEYTYPE_PQC_PGP (7) for such a slot, after reading only the 160-byte seed blob, so the
 * copy is 896 bytes - 384 past the buffer. RESTORE() then meets key type 7 in an RSA record,
 * which it does not know, and stops: "Error key configuration backup file format incorrect".
 *
 * This file asserts what SHOULD happen (the backup restores) and logs what does, with the
 * backup's length. On the RC it fails; that failure is the proof.
 */
const crypto = require('node:crypto');
const { describe, it } = require('../../lib/harness');
const { IFACE, okmsg } = require('../../lib/device');
const { PINS } = require('../../lib/config');
const backup = require('../../lib/device/backup');
const pqc = require('../../lib/pqc');

const RSA_SLOT = 1;
const PQC_PGP_KEYTYPE_BYTE = 0x67; /* KEYTYPE_PQC_PGP | DECRYPT | SIGN, as Edge's composite test loads it */
const PASSPHRASE = 'okt f9 pqc backup passphrase';
const sha256 = (b) => crypto.createHash('sha256').update(b).digest();

describe('F9: a backup of a key holding a PQC-PGP key', { state: 'initialized', timeoutMs: 900000, requires: ['crypto', 'keyboard-capture'] }, () => {
  it('backs up the slot\'s 160 bytes, and the backup restores', async ({ device, assert, signal, log }) => {
    /* a backup passphrase (config mode), as Edge's backup test sets one */
    await device.ensureUnlocked(PINS.primary, { signal });
    await device.enterConfigMode(PINS.primary, { signal });
    let since = device.mark(IFACE.VENDOR);
    device.sendVendor({ msg: okmsg.MSG.OKSETPRIV, slot: 131, payload: Buffer.concat([Buffer.from([161]), sha256(Buffer.from(PASSPHRASE, 'utf8'))]) });
    assert.match(okmsg.text(await device.waitHid(IFACE.VENDOR, { since, match: /Successfully|Error/, timeoutMs: 10000, signal })), /Successfully set Backup Passphrase/);
    await device.restart({ signal });
    await device.unlock(PINS.primary, { signal });

    /* the composite key into RSA slot 1 - the same messages Edge's test (and loadpqc) send */
    await pqc.readyForKeygen(device, { signal });
    const blob = crypto.randomBytes(160);
    since = device.mark(IFACE.VENDOR);
    for (let i = 0; i < blob.length; i += 57) {
      device.sendVendor({ msg: okmsg.MSG.OKSETPRIV, slot: RSA_SLOT, field: PQC_PGP_KEYTYPE_BYTE, payload: blob.subarray(i, i + 57) });
      await device.sleep(150, { signal });
    }
    const ack = okmsg.text(await device.waitHid(IFACE.VENDOR, { since, match: /Successfully|Error/, timeoutMs: 15000, signal }));
    assert.ok(!/^Error/.test(ack.trim()), `loading the composite key failed: ${ack}`);
    await device.sleep(500, { signal });
    await device.restart({ signal });
    await device.unlock(PINS.primary, { signal });

    /* the backup: hold button 1, the key types it (keyboard speed on a hard key) */
    let started = false;
    for (let attempt = 1; attempt <= 6 && !started; attempt++) {
      device.log.clear();
      device.keys.clear();
      device.pressLine([{ button: 1, hold: 'hold' }]);
      started = await Promise.any([
        device.log.waitFor(/Backing up Label Number/, { timeoutMs: 5000, signal }),
        device.waitKeystrokes(/-----BEGIN ONLYKEY BACKUP-----/, { timeoutMs: 5000, signal }),
      ]).then(() => true, () => device.keystrokes.length > 0);
    }
    assert.ok(started, 'the device never started a backup');
    await device.waitKeystrokes(/-----END ONLYKEY BACKUP-----/, { timeoutMs: 600000, signal });
    const parsed = backup.parse(device.keystrokes);
    assert.ok(parsed && parsed.data.length, 'no backup data');

    /*
     * The backup's own length is the measure of what backup() copied for the slot: the RC's
     * is 736 bytes longer than a fixed build's for the same key set (896 - 160). The console
     * cannot be counted for it - the slot's AES decrypt prints its own bytes in between.
     */
    log(`backup: ${parsed.data.length} bytes`);

    /* the restore onto this device (config mode) */
    await device.enterConfigMode(PINS.primary, { signal });
    since = device.mark(IFACE.VENDOR);
    const gen = device.generation;
    for (const payload of backup.toRestorePackets(parsed.data)) {
      device.sendVendor({ msg: okmsg.MSG.OKRESTORE, payload });
      await device.sleep(50, { signal });
    }
    const answer = okmsg.text(await device.waitHid(IFACE.VENDOR, { since, match: /Successfully loaded backup|format incorrect|Error/, timeoutMs: 90000, signal }));
    log(`restore answered: ${answer.trim()}`);
    if (/Successfully loaded backup/.test(answer)) await device.waitForReboot({ from: gen, timeoutMs: 90000, signal });
    else await device.restart({ signal });

    assert.match(answer, /Successfully loaded backup/, `the backup does not restore: ${answer.trim()}`);
  });
});
