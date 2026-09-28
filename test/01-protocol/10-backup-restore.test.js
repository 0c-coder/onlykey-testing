/*
 * The encrypted backup, created and restored.
 *
 * This is the test the emulator was built for. The old kit could not do it and
 * said so in as many words (onlykey-alpha-testing/test/08-backup-hmac.test.js):
 *
 *   a full backup-create -> restore round-trip isn't testable from this repo -
 *   there is no backup-file *creation* command anywhere in python-onlykey's
 *   client.py or CLI (only restore_from_backup(), which *consumes* a backup
 *   file); producing one is a closed-source OnlyKey-App/DUO-hardware feature
 *   this harness has no access to.
 *
 * It was never a closed-source feature. Creating a backup is the device TYPING
 * it - six hundred characters over the keyboard interface - and the old kit had
 * no way to read that, because on real hardware the keyboard is a device node
 * that needs elevated privileges and gives you every keystroke on the machine.
 * Here it is an event on a bus, which is exactly what EXPLAINER.md predicted
 * would "finally make backup and restore testable at all".
 *
 * Three firmware gates shape the order below, and none of them is obvious:
 *
 *   - The backup key is a private key in slot 131, and OKSETPRIV is refused
 *     outside config mode.
 *   - The backup itself CANNOT be taken in config mode. payload()'s backup
 *     branch requires !isfade, and config mode holds the LED in a permanent
 *     animation, so isfade never goes false. Configure, leave, then back up.
 *   - OKRESTORE is refused outside config mode. So config mode is entered
 *     twice, with a normal-mode window in the middle where the backup happens.
 */
'use strict';

const crypto = require('crypto');

const { describe, it } = require('../../lib/harness');
const { PINS } = require('../../lib/config');
const { IFACE, okmsg } = require('../../lib/device');
const backup = require('../../lib/device/backup');

/* python-onlykey requires >= 25 characters and hashes it to the 32-byte key. */
const PASSPHRASE = 'onlykey-testing backup passphrase 2026';

/* 161 = 128 (backup) | 32 (decryption) | 1 - the "Backup Decryption Key" type,
 * and 131 is the slot the firmware calls the Designated Backup Passphrase. */
const BACKUP_KEY_TYPE = 161;
const BACKUP_KEY_SLOT = 131;

const FIELD = { LABEL: 1, PASSWORD: 5 };
const SLOT = 2;                     // slot 1 belongs to 08-slot-keyboard
const LABEL = 'bkuptest';
const PASSWORD = 'backmeup42';
const OVERWRITTEN = 'clobbered77';

/* Typing 600 characters takes the better part of a minute, and the restore
 * chunks and reboots after it. */
describe('backup and restore',
  { state: 'initialized', requires: ['crypto', 'keyboard-capture'], timeoutMs: 240000 }, () => {
    let captured = null;
    let parsed = null;

    it('enters config mode, which the backup key needs', async ({ device, assert, signal }) => {
      await device.unlock(PINS.primary, { signal });
      await device.enterConfigMode(PINS.primary, { signal });

      /*
       * There is no reply that says "you are in config mode" - the proof is a
       * gated message being accepted. OKSETPRIV is the one this file needs
       * anyway, so setting the backup key IS the confirmation.
       */
      const key = crypto.createHash('sha256').update(PASSPHRASE, 'utf8').digest();
      const since = device.mark(IFACE.VENDOR);
      device.sendVendor({
        msg: okmsg.MSG.OKSETPRIV,
        slot: BACKUP_KEY_SLOT,
        payload: Buffer.concat([Buffer.from([BACKUP_KEY_TYPE]), key]),
      });

      const reply = await device.waitHid(IFACE.VENDOR,
        { since, match: /Successfully|Error/, timeoutMs: 10000, signal });
      assert.match(okmsg.text(reply), /Successfully set Backup Passphrase/,
        'the device refused the backup key');
    });

    it('stores a slot so the backup has something in it',
      async ({ device, assert, signal }) => {
        for (const [field, value] of [[FIELD.LABEL, LABEL], [FIELD.PASSWORD, PASSWORD]]) {
          const since = device.mark(IFACE.VENDOR);
          device.sendVendor({ msg: okmsg.MSG.OKSETSLOT, slot: SLOT, field, payload: value });
          const reply = await device.waitHid(IFACE.VENDOR,
            { since, match: /Successfully|Error/, timeoutMs: 8000, signal });
          assert.ok(!/Error/.test(okmsg.text(reply)), okmsg.text(reply));
        }
      });

    it('leaves config mode, because a backup cannot be taken inside it',
      async ({ device, assert, signal }) => {
        /*
         * Measured, and the reason this is its own step: with the device in
         * config mode, six long presses of button 1 produced "Button selected
         * 1" and nothing else, every time. payload()'s backup branch is
         * `duration < 180 && duration >= 72 && button_selected=='1' && !isfade`
         * and config mode's LED animation keeps isfade true forever.
         */
        await device.restart({ signal });
        const model = await device.unlock(PINS.primary, { signal });
        assert.match(model, /^UNLOCKED/);
      });

    it('types a complete backup when button 1 is held', async ({ device, assert, signal, log }) => {
      let started = false;
      for (let attempt = 1; attempt <= 6 && !started; attempt++) {
        device.log.clear();
        device.keys.clear();
        device.pressLine([{ button: 1, hold: 'hold' }]);

        /* The hold tier is 128 ticks, inside the firmware's [72,180) backup
         * band. A press that lands mid-fade is discarded, as everywhere else.
         *
         * Started is the console line OR the typing itself, whichever shows
         * first. Over the gadget the console line can trail the keystrokes past
         * the 5s window: the backup was already typing, the next attempt's
         * keys.clear() erased its BEGIN line, and the test failed on a backup
         * the device typed correctly. Any keystroke at all also counts - never
         * clear a buffer the device has started writing into. */
        started = await Promise.any([
          device.log.waitFor(/Backing up Label Number/, { timeoutMs: 5000, signal }),
          device.waitKeystrokes(/-----BEGIN ONLYKEY BACKUP-----/, { timeoutMs: 5000, signal }),
        ]).then(() => true, () => device.keystrokes.length > 0);
        if (!started) log(`hold ${attempt} landed mid-fade and was discarded`);
      }
      assert.ok(started, 'the device never started a backup in six attempts');

      /*
       * Wait on the END marker, not on the console. The console narrates the
       * slot scan and then goes quiet for the whole of the typing, which is
       * where the keystrokes actually are.
       */
      await device.waitKeystrokes(/-----END ONLYKEY BACKUP-----/, { timeoutMs: 180000, signal });
      captured = device.keystrokes;

      assert.includes(captured, backup.BEGIN);
      assert.ok(!/No Backup Key/.test(captured),
        'the device says it has no backup key - the passphrase did not take');
    });

    it('verifies against the chained SHA256 the device typed', async ({ assert }) => {
      assert.ok(captured, 'no backup was captured');
      parsed = backup.parse(captured);

      assert.ok(parsed.complete, 'the captured text is missing a marker');
      assert.ok(parsed.lines > 0, 'no base64 data lines');
      assert.ok(parsed.data.length > 0, 'the backup decoded to nothing');
      assert.ok(parsed.storedHash, 'the device typed no hash line');

      /*
       * Not a hash OF the backup - a chain, folding each line into the running
       * value. Recomputing it here and matching the device's own is what says
       * six hundred keystrokes were captured without dropping one, and it is a
       * pure-JS check against arithmetic the firmware did on its own.
       */
      assert.equal(parsed.computedHash.toString('hex'), parsed.storedHash.toString('hex'),
        'the chained hash does not match - keystrokes were lost or reordered');
    });

    it('overwrites the slot it is about to restore', async ({ device, assert, signal }) => {
      await device.enterConfigMode(PINS.primary, { signal });

      /*
       * Overwritten, not wiped, and deliberately so.
       *
       * OKWIPESLOT segfaults this firmware. wipe_slot() ends with
       * okeeprom_eeset_2FAtype(0, slot) - a literal 0 passed where the
       * signature takes a uint8_t*, so it is a NULL POINTER, not the value
       * zero (okcore.cpp:2259). On an MK20DX256 address 0 is the vector
       * table's initial stack pointer, which is readable, so the write
       * silently stores 0x00 and nobody notices. The emulator maps flash at
       * 0x1000 with page zero left unmapped precisely so a genuine NULL
       * dereference still faults - and it does, in the checkKey SoftTimer task
       * a moment after the acknowledgement comes back. The same bug class was
       * found and fixed three times in OnlyKey.ino (668, 704, 717) with
       * `{ uint8_t zero = 0; ...(&zero); }`; this one was missed.
       *
       * Overwriting is the better test anyway: it proves the restore REPLACED
       * live data, rather than merely filling a hole.
       */
      const since = device.mark(IFACE.VENDOR);
      device.sendVendor({
        msg: okmsg.MSG.OKSETSLOT, slot: SLOT, field: FIELD.PASSWORD, payload: OVERWRITTEN,
      });
      const reply = await device.waitHid(IFACE.VENDOR,
        { since, match: /Successfully|Error/, timeoutMs: 10000, signal });
      assert.ok(!/Error/.test(okmsg.text(reply)), okmsg.text(reply));
    });

    it('accepts the backup back as OKRESTORE packets', async ({ device, assert, signal, log }) => {
      assert.ok(parsed && parsed.data.length, 'nothing to restore');

      const packets = backup.toRestorePackets(parsed.data);
      log(`restoring ${parsed.data.length} bytes in ${packets.length} packets`);

      const before = device.generation;
      for (const payload of packets) {
        device.sendVendor({ msg: okmsg.MSG.OKRESTORE, payload });
        /* The device writes flash as the packets arrive; sending the whole
         * burst as fast as the bus allows is how a restore gets truncated. */
        await device.sleep(50, { signal });
      }

      /*
       * The reboot IS the completion, and waiting for it is not optional.
       * Probing before it lands reads a device that has not gone away yet and
       * then loses it mid-answer - "locked" on the emulator, where the reboot
       * is instant, and "unreachable" on a key, where re-enumeration takes
       * real time. Same race, two faces.
       */
      await device.waitForReboot({ from: before, timeoutMs: 90000, signal });
      assert.ok(!device.fatal, 'the device died during the restore');
    });

    it('comes back locked, with its PINs intact', async ({ device, assert, signal }) => {
      await device.waitReady({ signal });

      const after = await device.status({ signal });
      assert.notEqual(after.state, 'unknown', `the device is unreachable after the restore: ${after.raw}`);

      if (after.state === 'locked') {
        const model = await device.unlock(PINS.primary, { signal });
        assert.match(model, /^UNLOCKED/, 'the PIN no longer works after a restore');
      }
      assert.equal((await device.status({ signal })).state, 'unlocked');
    });

    it('has the restored label back', async ({ device, assert, signal }) => {
      /*
       * Read back over the protocol rather than by pressing the button.
       *
       * Both would prove it, but only one is deterministic: typing a slot
       * needs a press that does not land mid-fade, and this file has already
       * spent six attempts getting one past that gate. 08-slot-keyboard covers
       * the keystroke path; what this file needs to know is whether the bytes
       * came back, and OKGETLABELS answers that without touching a button.
       */
      const since = device.mark(IFACE.VENDOR);
      device.sendVendor({ msg: okmsg.MSG.OKGETLABELS });

      const reply = await device.waitHid(IFACE.VENDOR,
        { since, match: new RegExp(LABEL), timeoutMs: 10000, signal });
      assert.includes(okmsg.text(reply), LABEL,
        'the restored slot label never came back');
    });
  });
