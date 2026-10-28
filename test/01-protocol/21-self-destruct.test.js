/*
 * The self-destruct PIN: the other one this kit provisioned on every run and had
 * never entered.
 *
 * Like `PINS.secondary`, `PINS.selfDestruct` appeared exactly once in the whole
 * suite before this file - in `07-unlock`, as a NEGATIVE assertion saying the
 * wrong PIN must never be this one. Every run set it up; no run ever typed it.
 *
 * WHAT IT DOES, and why the gate is not optional. OnlyKey.ino's press handler
 * reaches `password.sdhashevaluate()` only after profile 1 and profile 2 have
 * both failed to match, and on a match it calls `factorydefault()` - which
 * erases EEPROM and flash, erases the FIRMWARE HASH, and restarts. On a physical
 * key that last part is the expensive one: it forces the bootloader, so the key
 * needs reflashing before it is a key again.
 *
 * So this file carries `full-wipe`, the same capability `device.wipe({full})`
 * checks. It is free on the emulator and, on hardware, false unless somebody
 * sets `OKT_ALLOW_FULL_WIPE=yes` - which is the opt-in that says "I can reflash
 * this key". The capability's own reason string says exactly that, which is why
 * this file reuses it rather than inventing a second gate meaning the same thing.
 * DO NOT weaken it: a hardware run that reaches this file without the opt-in is
 * supposed to skip with that reason printed.
 *
 * ORDER OF THE THREE PIN CHECKS IS THE THING THAT MAKES THIS TESTABLE AT ALL.
 * The self-destruct branch is an `else` after both profile evaluations, so it can
 * only fire on a PIN that is neither profile's. That is also why `lib/config.js`
 * insists all three test PINs are distinct: a repeat would be swallowed by an
 * earlier branch and this file would wipe nothing while appearing to pass.
 *
 * SURFACES - see PRODUCTION.md. The vendor interface carries the status reads
 * (the once-a-second broadcast is how a locked or uninitialized device answers
 * at all) and the keyboard interface carries the second test's assertion. The
 * console is not read. So both tests survive into a production walk, which is
 * worth having: this is the one behaviour a production key must get right and
 * cannot be asked about twice.
 */
'use strict';

const { describe, it } = require('../../lib/harness');
const { PINS } = require('../../lib/config');
const { pinPresses } = require('../../lib/model');
const { IFACE, okmsg } = require('../../lib/device');
const initialized = require('../../lib/fixtures/states/initialized');

const FIELD = { PASSWORD: 5 };
const BUTTON = 1;
const SLOT = 1;
const SECRET = 'gonefterwipe1';

describe('the self-destruct PIN', {
  state: 'initialized',
  requires: ['crypto', 'full-wipe'],
  timeoutMs: 240000,
}, () => {
  /**
   * Type the self-destruct PIN at a locked device and wait out the wipe.
   *
   * The reboot IS the completion signal - factorydefault() ends in
   * CPU_RESTART() and prints no acknowledgement a client can read - so this is
   * the `waitForReboot` shape README describes for restore, and for the same
   * reason: probing across the reboot reads a stale ready flag.
   *
   * The generation is captured BEFORE the presses. A wipe that completed while
   * the mark was being taken would otherwise be waited for twice.
   */
  async function selfDestruct(device, { signal, log }) {
    const from = device.generation;
    device.pressLine(pinPresses(PINS.selfDestruct));   /* 6 is a hold of 3 on a DUO */
    const generation = await device.waitForReboot({ from, timeoutMs: 60000, signal });
    log(`the device wiped and came back as generation ${generation}`);
    return generation;
  }

  /** A locked device, from wherever this test found it. */
  async function locked(device, { signal, log, assert }) {
    await initialized.apply(device, { signal, log });
    const { state, raw } = await device.status({ signal });
    assert.equal(state, 'locked', `expected a locked, provisioned device, got ${raw}`);
  }

  it('the self-destruct PIN wipes the device, which comes back uninitialized',
    async ({ device, assert, signal, log }) => {
      /*
       * SURFACE: vendor throughout - the status a device broadcasts is what a
       * client sees, and it is the whole assertion here.
       *
       * `initialized.apply()` rather than a bare restart, because this file's own
       * predecessor may have wiped the device: the fixture is restored once per
       * FILE, not per test, so after the first self-destruct there is nothing
       * provisioned left to destroy. apply() re-provisions when it has to and
       * costs a reboot when it does not, which is what lets these tests run in
       * any order and one at a time.
       */
      await locked(device, { signal, log, assert });

      await selfDestruct(device, { signal, log });

      const { state, raw } = await device.status({ signal });
      log(`after the self-destruct: ${raw}`);
      assert.equal(state, 'uninitialized',
        `a self-destructed device must report itself uninitialized, got ${raw}`);

      /* And the PINs are gone with it, not merely the initialized flag: the
       * primary PIN that worked a moment ago now unlocks nothing. Pressed
       * rather than asked, because there is no message that reports this. */
      const since = device.mark(IFACE.VENDOR);
      device.pressLine(pinPresses(PINS.primary));
      await assert.rejects(
        () => device.waitHid(IFACE.VENDOR, { since, match: /^UNLOCKED/, timeoutMs: 8000, signal }),
        /timed out|timeout/i,
        'the primary PIN still unlocks a self-destructed device',
      );
    });

  it('a slot password stored before the self-destruct is unrecoverable after it',
    async ({ device, assert, signal, log }) => {
      /*
       * SURFACE: keyboard for both halves, vendor for the write - so this
       * survives a production walk, and it is the assertion that means
       * something to a person: not "the device says it is blank" but "the secret
       * does not come back".
       *
       * The control comes first and is not optional. Storing a password and
       * pressing the button proves the secret was really there and really
       * readable, so that its absence afterwards is the wipe and not a slot that
       * was never written.
       *
       * WHAT MAKES IT UNRECOVERABLE IS TWO THINGS, and only one of them is the
       * erase. factorydefault() clears the storage; and re-provisioning derives
       * a NEW random profile key, because okcore_flashset_profilekey() generates
       * one whenever no stored pin hash is found. So even the same three PINs on
       * the same device cannot read what the old key sealed. That is why this
       * test re-provisions before pressing: on an unprovisioned device the press
       * would go to the PIN state machine and type nothing at all, which would
       * pass for the wrong reason entirely.
       */
      await locked(device, { signal, log, assert });
      await device.unlock(PINS.primary, { signal });

      const since = device.mark(IFACE.VENDOR);
      device.sendVendor({
        msg: okmsg.MSG.OKSETSLOT, slot: SLOT, field: FIELD.PASSWORD, payload: SECRET,
      });
      const ack = await device.waitHid(IFACE.VENDOR,
        { since, match: /Successfully set|Error/, timeoutMs: 8000, signal });
      assert.ok(!/Error/.test(okmsg.text(ack)),
        `storing the secret failed: ${okmsg.text(ack).trim()}`);

      /* Three presses, because one that lands mid-fade is discarded silently -
       * see 08-slot-keyboard for the measurement. */
      let typed = null;
      for (let attempt = 1; attempt <= 3 && !typed; attempt++) {
        device.keys.clear();
        device.press(BUTTON);
        typed = await device.waitKeystrokes(SECRET, { timeoutMs: 5000, signal }).catch(() => null);
      }
      assert.ok(typed, `the device never typed the secret, so there is nothing to destroy: ` +
        `${JSON.stringify(device.keystrokes)}`);

      /* The PIN only means "self-destruct" on a locked device - on an unlocked
       * one the digits are slot presses. */
      await device.restart({ signal });
      await selfDestruct(device, { signal, log });

      await initialized.apply(device, { signal, log });
      await device.unlock(PINS.primary, { signal });

      device.keys.clear();
      for (let attempt = 1; attempt <= 3; attempt++) {
        device.press(BUTTON);
        await device.sleep(4000, { signal });
        if (device.keystrokes.length) break;
      }
      log(`after the wipe and a re-provision, slot ${SLOT} typed ` +
        `${JSON.stringify(device.keystrokes)}`);

      assert.ok(!device.keystrokes.includes(SECRET),
        'the secret came back after a self-destruct and a re-provision - either the ' +
        'wipe did not reach slot data or the profile key was not regenerated');

      /*
       * AND THE PRESS PATH IS STILL ALIVE, which the assertion above cannot say
       * for itself. Measured: after the wipe the slot types nothing at all - an
       * empty slot produces an empty keybuffer - and "nothing" is also what
       * three presses discarded mid-fade produce, and what a dead keyboard
       * interface produces. Without this control the test passes on all three.
       *
       * So write a DIFFERENT secret into the same slot on the re-provisioned
       * device and read it back: typing it proves the slot is writable, the
       * press selects it, and the keyboard interface is delivering - so the
       * silence above was the wipe.
       */
      const after = `${SECRET}-after`;
      const since2 = device.mark(IFACE.VENDOR);
      device.sendVendor({
        msg: okmsg.MSG.OKSETSLOT, slot: SLOT, field: FIELD.PASSWORD, payload: after,
      });
      const ack2 = await device.waitHid(IFACE.VENDOR,
        { since: since2, match: /Successfully set|Error/, timeoutMs: 8000, signal });
      assert.ok(!/Error/.test(okmsg.text(ack2)),
        `the re-provisioned device refused a slot write: ${okmsg.text(ack2).trim()}`);

      let control = null;
      for (let attempt = 1; attempt <= 3 && !control; attempt++) {
        device.keys.clear();
        device.press(BUTTON);
        control = await device.waitKeystrokes(after, { timeoutMs: 5000, signal }).catch(() => null);
      }
      assert.ok(control,
        `the re-provisioned device never typed a secret it had just accepted, so the ` +
        'empty read above was a broken press path rather than the wipe: ' +
        `${JSON.stringify(device.keystrokes)}`);
    });
});
