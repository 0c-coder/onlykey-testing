/*
 * The second profile: the PIN this kit provisions on every single run and had
 * never once used.
 *
 * `PINS.secondary` appeared exactly once in the whole suite before this file,
 * in `07-unlock`, and only as a NEGATIVE assertion - "the wrong PIN must not be
 * this one". Every run set it up and no run ever entered it. That is the worst
 * shape a feature can be in: provisioned, so it looks covered, and unexercised,
 * so a break in it is invisible.
 *
 * WHAT THE SECOND PROFILE ACTUALLY IS, from `password.cpp`'s
 * profile2hashevaluate(). On a match it reads `2ndprofilemode` out of EEPROM: if
 * it is not NONENCRYPTEDPROFILE it unwraps the profile key and sets
 * `profilemode = STDPROFILE2`; if it is, it sets `profilemode =
 * NONENCRYPTEDPROFILE` and derives no key at all.
 *
 * That second branch is NOT what this file is about, and the distinction matters
 * enough to state before anything else - see README's "STD_VERSION" note.
 * NONENCRYPTEDPROFILE is primarily a BUILD: `setup()` assigns it in the `#else`
 * of `#ifdef STD_VERSION` (OnlyKey.ino:259-263), which is the International
 * Travel Edition, and that edition exists because some countries do not permit
 * encrypted devices. A legal constraint, not a security feature. Plausible
 * deniability is that build's property. Everything below is the STD build, which
 * is the only one this kit has ever compiled or run.
 *
 * So what the second profile gives you in an STD build is ONE thing, and this
 * file is the two halves of it:
 *
 *   IT IS A DIFFERENT SET OF SLOTS. `gen_press()` in OnlyKey.ino computes
 *   `slot = (button_selected - '0') + 12` when `profilemode` is set, and
 *   `gen_hold()` the same plus six - so the second profile's buttons address
 *   slots 13..24 and can never address 1..12. Twelve slots per profile,
 *   twenty-four in total.
 *
 *   IT IS NOT A DIFFERENT KEY, and the third test pins that. Slot passwords are
 *   sealed with `okcore_aes_gcm_encrypt(..., profilekey, ...)` (okcore.cpp:1778),
 *   and both profiles unwrap the SAME stored 32-byte master profile key -
 *   deliberately, so that a PIN change does not have to re-derive one. Measured,
 *   not reasoned: an AES-GCM decrypt of profile 1's ciphertext succeeds in
 *   profile 2 and the firmware prints the plaintext as it does it. Evidence in
 *   the third test's header.
 *
 * The row this file answers asked to "confirm it cannot see profile 1's [slot
 * data]". It can, and that premise is now in TODO's table with the other
 * disproven ones - but the correction is to the RECORD, not to the firmware.
 * Separation by slot numbering is what the second profile is documented to be.
 *
 * NAMED AFTER PINS AND SLOTS RATHER THAN MESSAGES. Every other section-1 file
 * names its tests after the endpoint they cover, because the subject is a
 * message. Here the subject is a PRESS path - `gen_press()` and the profile
 * dispatch above it - so the names carry the PIN and the slot number instead,
 * which is the thing that has to be greppable to debug one of these alone.
 *
 * ESTABLISHED, NEVER INHERITED, and here that costs a reboot per test rather
 * than the usual read-first shortcut. `ensureUnlocked()` cannot be used at all:
 * it reads the status, sees `unlocked`, and returns - and an unlocked device
 * says nothing about WHICH PROFILE it is unlocked into, so a test that accepted
 * it would assert about whichever profile its predecessor happened to leave
 * open. Every test here restarts and enters its own PIN.
 *
 * SURFACES - see PRODUCTION.md. The KEYBOARD surface carries every assertion
 * about what the device holds, which is the strongest oracle in the kit and
 * survives into a production walk whole: what a slot contains is proven by
 * reading what the device TYPES, not by an acknowledgement that a write was
 * accepted. The vendor interface carries the writes and the unlock
 * announcement. The console is not read at all.
 */
'use strict';

const { describe, it } = require('../../lib/harness');
const { PINS } = require('../../lib/config');
const { IFACE, okmsg } = require('../../lib/device');

/* okcore.cpp's set_slot() field ids, matching python-onlykey's MessageField. */
const FIELD = { LABEL: 1, PASSWORD: 5 };

/*
 * The same button, and the two slots it reads. gen_press() adds 12 in the
 * second profile, so these are button 1's slot in each.
 */
const BUTTON = 1;
const SLOT_FIRST = 1;
const SLOT_SECOND = 13;

/* Distinguishable at a glance in a failure message, and typeable. */
const IN_ONE = 'profileONEsecret1';
const IN_TWO = 'profileTWOsecret2';

describe('the second profile, and the PIN that reaches it', {
  state: 'initialized',
  /* Classic only: the DUO fixture sets no second-profile PIN - a DUO's extra
   * profiles come from button 3 (Duo_config[1]), and the App leaves that PIN
   * slot empty. A DUO second-profile PIN, if anyone uses one, wants its own file. */
  requires: ['crypto', 'keyboard-capture', 'classic'],
  timeoutMs: 180000,
}, () => {
  /**
   * Enter a profile from a known state.
   *
   * The restart is what makes this honest rather than convenient. Entering a
   * PIN only means "unlock" on a locked device - on an unlocked one the digits
   * are slot presses, and the device types whatever those slots hold while the
   * call waits for an UNLOCKED that will not come again. A reboot is the
   * cheapest way to know which state we are in.
   */
  async function enterProfile(device, pin, { signal, assert }) {
    await device.restart({ signal });
    const model = await device.unlock(pin, { signal });
    assert.match(model, /^UNLOCKED/, `the device did not unlock: ${model}`);
    return model;
  }

  /** Seal a password into a slot, in whatever profile is currently open. */
  async function storePassword(device, slot, value, { signal, assert }) {
    const since = device.mark(IFACE.VENDOR);
    device.sendVendor({ msg: okmsg.MSG.OKSETSLOT, slot, field: FIELD.PASSWORD, payload: value });
    const reply = await device.waitHid(IFACE.VENDOR,
      { since, match: /Successfully set|Error/, timeoutMs: 8000, signal });
    const said = okmsg.text(reply).trim();
    assert.ok(!/Error/.test(said), `storing a password in slot ${slot} failed: ${said}`);
    return said;
  }

  /**
   * Press a button and return everything the device typed.
   *
   * Retried three times for the reason 08-slot-keyboard documents: payload()
   * prints "Additional Character" and then does `if (isfade) return;`, so a
   * press that lands while the LEDs are still animating - from the unlock, or
   * from the blink that acknowledges a slot write - is consumed and produces
   * nothing at all. The firmware prints nothing when the fade ends, so pressing
   * again is the only honest option, and it is what a person does anyway.
   *
   * `want` is optional. Given, the wait ends as soon as it appears, which is
   * fast. Withheld - which is what the third test needs, since it is asserting
   * that a particular string does NOT appear - there is nothing to wait FOR, so
   * each press is given a fixed window to produce whatever it is going to
   * produce.
   */
  async function pressAndRead(device, button, { signal, log, want = null, windowMs = 4000 }) {
    device.keys.clear();

    for (let attempt = 1; attempt <= 3; attempt++) {
      device.press(button);

      if (want) {
        const hit = await device.waitKeystrokes(want, { timeoutMs: windowMs, signal })
          .catch(() => null);
        if (hit) return device.keystrokes;
      } else {
        await device.sleep(windowMs, { signal });
        if (device.keystrokes.length) return device.keystrokes;
      }
      log(`press ${attempt} produced ${JSON.stringify(device.keystrokes)}`);
    }
    return device.keystrokes;
  }

  it('the secondary PIN unlocks into the second profile, where button 1 reads slot 13',
    async ({ device, assert, signal, log }) => {
      /*
       * SURFACE: keyboard for the assertion, vendor for the writes and the
       * unlock - so this test survives into a production walk whole.
       *
       * Both slots are written from INSIDE the second profile, which is what
       * makes the discriminator airtight. Slot 1 and slot 13 hold different
       * passwords sealed with the SAME profile key, so whichever one the device
       * types identifies the slot the press selected and nothing else. Had slot
       * 1 been written from the other profile, a failure to type it would have
       * been ambiguous between "the wrong slot" and "the wrong key".
       */
      await enterProfile(device, PINS.secondary, { signal, assert });

      await storePassword(device, SLOT_FIRST, IN_ONE, { signal, assert });
      await storePassword(device, SLOT_SECOND, IN_TWO, { signal, assert });

      const typed = await pressAndRead(device, BUTTON, { signal, log, want: IN_TWO });
      log(`typed ${JSON.stringify(typed)}`);

      assert.includes(typed, IN_TWO,
        `in the second profile, button ${BUTTON} should read slot ${SLOT_SECOND}`);
      assert.ok(!typed.includes(IN_ONE),
        `button ${BUTTON} read slot ${SLOT_FIRST} - the press did not take the ` +
        'profile-2 branch of gen_press()');
    });

  it('the primary PIN unlocks into the first profile, where button 1 reads slot 1',
    async ({ device, assert, signal, log }) => {
      /*
       * SURFACE: keyboard for the assertion, vendor for the writes and the
       * unlock.
       *
       * The other half of the same claim, and it is not redundant: on its own,
       * the test above is also consistent with a device that reads slot 13 for
       * EVERY profile. Two profiles reading two different slots for one button
       * is the property, and it takes both halves to say it.
       */
      await enterProfile(device, PINS.primary, { signal, assert });

      await storePassword(device, SLOT_FIRST, IN_ONE, { signal, assert });
      await storePassword(device, SLOT_SECOND, IN_TWO, { signal, assert });

      const typed = await pressAndRead(device, BUTTON, { signal, log, want: IN_ONE });
      log(`typed ${JSON.stringify(typed)}`);

      assert.includes(typed, IN_ONE,
        `in the first profile, button ${BUTTON} should read slot ${SLOT_FIRST}`);
      assert.ok(!typed.includes(IN_TWO),
        `button ${BUTTON} read slot ${SLOT_SECOND} while in the first profile`);
    });

  it('both profiles share one profile key, so slot 13 sealed in profile 1 reads back in profile 2',
    async ({ device, assert, signal, log }) => {
      /*
       * SURFACE: keyboard for the assertion, vendor for the write.
       *
       * PINNED AS IT SHIPS, AND IT IS THE OPPOSITE OF WHAT TODO ASKED FOR. The
       * row this file answers said "confirm it cannot see profile 1's [slot
       * data]". It can. That premise is now in TODO's table with the other
       * disproven ones, and this test exists to pin the behaviour rather than
       * the expectation - so it FAILS if the profiles are ever given separate
       * keys, which is the notice a reader would want.
       *
       * The measurement, printed by the firmware itself on the first run of this
       * file, when the assertion was still the other way round:
       *
       *     INPUT KEY         85 E7 A9 F7 …      the key profile 2 read with
       *     SLOT              13
       *     ENCRYPTED STATE   E6 C2 DD 70 …      sealed while in profile 1
       *     DECRYPTED STATE   70 72 6F 66 69 …   "profileONEsecret1"
       *
       * An AES-GCM decrypt that SUCCEEDS across the profile boundary can only
       * mean one key, and okcore.cpp:1778 is where the seal happens.
       *
       * WHY IT IS ONE KEY, from `password.cpp`'s two unwrap paths. The device
       * stores ONE random 32-byte master profile key and wraps it for each PIN
       * - `okcore_flashset_profilekey()` for the primary, its counterpart for the
       * second - and profile2hashevaluate() unwraps that same blob with a KEK
       * derived from ITS shared secret. The comment at that branch says why:
       * "Using new method, PIN changes supported". A per-profile key would have
       * to be re-derived on every PIN change; a wrapped master does not. The
       * backwards-compatible path beside it - `Curve25519::eval(profilekey, KEK,
       * p1hash)` - is the one that gives profile 2 a key of its own, and it only
       * runs when no stored profile key is found.
       *
       * SO THE SECOND PROFILE'S SEPARATION IS BY SLOT NUMBERING, NOT BY
       * CRYPTOGRAPHY, and the first two tests are what that separation actually
       * consists of. Two things bound the exposure and are worth stating so this
       * is not read as more alarming than it is: gen_press() and gen_hold()
       * ALWAYS add 12 in the second profile, so a second-profile user cannot
       * press their way to slots 1..12 at all; and no client message reads a
       * password back out, so the vendor interface does not offer a way either.
       * Reaching across takes a slot both profiles can address - which is what
       * this test arranges, and what a client configuring all 24 slots from one
       * unlocked session would arrange too.
       *
       * The controls are unchanged in purpose. Control A proves the write path
       * and the seal are working in the session that wrote them, so the
       * cross-profile read below is a read of real ciphertext; control B proves
       * button 1 in the second profile really does select slot 13, so a pass
       * here cannot be the press landing somewhere else.
       */
      await enterProfile(device, PINS.primary, { signal, assert });
      await storePassword(device, SLOT_SECOND, IN_ONE, { signal, assert });
      await storePassword(device, SLOT_FIRST, IN_ONE, { signal, assert });

      const controlA = await pressAndRead(device, BUTTON, { signal, log, want: IN_ONE });
      assert.includes(controlA, IN_ONE,
        'the first profile cannot read back a password it just sealed, so nothing ' +
        'below would prove anything');

      await enterProfile(device, PINS.secondary, { signal, assert });
      const crossed = await pressAndRead(device, BUTTON, { signal, log, want: IN_ONE });
      log(`the second profile typed ${JSON.stringify(crossed)}`);

      assert.includes(crossed, IN_ONE,
        `the second profile did NOT read slot ${SLOT_SECOND}'s profile-1 ciphertext. ` +
        'If the profiles now hold separate keys that is a change in the security ' +
        'model, not a broken test - see this test\'s header and TODO');

      await storePassword(device, SLOT_SECOND, IN_TWO, { signal, assert });
      const controlB = await pressAndRead(device, BUTTON, { signal, log, want: IN_TWO });
      assert.includes(controlB, IN_TWO,
        `slot ${SLOT_SECOND} is not what button ${BUTTON} reads in the second profile, ` +
        'so the assertion above was about some other slot');
    });
});
