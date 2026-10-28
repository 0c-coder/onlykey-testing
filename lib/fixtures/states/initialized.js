/*
 * initialized - all three PINs set, device rebooted, sitting locked.
 *
 * This is the firmware's out-of-box setup flow, driven the way OnlyKeyWizard.js
 * drives it on Classic hardware. Each PIN type is a four-message state machine
 * (okcore.cpp set_primary_pin / set_secondary_pin / set_sd_pin, states 0-3):
 *
 *   msg1 (arm)          -> "Enter PIN"
 *   [round 1 digits]
 *   msg2 (store)        -> validates and stores round 1, resets the buffer
 *   msg3 (arm-confirm)  -> "Confirm PIN"   (does NOT touch the buffer)
 *   [round 2 digits]
 *   msg4 (commit)       -> validates round 2 against round 1, commits
 *
 * Sending the messages is what advances it; there is no button press needed to
 * arm a state, and no waiting on the firmware's own 20-second inactivity timer.
 *
 * Every step waits on the firmware's own print for that step rather than on a
 * sleep. That is not a refinement, it is what makes the flow correct: the
 * device consumes injected digits at roughly 100ms each, so a 7-digit PIN takes
 * the better part of a second to land, and a fixed sleep let the "store"
 * message arrive mid-burst. The firmware then saw a 5-digit PIN, answered
 * "Error PIN is not between 7 - 10 digits", and the whole sequence ran to
 * completion having committed nothing.
 *
 * Each step also waits on its FAILURE print alongside its success print, so a
 * device that rejects something fails here, at the step that failed, in the
 * device's own wording - instead of surfacing eight seconds later as an
 * unexplained timeout.
 */
'use strict';

const { PINS } = require('../../config');
const { okmsg, IFACE } = require('../../device');
const { isDuo } = require('../../model');

/* All three state machines print the same strings, so the accumulator is
 * cleared between steps to keep every wait unambiguous. */
const TOO_SHORT = /Error PIN is not between 7 - 10 digits/;
const MISMATCH = /Error PINs Don't Match/;

/* The firmware prints one of these per digit: "password appended with",
 * "SD password appended with", "2nd profile password appended with". Counting
 * them is the only way to know the whole burst was consumed - one print per
 * BYTE means a first-match wait returns after the first digit. */
const DIGIT_ACK = /password appended with/gi;

const ROUNDS = [
  ['primary', PINS.primary],
  ['secondary', PINS.secondary],
  ['selfDestruct', PINS.selfDestruct],
];

/*
 * A DUO's PINs, the way the App sets them (OnlyKey-App OnlyKeyDevice.sendPinDUO()):
 * one OKSETPIN whose payload is 0xFF and then three 16-byte slots of ASCII
 * digits - primary at frame offset 6, second profile at 22, self-destruct at 38
 * (okcore_quick_setup). A DUO's buttons cannot type PIN digits 4-6 while a PIN
 * is being set (payload() maps a hold to +3 only while the key is LOCKED), so
 * there is no press-by-press setup to drive. No second-profile PIN: a DUO's
 * extra profiles are button 3's, not a PIN's; the App leaves that slot empty.
 */
async function provisionDuo(device, { log, signal } = {}) {
  const slot = (pin) => {
    const b = Buffer.alloc(16);
    Buffer.from(String(pin || ''), 'ascii').copy(b);
    return b;
  };
  const since = device.mark(IFACE.VENDOR);
  device.sendVendor({
    msg: okmsg.PIN_KIND.primary,
    payload: Buffer.concat([Buffer.from([0xFF]), slot(PINS.primary), slot(''), slot(PINS.selfDestruct)]),
  });
  const ack = await device.waitHid(IFACE.VENDOR,
    { since, match: /Successfully set PIN|Error/, timeoutMs: 30000, signal });
  const said = okmsg.text(ack).trim();
  if (!/Successfully set PIN/.test(said)) throw new Error(`DUO PIN setup: device reported "${said}"`);
  log && log('DUO primary and self-destruct PINs set (App-style quick setup)');
}

module.exports = {
  name: 'initialized',
  description: 'primary, secondary (classic only) and self-destruct PINs set; boots locked',
  requires: ['crypto'],

  /*
   * Locked, not merely provisioned.
   *
   * On the emulator this distinction is free: a snapshot always boots locked,
   * because the unlocked flag and the PIN hashes are RAM rebuilt in setup().
   * On hardware nothing resets between files - the key keeps running - so a
   * file that unlocked the key hands the next file an unlocked one. Measured:
   * 04-provisioning left the key unlocked, and 06 then waited 2500ms for the
   * once-a-second INITIALIZED broadcast that only a LOCKED device sends, while
   * 07 pressed PIN digits at a device that was reading them as slot
   * selections. Both passed on the emulator and both failed on the key.
   *
   * So 'initialized' means provisioned AND sitting locked, on both adapters -
   * which is the state the emulated snapshot was always giving out anyway.
   */
  async check(device) {
    const { state } = await device.status();
    return state === 'locked';
  },

  /**
   * @param {object} device
   * @param {object} [opts] {log, adapter, signal} - signal is threaded into
   *        every wait, so a cancelled test cancels the setup flow too rather
   *        than leaving it driving the device from under the next test.
   */
  async apply(device, { log, signal } = {}) {
    if (await module.exports.check(device)) {
      log && log('already initialized and locked');
      return;
    }

    /*
     * Already provisioned, just unlocked - a previous file left it that way.
     * Unlocking is RAM state, so a reboot is the whole fix, and it is far
     * cheaper and far less destructive than re-provisioning.
     */
    const before = await device.status({ signal });
    if (before.state === 'unlocked') {
      log && log('already provisioned but unlocked - rebooting to relock');
      await device.restart({ signal });
      const after = await device.status({ signal });
      if (after.state !== 'locked') {
        throw new Error(`rebooted to relock but the device reports ${after.state} (${after.raw})`);
      }
      return;
    }

    if (isDuo()) {
      await provisionDuo(device, { log, signal });
    } else for (const [kind, pin] of ROUNDS) {
      const msg = okmsg.PIN_KIND[kind];

      const advance = async (label, patterns, timeoutMs = 15000) => {
        device.log.clear();
        device.sendVendor({ msg });
        const hit = await device.log.waitForAny(patterns, { timeoutMs, signal });
        if (hit.key !== 'ok') {
          throw new Error(`${kind} ${label}: device reported "${hit.match[0].trim()}"`);
        }
      };

      const enterDigits = async () => {
        device.log.clear();
        /* One line for the whole PIN: the firmware queues the presses and
         * replays them one per loop() iteration, so there is no per-digit delay
         * here to tune. */
        device.pressLine(pin.split(''));
        await device.log.waitForCount(DIGIT_ACK, pin.length, { timeoutMs: 15000, signal });
      };

      await advance('arm', { ok: /Enter PIN/ });
      await enterDigits();
      await advance('store', { ok: /Storing PIN/, short: TOO_SHORT });
      await advance('arm-confirm', { ok: /Confirm PIN/ });
      await enterDigits();
      await advance('commit', { ok: /Both PINs Match/, mismatch: MISMATCH, short: TOO_SHORT });

      log && log(`${kind} PIN committed`);
    }

    /*
     * The reboot is not optional and it is not observable either: `initialized`
     * is only recomputed from flash in setup(), and okcore.cpp prints "'8'
     * restart requested" immediately before CPU_RESTART(), which does not
     * return - so the device resets before the SEREMU buffer is flushed and
     * neither that print nor the byte echo before it ever reaches the host. The
     * acknowledgement is the next generation booting.
     */
    log && log('rebooting to load the new PINs');
    await device.restart({ signal });

    const { state, raw } = await device.status({ signal });
    if (state !== 'locked') {
      throw new Error(`after setup the device reports ${state} (${raw}), expected locked`);
    }
  },
};
