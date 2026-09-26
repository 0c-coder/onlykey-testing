/*
 * A CTAPHID message still arriving when the 5-second wipe timer fires must
 * not be cut in half.
 *
 * FOUND 2026-09-25, as an intermittent CTAP1_ERR_INVALID_COMMAND in FIDO2 PIN
 * tests (ok-rn's fidoPin suite, on several firmware releases). A bus capture
 * of a failing getPinToken - two CTAPHID packets - had, between them:
 *
 *     Recv packet / CID / cmd / length     <- the init packet
 *     wipe buffers after 5 sec             <- Wipedata fired mid-message
 *     Recv packet ... CTAPHID_CBOR         <- the continuation, 150 ms later
 *     error, invalid cmd                   <- ctap.cpp
 *
 * wipebuffersafter5sec() calls wipetasks(), which zeroes ctap_buffer - the
 * packets of a multi-packet message received so far - but leaves the
 * reassembly state alone. The continuation is then appended after zeros, the
 * CBOR command byte reads as 0, and the request is refused with
 * INVALID_COMMAND before anything in it is looked at. Same class as
 * 31-derive-decaps-wipe-timer, on the FIDO path.
 *
 * THIS TEST MAKES IT HAPPEN ON PURPOSE. Unlocking with the PIN arms the timer
 * (measured once, below). Then a multi-packet request is sent with its init
 * packet just before the timer is due and its continuation just after - 700 ms
 * apart, inside CTAPHID's own 750 ms message timeout. The request is a
 * getAssertion for a credential that does not exist: no PIN, no touch, and the
 * right answer is CTAP2_ERR_NO_CREDENTIALS. Measured against the unfixed
 * firmware (libraries b412e78): INVALID_COMMAND every time. With ctap_buffer
 * left alone while a message is being reassembled: NO_CREDENTIALS every time.
 *
 * The control is that the wipe really fired BETWEEN the two packets. The fix
 * does not move the timer - it only keeps the message - so the timer fires
 * there on fixed and unfixed firmware alike, and a round that missed the
 * moment proves nothing and is retried.
 */
'use strict';

const crypto = require('crypto');
const { describe, it } = require('../../lib/harness');
const { IFACE } = require('../../lib/device');
const { PINS } = require('../../lib/config');
const cbor = require('../../lib/device/cbor');
const { Ctap2, CTAPHID, CTAP2_CMD, frame } = require('../../lib/device/ctap2');

const WIPE = /wipe buffers after 5 sec/g;
const NO_CREDENTIALS = 0x2E;
const INVALID_COMMAND = 0x01;
const BEFORE_MS = 350;               // init packet this far ahead of the timer
const AFTER_MS = 350;                // continuation this far after it
const ROUNDS = 3;                    // a round that misses the moment is retried

/* A getAssertion that needs no PIN and no touch, and spans two packets. */
function assertionRequest() {
  const params = new Map([
    [1, 'example.com'],
    [2, crypto.randomBytes(32)],
    [3, [new Map([['type', 'public-key'], ['id', crypto.randomBytes(64)]])]],
  ]);
  return Buffer.concat([Buffer.from([CTAP2_CMD.GET_ASSERTION]), cbor.encode(params)]);
}

describe('CTAPHID reassembly and the 5-second wipe timer', {
  state: 'initialized',
  requires: ['crypto'],
  timeoutMs: 240000,
}, () => {
  /* Restart, unlock (which arms the timer), and say when the unlock landed. */
  async function unlockArmed(device, { signal }) {
    await device.restart({ signal });
    await device.ensureUnlocked(PINS.primary, { signal });
    return Date.now();
  }

  async function waitForWipe(device, before, { signal, timeoutMs = 9000 }) {
    const end = Date.now() + timeoutMs;
    while (Date.now() < end) {
      if (device.log.count(WIPE) > before) return Date.now();
      await device.sleep(10, { signal });
    }
    return null;
  }

  it('a message still arriving when the wipe timer fires is not cut in half',
    async ({ device, assert, signal, log }) => {
      /* How long after the unlock the timer fires, on this key. */
      const armedAt = await unlockArmed(device, { signal });
      const firedAt = await waitForWipe(device, device.log.count(WIPE), { signal });
      assert.ok(firedAt, 'unlocking did not arm the wipe timer within 9 s');
      const delay = firedAt - armedAt;
      log(`the wipe fires ${delay} ms after the unlock`);

      for (let round = 1; round <= ROUNDS; round++) {
        const unlockedAt = await unlockArmed(device, { signal });
        const ctap = new Ctap2(device, { signal });
        await ctap.init();

        const [first, ...rest] = frame(ctap.cid, CTAPHID.CBOR, assertionRequest());
        assert.ok(rest.length > 0, 'the request must span more than one packet');

        const due = unlockedAt + delay;
        await device.sleep(Math.max(0, due - BEFORE_MS - Date.now()), { signal });
        const wipesBefore = device.log.count(WIPE);
        const since = device.mark(IFACE.FIDO);
        device.send(IFACE.FIDO, first);
        await device.sleep(BEFORE_MS + AFTER_MS, { signal });
        const straddled = device.log.count(WIPE) > wipesBefore;
        for (const packet of rest) device.send(IFACE.FIDO, packet);

        const { cmd, payload } = await ctap._receive({ since, timeoutMs: 5000 });
        const status = cmd === CTAPHID.CBOR ? payload[0] : null;
        log(`round ${round}: wipe between the packets: ${straddled}; ` +
          `answer: ${cmd === CTAPHID.ERROR ? 'CTAPHID error' : `0x${(status ?? 0).toString(16)}`}`);

        if (!straddled) continue;          // missed the moment - proves nothing

        assert.control('the wipe timer fired between the init packet and its continuation',
          straddled);
        assert.notEqual(status, INVALID_COMMAND,
          'the wipe timer cut the message in half (CTAP1_ERR_INVALID_COMMAND)');
        assert.equal(status, NO_CREDENTIALS,
          'a getAssertion for a made-up credential should answer NO_CREDENTIALS');
        return;
      }
      assert.ok(false, `the wipe never fired between the two packets in ${ROUNDS} rounds - ` +
        'the test could not reach the condition it exists for');
    });
});
