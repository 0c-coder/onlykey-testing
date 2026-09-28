/*
 * A derived X-Wing decapsulation must survive the 5-second wipe timer firing
 * while its chunks are still arriving.
 *
 * FOUND 2026-09-22, in 02-cli/07-derived-xwing: one `age -d` answered
 * "Error derived decaps payload size" and the re-run did not. The device log
 * of the failing run had, between two of the 21 OKDECRYPT reports:
 *
 *     OKDECRYPT MESSAGE RECEIVED
 *     wipe buffers after 5 sec          <- Wipedata fired mid-request
 *     Received packet
 *     OKDECRYPT MESSAGE RECEIVED        <- the final 12-byte report
 *
 * fadeoff() - the end of almost every operation - arms Wipedata for 5 s, and
 * wipebuffersafter5sec() calls wipetasks(), which calls okcrypto_derive_reset()
 * and zeroes derive_offset. The ordinary multi-packet path re-arms the timer
 * on every packet (process_packets() calls wipedata()); the derived X-Wing
 * reassembly in okcrypto_decrypt() does its own reassembly and did NOT. So a
 * request that started within 5 s of the previous operation and was still
 * streaming when the timer ran out lost its first part, and the final report
 * found derive_offset short of 1152.
 *
 * On a quiet machine the 21 reports take tens of milliseconds, so the window
 * is small - which is why it looked like a flake. It is not load-dependent in
 * kind, only in odds: any host that pauses between reports, or starts a
 * decapsulation shortly after another operation, can hit it.
 *
 * THIS TEST MAKES IT HAPPEN ON PURPOSE. One fast decapsulation first: it
 * yields the reference shared secret and, ending in fadeoff(), arms the timer.
 * Then, ~4.3 s later, the same request again with the reports spaced so the
 * stream spans the moment the timer is due. Measured against the unfixed
 * firmware (libraries 7bd29a4): the timer fired mid-stream and the answer was
 * "Error derived decaps payload size". With each chunk re-arming the timer
 * (libraries fix/derive-decaps-wipe-timer) the answer is the reference secret.
 *
 * X-Wing decapsulation never fails on a well-formed length - ML-KEM uses
 * implicit rejection - so a fixed arbitrary ciphertext gives a deterministic
 * shared secret, and "same answer as the fast run" is the whole assertion.
 *
 * Field 30 is set to "none" so no confirmation is primed (the unattended-agent
 * setting, honoured on every build for slot 128) and restored afterwards.
 */
'use strict';

const crypto = require('crypto');

const { describe, it } = require('../../lib/harness');
const { IFACE, okmsg } = require('../../lib/device');
const { PINS } = require('../../lib/config');
const pqc = require('../../lib/pqc');

const SLOT = 128;                 // RESERVED_KEY_WEB_AGENT_DERIVATION
const FIELD_WEB_AGENT_DERIVE_MODE = 30;
const USER_INPUT_PRESS = 1;
const USER_INPUT_NONE = 2;
const XWING_CT = 1120;
const WIPE = /wipe buffers after 5 sec/g;

const tag = crypto.createHash('sha256').update('wipe-timer', 'utf8').digest();
const ct = crypto.createHash('sha512').update('fixed ciphertext').digest();
const CIPHERTEXT = Buffer.alloc(XWING_CT);
for (let i = 0; i < XWING_CT; i++) CIPHERTEXT[i] = ct[i % ct.length] ^ (i & 0xFF);
const PAYLOAD = Buffer.concat([tag, CIPHERTEXT]);            // 1152 = 20 x 57 + 12

const ANSWER = (buf) => {
  const text = okmsg.text(buf);
  return text !== 'INITIALIZED';
};

describe('derived decapsulation and the 5-second wipe timer', {
  state: 'initialized',
  requires: ['crypto'],
  timeoutMs: 240000,
}, () => {
  async function setDeriveMode(device, value, { signal }) {
    await pqc.readyForKeygen(device, { signal });
    const since = device.mark(IFACE.VENDOR);
    device.sendVendor({
      msg: okmsg.MSG.OKSETSLOT, slot: 1, field: FIELD_WEB_AGENT_DERIVE_MODE,
      payload: Buffer.from([value]),
    });
    const ack = await device.waitHid(IFACE.VENDOR, { since, match: /Success|Error/, timeoutMs: 8000, signal });
    await device.restart({ signal });
    await device.ensureUnlocked(PINS.primary, { signal });
    return okmsg.text(ack).trim();
  }

  /** Send the 21 reports, `gapMs` apart, and return the device's answer. */
  async function decaps(device, gapMs, { signal }) {
    const since = device.mark(IFACE.VENDOR);
    const startedAt = Date.now();
    let lastSentAt = startedAt;
    for (let off = 0; off < PAYLOAD.length; off += 57) {
      const part = PAYLOAD.subarray(off, off + 57);
      const last = off + 57 >= PAYLOAD.length;
      device.sendVendor({
        msg: okmsg.MSG.OKDECRYPT, slot: SLOT,
        field: last ? part.length : 0xFF, payload: part,
      });
      lastSentAt = Date.now();
      if (gapMs && !last) await device.sleep(gapMs, { signal });
    }
    const reply = await device.waitHid(IFACE.VENDOR, { since, match: ANSWER, timeoutMs: 15000, signal });
    /* A shared secret is binary; only an error or status is text worth keeping. */
    const said = okmsg.text(reply);
    const text = /^(Error|Timeout)/.test(said) ? said : '';
    return { text, ss: reply.subarray(0, 32), startedAt, lastSentAt };
  }

  it('a request still streaming when the wipe timer fires is not cut in half',
    async ({ device, assert, signal, log }) => {
      const set = await setDeriveMode(device, USER_INPUT_NONE, { signal });
      assert.match(set, /^Success/, `setting field 30 to no-press: ${set}`);
      try {
        /* Reference answer, fast. It ends in fadeoff(), which arms Wipedata. */
        const first = await decaps(device, 0, { signal });
        log(`fast: ${first.text || first.ss.toString('hex').slice(0, 24) + '...'}`);
        assert.ok(!/^Error|^Timeout/.test(first.text), `the fast request was refused: ${first.text}`);
        const armedAt = Date.now();

        /* Start ~0.7 s before the timer runs out and take ~1.4 s to finish. */
        await device.sleep(Math.max(0, 5000 - 700 - (Date.now() - armedAt)), { signal });
        const wipesBefore = device.log.count(WIPE);
        const second = await decaps(device, 70, { signal });
        const wipesDuring = device.log.count(WIPE) - wipesBefore;
        log(`slow: ${second.text || second.ss.toString('hex').slice(0, 24) + '...'}; wipe timer fired ${wipesDuring}x during it`);

        /*
         * The control is TIMING, not the console line. Before the fix the timer
         * armed by the fast request fired mid-stream (measured: "wipe timer
         * fired 1x", answer "Error derived decaps payload size"); after it,
         * every chunk re-arms the timer, so it no longer fires there at all and
         * the console line cannot be the control. What makes the test mean
         * something is that the stream straddled the moment the OLD timer was
         * due - with a margin either side - so a firmware without the re-arm
         * would be cut here, as it was.
         */
        const due = armedAt + 5000;
        log(`stream ${second.startedAt - due} ms .. ${second.lastSentAt - due} ms around the old timer's due time`);
        assert.control('the stream straddled the moment the timer armed by the fast ' +
          'request was due', second.startedAt < due - 300 && second.lastSentAt > due + 300);
        assert.ok(!/payload size/.test(second.text),
          `the wipe timer cut the request in half: ${second.text}`);
        assert.ok(!/^Error|^Timeout/.test(second.text), `the slow request was refused: ${second.text}`);
        assert.bytes(second.ss, first.ss,
          'the same request decapsulated to a different secret the second time');
      } finally {
        await setDeriveMode(device, USER_INPUT_PRESS, { signal });
      }
    });
});
