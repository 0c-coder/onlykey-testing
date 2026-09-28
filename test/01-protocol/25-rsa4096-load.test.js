/*
 * Section 1: the RSA-4096 key load, pinned now that it is CORRECT.
 *
 * THIS FILE REPLACES 25-rsa4096-overflow.test.js, which pinned the defect while
 * it was live. `rsa_priv_flash()` accumulated a type-4 key in fixed 57-byte
 * memcpys whose length was a literal: the offsets satisfying `<= 456` are
 * 0, 57, ..., 456 - nine of them - and the ninth copied 57 bytes to
 * `rsa_private_key + 456`, writing index 512 of a 512-byte array.
 * See FINDING-rsa4096-overflow.md.
 *
 * libraries:merge/user-input-modes-pqc clamps it:
 *
 *     int room = MAX_RSA_KEY_SIZE - packet_buffer_offset;
 *     memcpy(rsa_private_key + packet_buffer_offset, buffer + 7,
 *            room < 57 ? room : 57);
 *
 * WHY THIS IS NOT A DELETION. The old file's header said to retire it once the
 * clamp landed, and that was the right instruction to leave at the time -
 * `expectFatal()` rejects if the device survives, so it goes red on the fix,
 * and there was no positive test to replace it with because the key could not
 * be loaded at all. It can now. Deleting would leave a memory-safety fix with
 * no coverage; a reintroduction would be caught by nothing.
 *
 * AND SURVIVAL IS NOT THE ASSERTION THAT MATTERS. A clamp that drops one byte
 * too many also survives, and would pass any test that only asks whether the
 * device is still alive - while quietly storing a key whose last byte is zero.
 * So the subject here is the MODULUS: load the key, reboot, read N back out of
 * flash, and compare it to p*q computed host-side. That fails for a removed
 * clamp (the device dies) and for a wrong one (N differs), which are the only
 * two ways this can regress.
 *
 * 8 x 57 = 456 plus a clamped 56 is exactly 512, so the byte the clamp drops is
 * the host's padding in the ninth report and none of the key. Measured
 * 2026-09-22: modulus round-trips byte for byte.
 *
 * SURFACE: vendor for everything. It needs none of its predecessor's
 * emulator-only machinery - no expectFatal, no host exit status - but it stays
 * gated `emulated` anyway, and the reason is worth stating because it is easy
 * to get wrong now that the defect is fixed.
 *
 * A test cannot know which firmware the key in front of it is running. On a
 * build WITHOUT the clamp, these nine chunks are the out-of-bounds write - and
 * on hardware there is no _FORTIFY_SOURCE to stop it; it lands silently and
 * surfaces later somewhere unrelated. The old file gated itself `emulated` for
 * exactly that reason and the fix does not retire the reason: it only means
 * the write no longer happens on builds that carry the clamp. Ungating this
 * would make the test safe exactly when it is not needed and dangerous exactly
 * when it is.
 */
'use strict';

const crypto = require('crypto');

const { describe, it } = require('../../lib/harness');
const { IFACE, okmsg } = require('../../lib/device');
const { PINS } = require('../../lib/config');
const pqc = require('../../lib/pqc');

/* rsa_priv_flash() copies a fixed 57 bytes per report; the clamp applies to the
 * last one only. */
const CHUNK = 57;

const TYPE_2048 = 2;
const TYPE_4096 = 4;
const FEATURE_DECRYPT = 0x20;
const FEATURE_SIGN = 0x40;
const SLOT = 1;
const REPORT = 64;

/** p||q and the modulus, as the device and the host each need them. */
function rsaKey(bits) {
  const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: bits });
  const jwk = privateKey.export({ format: 'jwk' });
  return {
    pq: Buffer.concat([
      Buffer.from(jwk.p, 'base64url'), Buffer.from(jwk.q, 'base64url'),
    ]),
    n: Buffer.from(jwk.n, 'base64url'),
  };
}

/**
 * Send p||q as the firmware counts it: a fixed number of reports, each carrying
 * the TYPE BYTE in buffer[6] - not a continuation marker, which is the other
 * framing in this protocol and means something else entirely. The last report
 * of a 4096-bit key is deliberately a full 57 bytes with one of padding: that
 * padding byte IS the overflow, and driving it is the point.
 */
async function sendKey(device, { slot, typeByte, pq }, { signal }) {
  for (let i = 0; i < pq.length; i += CHUNK) {
    const slice = pq.subarray(i, i + CHUNK);
    const payload = Buffer.alloc(CHUNK);
    slice.copy(payload);
    device.sendVendor({ msg: okmsg.MSG.OKSETPRIV, slot, field: typeByte, payload });
    await device.sleep(120, { signal });
  }
}

describe('an RSA-4096 key loads intact, and the ninth chunk overflows nothing', {
  state: 'initialized',
  requires: ['emulated', 'crypto'],   // see the header: not a machinery need, a safety one
  timeoutMs: 300000,
}, () => {
  /**
   * Generate a 4096-bit key and put it in the slot, from wherever the device is.
   *
   * Each test calls this rather than sharing one load, because `--isolate` is
   * the gate for a new file and a test that only passes after its neighbour ran
   * is a test that cannot be run on its own to reproduce a failure. The cost is
   * one extra load - about twelve seconds - and it buys a modulus assertion that
   * stands by itself.
   */
  async function load4096(device, { assert, signal, log }) {
    const key = rsaKey(4096);
    assert.equal(key.pq.length, 512, 'a 4096-bit key is 512 bytes of P||Q');
    assert.equal(key.n.length, 512, 'and its modulus is 512 bytes');

    await pqc.readyForKeygen(device, { signal });
    const since = device.mark(IFACE.VENDOR);
    await sendKey(device, { slot: SLOT, typeByte: TYPE_4096 | FEATURE_DECRYPT, pq: key.pq },
      { signal });

    const ack = await device.waitHid(IFACE.VENDOR,
      { since, match: /Successfully|Error/, timeoutMs: 25000, signal });
    const said = okmsg.text(ack).trim();
    log(`device said: ${said}`);
    assert.match(said, /Successfully set RSA Key/, `the 4096-bit load failed: ${said}`);
    return key;
  }

  it('loads nine chunks without killing the device', async ({ device, assert, signal, log }) => {
    await load4096(device, { assert, signal, log });

    /* The direct inverse of the old expectFatal(): the device must still be
     * there. It is worth its own test so a reintroduced overflow names itself
     * rather than arriving as "the modulus did not match". */
    assert.ok(!device.fatal, 'the 4096-bit load killed the device - the clamp is gone');
  });

  it('publishes a modulus equal to p*q, so the clamp dropped padding and not key material',
    async ({ device, assert, signal, log }) => {
      const key = await load4096(device, { assert, signal, log });

      /*
       * Out of config mode first, and through flash on the way: OKGETPUBKEY is
       * refused in config mode, and a reboot is what makes this a test of what
       * was STORED rather than of what is still sitting in RAM from the load.
       */
      await device.restart({ signal });
      await device.unlock(PINS.primary, { signal });

      const since = device.mark(IFACE.VENDOR);
      device.sendVendor({ msg: okmsg.MSG.OKGETPUBKEY, slot: SLOT });

      /* Counted in REPORTS as well as bytes, for the reason 13-large-response
       * gives: a short byte count is a truncated response and a changed report
       * count is changed framing, and they are different news. */
      const expected = key.n.length / REPORT;
      const deadline = Date.now() + 25000;
      let reports = device.reportsSince(IFACE.VENDOR, since);
      while (reports.length < expected && Date.now() < deadline) {
        await device.sleep(100, { signal });
        reports = device.reportsSince(IFACE.VENDOR, since);
      }
      const got = Buffer.concat(reports).subarray(0, key.n.length);

      log(`modulus ${got.length} bytes in ${reports.length} reports`);
      assert.equal(reports.length, key.n.length / REPORT,
        `expected ${key.n.length / REPORT} reports for a 4096-bit modulus, got ${reports.length}`);

      /*
       * THE ASSERTION THE WHOLE FILE EXISTS FOR. A clamp of `room - 1` would
       * store 511 bytes and a trailing zero; the device would survive, report
       * success, and answer with a modulus that is not p*q. Only this catches
       * that.
       */
      assert.bytes(got, key.n,
        'the stored modulus is not p*q - the ninth chunk lost key material');
    });

  it('loads a 2048-bit key through the same path, which is the control',
    async ({ device, assert, signal, log }) => {
      /*
       * The same code path, the same framing, one size smaller. Type 2's
       * offsets stop at 228 and the last copy ends at 285, well inside the
       * 512-byte array, so the clamp is never reached. Without this, a failure
       * above would be equally consistent with the kit framing OKSETPRIV
       * wrongly; with it, the difference is the key size and nothing else.
       */
      const small = rsaKey(2048);
      await pqc.readyForKeygen(device, { signal });
      const since = device.mark(IFACE.VENDOR);
      await sendKey(device, { slot: 2, typeByte: TYPE_2048 | FEATURE_SIGN, pq: small.pq },
        { signal });

      const ack = await device.waitHid(IFACE.VENDOR,
        { since, match: /Successfully|Error/, timeoutMs: 25000, signal });
      const said = okmsg.text(ack).trim();
      log(`device said: ${said}`);
      assert.match(said, /Successfully set RSA Key/, `the 2048-bit control did not load: ${said}`);
      assert.ok(!device.fatal, 'the 2048-bit load killed the device, which it must not');
    });
});
