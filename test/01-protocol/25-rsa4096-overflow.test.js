/*
 * Section 1: the RSA-4096 key load, and the clamp that makes it safe.
 *
 * THE DEFECT THIS FILE USED TO PIN. `rsa_priv_flash()` accumulated a key in
 * fixed 57-byte memcpys whose length was a literal, never clamped to what
 * remained in the destination. For type 4 the offsets satisfying `<= 456` are
 * 0, 57, ..., 456 - nine of them - and the ninth copied 57 bytes to
 * `rsa_private_key + 456`, touching index 512 of a 512-byte array. See
 * FINDING-rsa4096-overflow.md.
 *
 * INVERTED, NOT RETIRED. Until the fix landed this file asserted the abort:
 * expectFatal() captured the crash, and the run continued against a fresh
 * host. Its own header said that the day `rsa_priv_flash()` clamped its copy,
 * it would go red and whoever saw that should deal with it. This is that.
 *
 * Pinning a defect and pinning its fix are the same test read in opposite
 * directions, and the second is worth more: it fails if the clamp is ever
 * reverted, dropped in a rebase, or lost when this file is ported to firmware
 * that does not carry it. A retired file asserts nothing.
 *
 * WHAT IT NOW REQUIRES. Nine chunks load, the device host survives - the same
 * generation, not a replacement - and slot 2 publishes the modulus of the key
 * that was actually loaded. That last part is the one that would catch a clamp
 * that stopped the overflow by truncating the key.
 *
 * SURFACE: still gated `emulated`, and the reason has changed rather than
 * gone. Driving this at a physical key is only safe if that key's firmware
 * already has the clamp, and the test cannot know that before it runs - on
 * unfixed firmware these nine chunks are the out-of-bounds write, with no
 * _FORTIFY_SOURCE there to stop it. The same reasoning gates `23-rsa-tunnel`'s
 * 4096 case.
 */
'use strict';

const crypto = require('crypto');

const { describe, it } = require('../../lib/harness');
const { IFACE, okmsg } = require('../../lib/device');
const { PINS } = require('../../lib/config');
const { collectVendor } = require('../../lib/pgp-rsa');
const pqc = require('../../lib/pqc');

/* rsa_priv_flash() copies at most 57 bytes per report; the clamp is what makes
 * "at most" true on the last one. */
const CHUNK = 57;

/* Type 4 (4096-bit) with the SIGN feature bit, the shape the finding used. */
const TYPE_4096 = 4;
const FEATURE_SIGN = 0x40;

/* A 4096-bit modulus, which is also the whole of P||Q. */
const MODULUS_4096 = 512;

describe('the RSA-4096 key load is clamped', {
  state: 'initialized',
  requires: ['emulated', 'crypto'],
  timeoutMs: 300000,
}, () => {
  it('loads all nine chunks without aborting, and slot 2 publishes the key that was loaded',
    async ({ device, assert, signal, log }) => {
      const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 4096 });
      const jwk = privateKey.export({ format: 'jwk' });
      const pq = Buffer.concat([
        Buffer.from(jwk.p, 'base64url'), Buffer.from(jwk.q, 'base64url'),
      ]);
      const n = Buffer.from(jwk.n, 'base64url');
      assert.equal(pq.length, MODULUS_4096, 'a 4096-bit key is 512 bytes of P||Q');

      await pqc.readyForKeygen(device, { signal });
      const before = device.generation;
      const since = device.mark(IFACE.VENDOR);

      let chunks = 0;
      for (let i = 0; i < pq.length; i += CHUNK) {
        device.sendVendor({
          msg: okmsg.MSG.OKSETPRIV, slot: 2,
          field: TYPE_4096 | FEATURE_SIGN,
          payload: pq.subarray(i, i + CHUNK),
        });
        chunks += 1;
        await device.sleep(120, { signal });
      }
      assert.equal(chunks, 9, 'type 4 is nine reports, and the ninth is the one that overflowed');

      const ack = await device.waitHid(IFACE.VENDOR,
        { since, match: /Successfully|Error/, timeoutMs: 25000, signal });
      const said = okmsg.text(ack).trim();
      log(`device said: ${said}`);
      assert.match(said, /Successfully set RSA Key/,
        `the 4096-bit key did not load: ${said}`);

      /*
       * SURVIVING IS THE POINT, and "no fatal" alone does not say it. A crash
       * here is contained - the kit brings up a fresh host and carries on - so
       * an unchanged generation is what distinguishes "never aborted" from
       * "aborted and recovered quietly".
       */
      assert.ok(!device.fatal,
        'the load killed the device host, so this firmware has no clamp');
      assert.equal(device.generation, before,
        'the device host was replaced, so something aborted mid-load');

      /*
       * OKGETPUBKEY IS REFUSED IN CONFIG MODE - it prints to the console and
       * sends no vendor reply at all, so reading back without leaving first
       * times out with nothing to explain it. Restart is the only exit.
       */
      await device.restart({ signal });
      await device.ensureUnlocked(PINS.primary, { signal });

      const sincePub = device.mark(IFACE.VENDOR);
      device.sendVendor({ msg: okmsg.MSG.OKGETPUBKEY, slot: 2, field: 0 });
      const got = await collectVendor(device, sincePub, MODULUS_4096, { signal });

      /*
       * Against the key's OWN modulus, not merely a non-empty answer. A clamp
       * that stopped the overflow by dropping the tail of the key would pass
       * everything above this line and fail here.
       */
      assert.equal(got.length, MODULUS_4096, `expected a 512-byte modulus, got ${got.length}`);
      assert.ok(got.equals(n),
        'slot 2 published a different modulus than the key that was loaded');
      log('slot 2 published its own 4096-bit modulus');
    });

  it('loads a 2048-bit key through the same path, which is the size that never overflowed',
    async ({ device, assert, signal, log }) => {
      /*
       * THE CONTROL, and the clamp is why it still earns its place. Type 2's
       * offsets stop at 228 and its last copy ended at 285, inside the
       * 512-byte array - so this size never overflowed and must keep working.
       *
       * The clamp changes what it copies: the last report now moves 28 bytes
       * instead of 57. That is the half of the fix most likely to break a
       * normal load, and this is what would catch it.
       */
      const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
      const jwk = privateKey.export({ format: 'jwk' });
      const pq = Buffer.concat([
        Buffer.from(jwk.p, 'base64url'), Buffer.from(jwk.q, 'base64url'),
      ]);

      await pqc.readyForKeygen(device, { signal });
      const since = device.mark(IFACE.VENDOR);
      for (let i = 0; i < pq.length; i += CHUNK) {
        device.sendVendor({
          msg: okmsg.MSG.OKSETPRIV, slot: 2, field: 2 | FEATURE_SIGN,
          payload: pq.subarray(i, i + CHUNK),
        });
        await device.sleep(120, { signal });
      }

      const ack = await device.waitHid(IFACE.VENDOR,
        { since, match: /Successfully|Error/, timeoutMs: 25000, signal });
      const said = okmsg.text(ack).trim();
      log(`device said: ${said}`);
      assert.match(said, /Successfully set RSA Key/,
        `the 2048-bit control did not load: ${said}`);
      assert.ok(!device.fatal, 'the 2048-bit load killed the device, which it must not');
    });
});
