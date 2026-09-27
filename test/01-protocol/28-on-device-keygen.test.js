/*
 * On-device key generation, for every type that claims to support it.
 *
 * The firmware's "generate your own" trigger is thirty-two 0xFF bytes in place
 * of the key material on OKSETPRIV. `okcrypto_generate_random_key()` dispatches
 * on the low nibble of the type byte and is the ONLY thing standing between
 * that trigger and `ecc_priv_flash()` storing it verbatim - so a type the
 * dispatch does not know about is not refused, it is stored as a private key
 * made of 0xFF.
 *
 * THAT IS NOT HYPOTHETICAL: KEYTYPE_CURVE25519 (4) had no branch. The CLI
 * accepts it - `genkey <slot> c`, `CLI_KEY_LETTERS['c'] = CURVE25519` - so
 * `genkey` on that type produced a key whose private half is a published
 * constant, identically on every device, with a "Successfully set ECC Key" to
 * confirm it. Measured on the emulator 2026-09-22: two generations in a row
 * answered the same public key, while types 1, 2 and 3 answered differently
 * every time. Fixed in libraries by adding the missing branch.
 *
 * WHY EVERY TYPE, EVERY TIME. The defect is a MISSING branch, so it is invisible
 * to any test that enumerates the branches that exist - the dispatch and the
 * test would agree with each other and both be wrong. What cannot be faked is
 * the device's own answer, so this file drives the trigger for every type the
 * host can ask for and asks the device what it stored. A type added to
 * `CLI_KEY_LETTERS` without a matching branch fails here the day it is added.
 *
 * THE ORACLE IS FRESHNESS, not a value. A generated key is unknowable from
 * outside by construction, so there is nothing to compare it against - except
 * another one. Two generations of the same type must not agree: real randomness
 * collides with probability 2^-256, and a stored constant collides every time.
 * That catches this defect and every other way a keygen can quietly not
 * generate - a stuck RNG, a branch that writes nothing, a slot that answers
 * from the previous key.
 *
 * ON TOP OF THAT the exact failure is named. For CURVE25519 the wrong answer is
 * computable: the trigger is thirty-two 0xFF, the firmware byte-swaps the scalar
 * (`swap_buffer(0, 31, ...)`, the GnuPG ordering) which leaves a palindrome
 * unchanged, and then clamps and multiplies the base point. node:crypto can do
 * exactly that, so the test asserts the device did NOT answer it. A generic
 * freshness failure says "something is wrong"; this one says "the 0xFF trigger
 * was stored as the key", which is the sentence somebody needs.
 *
 * PQC IS IN HERE FOR THE SAME REASON IT IS IN THE FIRMWARE: it is ordinary.
 * ML-KEM-768 and X-Wing generate through the same trigger, the same dispatch and
 * the same slot infrastructure as ECC, and since the confirmation gate was
 * removed they raise no challenge either - a keygen is reachable only from
 * config mode or first use, and both are presence proofs already. If that ever
 * diverges again, the PQC rows here stop matching the ECC rows beside them.
 *
 * SURFACES - see PRODUCTION.md. Vendor for all of it: OKSETPRIV to generate,
 * OKGETPUBKEY to read back. No console, and nothing that needs the emulator, so
 * this runs against a physical key unchanged.
 */
'use strict';

const crypto = require('crypto');

const { describe, it } = require('../../lib/harness');
const { IFACE, okmsg } = require('../../lib/device');
const { PINS } = require('../../lib/config');
const pqc = require('../../lib/pqc');

/* 32 bytes of 0xFF is the firmware's "generate your own" trigger. */
const GENERATE = Buffer.alloc(32, 0xFF);
const REPORT = 64;
const SLOT = 101;                       // 'ECC1'; a fresh fixture per file

const FEATURE_DECRYPT = 32;
const FEATURE_SIGN = 64;

/*
 * Every type the host can ask the device to generate, with the length of the
 * public key it answers with. Kept in the order of the firmware's own dispatch
 * so the two can be read side by side.
 */
const TYPES = [
  { name: 'ED25519', type: 1, feature: FEATURE_SIGN, pub: 32, letter: 'x' },
  { name: 'P256R1', type: 2, feature: FEATURE_SIGN, pub: 64, letter: 'n' },
  { name: 'P256K1', type: 3, feature: FEATURE_SIGN, pub: 64, letter: 's' },
  { name: 'CURVE25519', type: 4, feature: FEATURE_DECRYPT, pub: 32, letter: 'c' },
  { name: 'ML-KEM-768', type: 5, feature: FEATURE_DECRYPT, pub: 1184, letter: 'm' },
  { name: 'X-Wing', type: 6, feature: FEATURE_DECRYPT, pub: 1216, letter: 'w' },
];

/**
 * The X25519 public key the device WOULD publish if it stored the trigger.
 *
 * `okcrypto_compute_pubkey()` does `swap_buffer(0, 31, ecc_private_key)` before
 * `Curve25519::eval()`. Reversing thirty-two identical bytes changes nothing, so
 * the scalar is still all-0xFF, and what follows is a clamped X25519 base
 * multiplication - which is what node:crypto does with a PKCS#8 wrapper. Derived
 * here rather than pasted as a hex constant so it stays right if either side's
 * convention is ever revisited.
 */
function triggerPublicKey() {
  const key = crypto.createPrivateKey({
    key: Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), GENERATE]),
    format: 'der',
    type: 'pkcs8',
  });
  return crypto.createPublicKey(key).export({ type: 'spki', format: 'der' }).subarray(12);
}

describe('on-device key generation', {
  state: 'initialized',
  requires: ['crypto'],
  timeoutMs: 900000,
}, () => {
  /** Read `want` bytes of a vendor answer as consecutive reports. */
  async function collect(device, since, want, { signal, timeoutMs = 25000 }) {
    const expected = Math.ceil(want / REPORT);
    const deadline = Date.now() + timeoutMs;
    let reports = device.reportsSince(IFACE.VENDOR, since);
    while (reports.length < expected && Date.now() < deadline) {
      await device.sleep(100, { signal });
      reports = device.reportsSince(IFACE.VENDOR, since);
    }
    return Buffer.concat(reports).subarray(0, want);
  }

  /**
   * Generate one key of `type` in the slot and return the public key the device
   * publishes for it, read back after a reboot.
   *
   * THE REBOOT IS PART OF THE MEASUREMENT, not tidying. It puts the answer on
   * the far side of flash, so what comes back is what was STORED rather than
   * whatever is still sitting in the firmware's globals from the generation -
   * which is the difference between testing a keygen and testing a memcpy. It
   * is also how OKGETPUBKEY becomes answerable at all: it is refused in config
   * mode, and `readyForKeygen()` leaves the device there.
   */
  async function generate(device, { type, feature, pub }, { signal, assert, log }) {
    await pqc.readyForKeygen(device, { signal });

    let since = device.mark(IFACE.VENDOR);
    device.sendVendor({
      msg: okmsg.MSG.OKSETPRIV, slot: SLOT, field: type | feature, payload: GENERATE,
    });

    /*
     * ECC answers with text; a PQC keygen's response IS its public key and
     * there is no text at all, so this waits for either and treats a timeout as
     * neither having arrived rather than as a failure - the readback below is
     * what decides. `14-stored-keys` has the same split and the same reason.
     */
    const ack = await device.waitHid(IFACE.VENDOR,
      { since, match: /Successfully|Error/, timeoutMs: 20000, signal }).catch(() => null);
    if (ack) {
      const said = okmsg.text(ack).trim();
      assert.ok(!/^Error/.test(said), `the device refused to generate: ${said}`);
    }

    await device.restart({ signal });
    await device.ensureUnlocked(PINS.primary, { signal });

    since = device.mark(IFACE.VENDOR);
    device.sendVendor({ msg: okmsg.MSG.OKGETPUBKEY, slot: SLOT, field: 0 });
    const got = await collect(device, since, pub, { signal });
    assert.equal(got.length, pub,
      `a ${pub}-byte public key was expected; the slot answered ${got.length} bytes`);
    return got;
  }

  for (const t of TYPES) {
    it(`${t.name} (genkey '${t.letter}', type ${t.type}) generates a different key every time`,
      async ({ device, assert, signal, log }) => {
        const first = await generate(device, t, { signal, assert, log });
        const second = await generate(device, t, { signal, assert, log });
        log(`#1 ${first.subarray(0, 16).toString('hex')}…`);
        log(`#2 ${second.subarray(0, 16).toString('hex')}…`);

        /* The generic oracle - see the header. Everything else below only
         * sharpens the message when this is what failed. */
        assert.notEqual(first.toString('hex'), second.toString('hex'),
          `two ${t.name} generations published the SAME public key, so nothing was ` +
          'generated - okcrypto_generate_random_key() has no branch for type ' +
          `${t.type} and ecc_priv_flash() stored the 0xFF trigger as the private key`);

        assert.notEqual(first.toString('hex'), '00'.repeat(t.pub),
          'the slot published all zeros, which is not a key');
        assert.notEqual(first.toString('hex'), 'ff'.repeat(t.pub),
          'the slot published the 0xFF trigger back');

        if (t.type === 4) {
          /* Names the exact defect rather than leaving it at "not fresh". */
          const bad = triggerPublicKey().toString('hex');
          assert.notEqual(first.toString('hex'), bad,
            'the slot published the X25519 public key of the all-0xFF trigger scalar ' +
            `(${bad.slice(0, 16)}…) - that private key is a published constant and is ` +
            'the same on every OnlyKey that ran this');
        }
      });
  }
});
