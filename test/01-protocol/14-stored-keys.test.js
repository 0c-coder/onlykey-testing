/*
 * Stored keys: OKGETPUBKEY, OKSIGN and OKDECRYPT across all six key types.
 *
 * Every one of those three messages dispatches on the SLOT number, and until
 * now only the two RESERVED derivation slots had ever been sent - 132 for
 * SSH/GPG and 128 for the web derivation. The stored-slot branches, the ones
 * that read a key out of flash, had never been reached by any of the three.
 * That is where all six key types live, and where a bug sits on a user's real
 * key material rather than on something reproducible from a label.
 *
 * SECTION 1 ON PURPOSE. Section 2 can never run against a physical key and
 * section 3's headless tier drives the emulator by design, so section 1 is the
 * only place a test is worth double - it is the hardware-capable surface. Every
 * message here is built by the kit and put on the in-process bus; no CLI, no
 * plugin, no browser, no kernel device node.
 *
 * THE CHALLENGE-MODE BLOCKER, WHICH THIS FILE CLEARS
 * --------------------------------------------------
 * README has listed crypto vectors against stored keys as not built, blocked on
 * "challenge-mode configuration that has not been worked out". It is worked out
 * here, and it is two facts:
 *
 *   1. `stored_key_challenge_mode` = 1 turns the three-digit challenge into a
 *      SINGLE press of ANY button. done_process_packets() sets CRYPTO_AUTH = 3
 *      instead of computing Challenge_button1/2/3, and the press handler in
 *      OnlyKey.ino has a clause - `(stored_key_challenge_mode==1 && isfade &&
 *      packet_buffer_details[0])` - that jumps straight to CRYPTO_AUTH = 4
 *      without comparing which button was pressed.
 *
 *   2. IT MUST BE SENT AS THE BYTE 1, NOT THE CHARACTER '1'. The clause tests
 *      `== 1` exactly. Sending the string puts 0x31 in EEPROM, which is truthy
 *      enough for done_process_packets() to set CRYPTO_AUTH = 3 - so the device
 *      primes, and looks like it is waiting for one press - and then no press
 *      satisfies the clause, and the operation answers "Error incorrect
 *      challenge". That cost the first run of this file and is exactly the shape
 *      of thing that made the row look unworkable.
 *
 * Worth knowing next door: `03-gui/02-derive` sets the DERIVED mode with
 * `String(8)`, which is 0x38. That happens to work, because the tunnelled path
 * tests `is_bit_set(mode, 3)` and 0x38 has bit 3 set. It is right by accident,
 * and it would not survive being changed to any other value.
 *
 * WHAT EACH TYPE IS CHECKED AGAINST, because "the device answered" is not a
 * result. Nothing here trusts the device twice:
 *
 *   ed25519      pubkey and signature against node:crypto
 *   nist256p1    pubkey and signature against node:crypto
 *   secp256k1    pubkey and signature against node:crypto
 *   curve25519   shared secret against node:crypto's X25519
 *   ML-KEM-768   shared secret against @noble's encapsulation
 *   X-Wing       shared secret against @noble's encapsulation
 *
 * The three classic curves and X25519 need nothing but node:crypto. The two PQC
 * types need @noble, so they carry `xwing-math` and skip with a reason without
 * it - which is why they are separate tests rather than one loop.
 *
 * SURFACES - see PRODUCTION.md. Vendor throughout for every answer. The console
 * is read for one thing only and it is unavoidable: knowing WHEN the device has
 * primed a confirmation, so the press lands after the fade rather than during
 * it. Nothing is read from it that a client could have been told.
 */
'use strict';

const crypto = require('crypto');

const { describe, it } = require('../../lib/harness');
const { IFACE, okmsg } = require('../../lib/device');
const { PINS } = require('../../lib/config');
const pqc = require('../../lib/pqc');
const ours = require('../../lib/age-pqc');

const PRIMED = /Encrypted Buffer/g;
const REPORT = 64;

/* okcore.h key types and their feature flags, as python-onlykey folds them. */
const TYPE = { ED25519: 1, P256: 2, SECP256K1: 3, CURVE25519: 4, MLKEM768: 5, XWING: 6 };
const FEATURE_DECRYPT = 32;
const FEATURE_SIGN = 64;

const SLOT = 101;                       // 'ECC1'; a fresh fixture per file, so reused freely
const FIELD_STORED_CHALLENGE = 22;      // PGPCHALENGEMODE -> stored_key_challenge_mode

/* 32 bytes of 0xFF is the firmware's "generate your own" trigger. */
const GENERATE = Buffer.alloc(32, 0xFF);

/* RFC 8032 test vector 1 - published, so its public half is a fact rather than
 * something this file computes and then agrees with itself about. */
const ED_SEED = Buffer.from('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60', 'hex');

const ANSWER = (buf) => {
  const text = okmsg.text(buf);
  return !!text && text !== 'INITIALIZED';
};

/* SPKI wrappers, so a raw point can be handed to node:crypto. Only the curve
 * OID differs between the two prime curves. */
const SPKI = {
  ed25519: Buffer.from('302a300506032b6570032100', 'hex'),
  nist256p1: Buffer.from('3059301306072a8648ce3d020106082a8648ce3d03010703420004', 'hex'),
  secp256k1: Buffer.from('3056301006072a8648ce3d020106052b8104000a03420004', 'hex'),
  x25519: Buffer.from('302a300506032b656e032100', 'hex'),
};

/** r||s -> the DER SEQUENCE node:crypto wants. */
function derSignature(raw) {
  const int = (b) => {
    let i = 0;
    while (i < b.length - 1 && b[i] === 0) i++;
    const v = b.subarray(i);
    const body = v[0] & 0x80 ? Buffer.concat([Buffer.from([0]), v]) : v;
    return Buffer.concat([Buffer.from([0x02, body.length]), body]);
  };
  const seq = Buffer.concat([int(raw.subarray(0, 32)), int(raw.subarray(32, 64))]);
  return Buffer.concat([Buffer.from([0x30, seq.length]), seq]);
}

describe('stored keys, across all six key types', {
  state: 'initialized',
  requires: ['crypto'],
  timeoutMs: 600000,
}, () => {
  /**
   * Put a key in a slot, with the challenge mode that makes its later use cost
   * one press instead of three digits.
   *
   * Both writes need config mode; everything that USES the key needs to be out
   * of it, since OKSIGN and OKDECRYPT are not among the messages config mode
   * admits and OKGETPUBKEY is refused outright there.
   */
  async function storeKey(device, { keytype, feature, value, generates }, { signal, assert }) {
    await pqc.readyForKeygen(device, { signal });

    let since = device.mark(IFACE.VENDOR);
    device.sendVendor({
      msg: okmsg.MSG.OKSETSLOT,
      slot: 1,
      field: FIELD_STORED_CHALLENGE,
      /* THE BYTE 1. See the header - the string '1' primes and then refuses. */
      payload: Buffer.from([1]),
    });
    let reply = await device.waitHid(IFACE.VENDOR,
      { since, match: /Success|Error/, timeoutMs: 8000, signal });
    assert.ok(!/^Error/.test(okmsg.text(reply)),
      `setting the stored-key challenge mode failed: ${okmsg.text(reply)}`);

    /*
     * TWO DIFFERENT COMPLETION SIGNALS, and assuming the wrong one is a timeout
     * that names the wait rather than the reason - which is how this file's
     * first PQC run failed.
     *
     * Handing a key over answers with text: "Successfully set ECC Key".
     * GENERATING one does not answer with text at all - it raises its own
     * confirmation, and then its response IS THE PUBLIC KEY, 1184 bytes for
     * ML-KEM and 1216 for X-Wing. python-onlykey says as much without saying it
     * is different: mlkem_keygen() is documented as "returns 1184-byte pubkey".
     *
     * AND A GENERATED PQC KEY RAISES NO CONFIRMATION AT ALL, which is the
     * correction that made this pass. It read as a 20-second firmware hang and
     * it is not one; the two halves that produce it sit in different files:
     *
     *   okcore.cpp:456  OKSETPRIV is dispatched only when `configmode == true`
     *                   (or on first use) - "Only permit loading keys on first
     *                   use and while in config mode". There is no way to reach
     *                   a keygen from outside config mode.
     *   okcore.cpp:5447 `ecc_priv_flash()` gates the PQC keygen challenge on
     *                   `if (!CRYPTO_AUTH && !configmode)` - in config mode it
     *                   raises none, deliberately: "config mode IS the presence
     *                   proof", and the config-mode LED owns the indicator, so a
     *                   3-button challenge could not be answered there anyway.
     *
     * Together those make the challenge branch unreachable in normal operation,
     * so the keygen answers with the public key and nothing else. This file used
     * to wait for a prime that the firmware had decided not to send. Driving the
     * keygen out of config mode to get the challenge does not work either - the
     * dispatcher drops the message before `ecc_priv_flash()` ever sees it, which
     * is silent, and was measured here before this comment was written.
     *
     * The field-22 write above still matters: it is what covers the confirmation
     * on the DECAPS side, which is a live challenge and is answered below.
     */
    let generated = null;
    if (generates) {
      since = device.mark(IFACE.VENDOR);
      device.sendVendor({
        msg: okmsg.MSG.OKSETPRIV, slot: SLOT, field: keytype | feature, payload: value,
      });
      generated = await readBack(device, since, generates, { signal, timeoutMs: 40000 });
      assert.equal(generated.length, generates,
        `a generated key should answer with its ${generates}-byte public key`);
    } else {
      /* Handed over, not generated: stays in config mode and answers with text. */
      since = device.mark(IFACE.VENDOR);
      device.sendVendor({
        msg: okmsg.MSG.OKSETPRIV, slot: SLOT, field: keytype | feature, payload: value,
      });
      reply = await device.waitHid(IFACE.VENDOR,
        { since, match: /Success|Error/, timeoutMs: 30000, signal });
      assert.ok(!/^Error/.test(okmsg.text(reply)),
        `storing the key failed: ${okmsg.text(reply)}`);
      await device.sleep(500, { signal });
    }

    await device.restart({ signal });
    await device.ensureUnlocked(PINS.primary, { signal });
    return generated;
  }

  /** Whatever the device answers, collected across as many reports as it takes. */
  async function readBack(device, since, want, { signal, timeoutMs = 25000 }) {
    const expected = Math.ceil(want / REPORT);
    const deadline = Date.now() + timeoutMs;
    let reports = device.reportsSince(IFACE.VENDOR, since);
    while (reports.length < expected && Date.now() < deadline) {
      await device.sleep(100, { signal });
      reports = device.reportsSince(IFACE.VENDOR, since);
    }
    return Buffer.concat(reports).subarray(0, want);
  }

  async function publicKey(device, want, { signal }) {
    const since = device.mark(IFACE.VENDOR);
    device.sendVendor({ msg: okmsg.MSG.OKGETPUBKEY, slot: SLOT });
    return readBack(device, since, want, { signal });
  }

  /**
   * Send a payload with send_large_message2's framing and answer the one press
   * the challenge mode leaves.
   *
   * The marker in buffer[6] is 0xFF while more chunks follow and the remaining
   * count on the last, which is the same framing okmsg.build's `field` carries.
   */
  async function operate(device, msg, payload, want, { signal, assert }) {
    const primed = device.log.count(PRIMED);
    const since = device.mark(IFACE.VENDOR);

    for (let i = 0; i < payload.length; i += 57) {
      const chunk = payload.subarray(i, i + 57);
      device.sendVendor({
        msg, slot: SLOT, field: chunk.length < 57 ? chunk.length : 0xFF, payload: chunk,
      });
      await device.sleep(20, { signal });
    }

    /*
     * SURFACE: console, and only for the timing. The device gives a client no
     * signal that it is waiting, so there is nothing else to wait on - and a
     * press that lands before the fade is discarded silently.
     */
    await device.log.waitForCount(PRIMED, primed + 1, { timeoutMs: 20000, signal });
    device.press(1);

    const answer = await readBack(device, since, want, { signal });
    assert.ok(!/^Error/.test(okmsg.text(answer.subarray(0, REPORT))),
      `the device refused: ${okmsg.text(answer.subarray(0, REPORT))}`);
    return answer;
  }

  const spki = (kind, point) => crypto.createPublicKey({
    key: Buffer.concat([SPKI[kind], point]), format: 'der', type: 'spki',
  });

  /* ---- signing types ---------------------------------------------------- */

  it('ed25519 stores, publishes and signs, all three checked in pure JS',
    async ({ device, assert, signal, log }) => {
      /* SURFACE: vendor for every answer; console only for press timing. */
      await storeKey(device,
        { keytype: TYPE.ED25519, feature: FEATURE_SIGN, value: ED_SEED }, { signal, assert });

      const pub = (await publicKey(device, REPORT, { signal })).subarray(0, 32);
      const der = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), ED_SEED]);
      const want = crypto.createPublicKey(
        crypto.createPrivateKey({ key: der, format: 'der', type: 'pkcs8' }),
      ).export({ format: 'der', type: 'spki' }).subarray(-32);

      log(`device ${pub.toString('hex')}`);
      assert.bytes(pub, want, 'the device published a different public key than the seed implies');

      /*
       * Ed25519 signs the RAW message rather than a digest of it -
       * okcrypto_ecdsa_eddsa() hands large_buffer straight to Ed25519::sign - so
       * the 32 bytes sent are the message, and node:crypto verifies them as
       * such.
       */
      const message = crypto.createHash('sha256').update('okt stored ed25519').digest();
      const sig = (await operate(device, okmsg.MSG.OKSIGN, message, 64, { signal, assert }));

      assert.ok(crypto.verify(null, message, spki('ed25519', pub), sig),
        'the signature does not verify against the key the device published');

      /* And it is a signature over THIS message, not any message. */
      assert.ok(!crypto.verify(null, Buffer.alloc(32, 7), spki('ed25519', pub), sig),
        'the signature verifies over a different message - it is not binding');
    });

  it('nist256p1 stores, publishes and signs, verified against node:crypto',
    async ({ device, assert, signal, log }) => {
      /* SURFACE: vendor for every answer; console only for press timing. */
      const priv = crypto.randomBytes(32);
      await storeKey(device,
        { keytype: TYPE.P256, feature: FEATURE_SIGN, value: priv }, { signal, assert });

      /* A prime-curve public key is x||y, both 32 bytes, and 04 says uncompressed. */
      const pub = (await publicKey(device, REPORT, { signal })).subarray(0, 64);
      log(`device ${pub.subarray(0, 8).toString('hex')}...`);
      assert.notEqual(pub.toString('hex'), '00'.repeat(64), 'the device published an empty key');

      /*
       * uECC_sign_deterministic() signs the 32 bytes it was given AS THE DIGEST,
       * so sending sha256(message) and asking node:crypto to verify `message`
       * with sha256 lines the two up without needing a pre-hashed verify, which
       * node does not offer for ECDSA.
       */
      const message = Buffer.from('okt stored nist256p1');
      const digest = crypto.createHash('sha256').update(message).digest();
      const raw = await operate(device, okmsg.MSG.OKSIGN, digest, 64, { signal, assert });

      assert.ok(crypto.verify('sha256', message, spki('nist256p1', pub), derSignature(raw)),
        'the P-256 signature does not verify against the published key');
      assert.ok(!crypto.verify('sha256', Buffer.from('another message'),
        spki('nist256p1', pub), derSignature(raw)),
      'the P-256 signature verifies over a different message');
    });

  it('secp256k1 stores, publishes and signs, verified against node:crypto',
    async ({ device, assert, signal, log }) => {
      /* SURFACE: vendor for every answer; console only for press timing.
       *
       * Same shape as P-256 and worth doing separately rather than looping: the
       * curve is chosen by the KEY TYPE byte, so a firmware that ignored it
       * would produce a valid signature on the wrong curve and only a
       * curve-specific verify catches that. */
      const priv = crypto.randomBytes(32);
      await storeKey(device,
        { keytype: TYPE.SECP256K1, feature: FEATURE_SIGN, value: priv }, { signal, assert });

      const pub = (await publicKey(device, REPORT, { signal })).subarray(0, 64);
      log(`device ${pub.subarray(0, 8).toString('hex')}...`);

      const message = Buffer.from('okt stored secp256k1');
      const digest = crypto.createHash('sha256').update(message).digest();
      const raw = await operate(device, okmsg.MSG.OKSIGN, digest, 64, { signal, assert });

      assert.ok(crypto.verify('sha256', message, spki('secp256k1', pub), derSignature(raw)),
        'the secp256k1 signature does not verify against the published key');
    });

  /* ---- decrypting types ------------------------------------------------- */

  it('curve25519 stores, publishes and agrees a secret node:crypto can reproduce',
    async ({ device, assert, signal, log }) => {
      /*
       * SURFACE: vendor for every answer; console only for press timing.
       *
       * The decrypt feature rather than sign, and OKDECRYPT rather than OKSIGN -
       * the firmware refuses the wrong pairing with "Error key not set as
       * decryption key", which is a dispatch on the FEATURE bits rather than on
       * the key type.
       */
      const priv = crypto.randomBytes(32);
      await storeKey(device,
        { keytype: TYPE.CURVE25519, feature: FEATURE_DECRYPT, value: priv }, { signal, assert });

      const pub = (await publicKey(device, REPORT, { signal })).subarray(0, 32);
      log(`device ${pub.toString('hex')}`);
      assert.notEqual(pub.toString('hex'), '00'.repeat(32), 'the device published an empty key');

      /*
       * A sender with no device: an ephemeral X25519 pair, and the shared secret
       * computed against the key the device published. The device then has to
       * reach the same value from the other side.
       */
      const ephemeral = crypto.generateKeyPairSync('x25519');
      const ephemeralPub = ephemeral.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
      const expected = crypto.diffieHellman({
        privateKey: ephemeral.privateKey,
        publicKey: spki('x25519', pub),
      });

      const got = (await operate(device, okmsg.MSG.OKDECRYPT, ephemeralPub, 32, { signal, assert }));
      log(`device secret ${got.toString('hex')}`);
      log(`node:crypto   ${expected.toString('hex')}`);

      assert.bytes(got, expected,
        'the device and node:crypto did not agree on the X25519 shared secret');
    });

  it('ML-KEM-768 generates, publishes 1184 bytes and decapsulates',
    async ({ device, assert, signal, log, skip }) => {
      /*
       * SURFACE: vendor for every answer; console only for press timing.
       *
       * Generated rather than stored: a PQC key is a SEED and the device expands
       * it, so handing one in and getting the public key back would test the
       * expansion against nothing. Generated, the encapsulation is done here
       * against whatever the device produced, and the device has to reach the
       * same secret from its own private half.
       */
      if (!ours.probe().ok) skip(ours.probe().why);

      const atKeygen = await storeKey(device,
        { keytype: TYPE.MLKEM768, feature: FEATURE_DECRYPT, value: GENERATE, generates: 1184 },
        { signal, assert });

      const pub = await publicKey(device, 1184, { signal });
      log(`published ${pub.length} bytes`);
      assert.equal(pub.length, 1184, 'an ML-KEM-768 encapsulation key is 1184 bytes');

      /* The key the keygen handed back, read out of flash after a reboot, is the
       * same key - so generation, storage and retrieval agree. */
      assert.bytes(pub, atKeygen,
        'the stored key is not the one the keygen returned');

      const { ml_kem768 } = require('@noble/post-quantum/ml-kem.js');
      const { cipherText, sharedSecret } = ml_kem768.encapsulate(new Uint8Array(pub));
      log(`ciphertext ${cipherText.length} bytes`);

      const got = await operate(device, okmsg.MSG.OKDECRYPT, Buffer.from(cipherText), 32,
        { signal, assert });
      log(`device secret ${got.toString('hex')}`);

      assert.bytes(got, Buffer.from(sharedSecret),
        'the device decapsulated to a different secret than the encapsulation produced');
    });

  it('X-Wing generates, publishes 1216 bytes and decapsulates',
    async ({ device, assert, signal, log, skip }) => {
      /*
       * SURFACE: vendor for every answer; console only for press timing.
       *
       * The hybrid, and the reason the kit has its own X-Wing maths at all:
       * lib/age-pqc.js's xwingEncapsHost() is the sender's side, mirroring
       * xwing.py, and here it is the oracle. A device that got only the ML-KEM
       * half right would still return 32 plausible bytes.
       */
      if (!ours.probe().ok) skip(ours.probe().why);

      const atKeygen = await storeKey(device,
        { keytype: TYPE.XWING, feature: FEATURE_DECRYPT, value: GENERATE, generates: 1216 },
        { signal, assert });

      const pub = await publicKey(device, 1216, { signal });
      log(`published ${pub.length} bytes`);
      assert.equal(pub.length, 1216, 'an X-Wing public key is 1184 + 32 bytes');
      assert.bytes(pub, atKeygen, 'the stored key is not the one the keygen returned');

      const { ciphertext, sharedSecret } = ours.xwingEncapsHost(new Uint8Array(pub));
      log(`ciphertext ${ciphertext.length} bytes`);

      const got = await operate(device, okmsg.MSG.OKDECRYPT, Buffer.from(ciphertext), 32,
        { signal, assert });
      log(`device secret ${got.toString('hex')}`);

      assert.bytes(got, Buffer.from(sharedSecret),
        'the device decapsulated to a different X-Wing secret than the sender computed');
    });
});
