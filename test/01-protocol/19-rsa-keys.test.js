/*
 * Classic RSA: OKSETPRIV, OKGETPUBKEY, OKSIGN, OKDECRYPT and OKWIPEPRIV against
 * a stored RSA-2048 key.
 *
 * RSA was the one key type of the six with no coverage at all.
 * `01-protocol/14-stored-keys` drives the other five - ed25519, nist256p1,
 * secp256k1, curve25519 and the two PQC types - and every one of those lives in
 * an ECC slot and goes through `okcrypto_ecdsa_eddsa()` or its decrypt twin.
 * `okcrypto_rsasign()` and `okcrypto_rsadecrypt()` had never had a byte sent at
 * them by any test in either kit. `13-large-response` writes RSA slot 1, but with
 * `KEYTYPE_PQC_PGP`, which `okcrypto_sign()` routes to `okpqc_sign()` before the
 * RSA branch is reached - so that file proves nothing about RSA either.
 *
 * SECTION 1 ON PURPOSE, same argument as 14-stored-keys: section 2 can never run
 * against a physical key and section 3's headless tier drives the emulator by
 * design, so section 1 is the hardware-capable surface and a test here is worth
 * double. Every message is built by the kit and put on the in-process bus.
 *
 * WHAT THE DEVICE ACTUALLY STORES, because it is not a private key in any format
 * a client library will hand you:
 *
 *   The slot holds P || Q and nothing else. `rsa_getpub()` (okcrypto.cpp:1216)
 *   multiplies the two halves to get N on every load, and `rsa_sign()` /
 *   `rsa_decrypt()` recompute D, DP, DQ and QP from them - with E HARDCODED to
 *   0x10001. So a key whose public exponent is not 65537 can be stored happily
 *   and will then sign with a D derived from an exponent it does not have.
 *   node:crypto's RSA keygen uses 65537, as does every other generator in
 *   practice, but nothing on the wire says so.
 *
 *   `type` is the modulus size in units of 128 bytes - 1, 2, 3, 4 for 1024,
 *   2048, 3072, 4096 - and it shares one byte with the feature flags: the low
 *   nibble is the size, bit 5 is decrypt, bit 6 is sign. python-onlykey's
 *   `setkey()` folds them the same way.
 *
 * TWO DIFFERENT CHUNK FRAMINGS IN ONE FILE, which is the trap here. They look
 * alike and byte 6 means something different in each:
 *
 *   The KEY going in (OKSETPRIV -> rsa_priv_flash, okcore.cpp:5480) carries the
 *   TYPE BYTE in buffer[6] on every one of the five reports, and the firmware
 *   copies a fixed 57 bytes from each regardless of how much the report really
 *   held. It counts its own way to 256 with a global offset. That is exactly
 *   what python-onlykey's `setkey()` sends - five slices of 114 hex characters
 *   for RSA-2048, nine for RSA-4096.
 *
 *   The OPERATION payload (OKSIGN / OKDECRYPT -> process_packets,
 *   okcore.cpp:7419) carries the CONTINUATION MARKER in buffer[6]: 0xFF while
 *   more follows, and the final chunk's own length on the last one. Send the
 *   type byte here and the packet is accumulated as if 0xFF meant 255 bytes;
 *   send 0xFF as a key type and the load is rejected as an invalid RSA type.
 *
 * THE SINGLE-PRESS CHALLENGE MODE COVERS RSA SLOTS TOO, which is not obvious and
 * is not written down anywhere else. `done_process_packets()` loads
 * `stored_key_challenge_mode` when the slot is `< 5` OR in 101..116 - and `< 5`
 * IS the RSA slot range. So the byte-1 trick 14-stored-keys established works
 * here unchanged, and for the same reason: the press handler's clause tests
 * `stored_key_challenge_mode == 1` exactly, so the character '1' (0x31) primes a
 * confirmation that no press can then answer.
 *
 * WHAT EACH ANSWER IS CHECKED AGAINST. Nothing here trusts the device twice:
 *
 *   the modulus     against OpenSSL's own N for the same key, and against
 *                   P * Q multiplied out here in BigInt
 *   the signature   verified by node:crypto against a public key built from the
 *                   modulus THE DEVICE PUBLISHED, not from the host's key object
 *   the plaintext   sealed by node:crypto to that same published modulus, so a
 *                   device that decrypted with the wrong key returns noise
 *
 * SURFACES - see PRODUCTION.md. The vendor interface carries every answer and
 * every refusal, so the whole file survives into a production walk bar the press
 * timing: the console is read for "Encrypted Buffer" only, because the device
 * gives a client no signal that it has finished priming a confirmation, and a
 * press that lands during the fade is discarded silently. Where a test asserts
 * that NO confirmation was primed, that count is console-only for the same
 * reason and is a secondary assertion - the vendor error text is the primary one.
 */
'use strict';

const crypto = require('crypto');

const { describe, it } = require('../../lib/harness');
const { IFACE, okmsg } = require('../../lib/device');
const { PINS } = require('../../lib/config');
const pqc = require('../../lib/pqc');
const { firmwareFixes } = require('../../lib/firmware-fixes');

const REPORT = 64;
const CHUNK = 57;                       // payload bytes per report, buffer[7..63]

/* The low nibble of the type byte is the modulus size in 128-byte units. */
const RSA_2048 = 2;
const MODULUS = RSA_2048 * 128;         // 256 bytes of N, and of P||Q
const FEATURE_DECRYPT = 32;             // is_bit_set(features, 5)
const FEATURE_SIGN = 64;                // is_bit_set(features, 6)

/*
 * The slots onlykey-pgp.js hardcodes. `slotid()` returns 2 for OKSIGN and 1 for
 * everything else, +100 only when the key is ECC - so the classic PGP pages
 * reach RSA slot 1 to decrypt and RSA slot 2 to sign, and 18-gui-encrypt-decrypt
 * needs exactly this pair. A fresh fixture image per file, so they are reused
 * freely between tests.
 */
const SLOT_DECRYPT = 1;
const SLOT_SIGN = 2;
const SLOT_EMPTY = 4;

const FIELD_STORED_CHALLENGE = 22;      // PGPCHALENGEMODE -> stored_key_challenge_mode

/* done_process_packets()'s last line before it waits for a finger. */
const PRIMED = /Encrypted Buffer/g;

describe('classic RSA keys in RSA slots', {
  state: 'initialized',
  requires: ['crypto'],
  timeoutMs: 600000,
}, () => {
  /**
   * An RSA-2048 keypair, as the two things the device and the host each need.
   *
   * `p` and `q` are exactly 128 bytes each for a 2048-bit key - OpenSSL sets the
   * top bit of both primes - so P||Q is 256 and needs no padding. `n` is
   * OpenSSL's own modulus, which is what makes it an oracle rather than an echo:
   * the device computes N itself, from P and Q, with mbedtls.
   */
  function keypair() {
    const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const jwk = privateKey.export({ format: 'jwk' });
    const p = Buffer.from(jwk.p, 'base64url');
    const q = Buffer.from(jwk.q, 'base64url');
    return { privateKey, jwk, p, q, pq: Buffer.concat([p, q]), n: Buffer.from(jwk.n, 'base64url') };
  }

  /** A verifier for a modulus the DEVICE published, with the E the firmware assumes. */
  const publicFromModulus = (n) => crypto.createPublicKey({
    key: { kty: 'RSA', n: n.toString('base64url'), e: 'AQAB' },
    format: 'jwk',
  });

  /**
   * Read `want` bytes off the vendor interface as consecutive reports.
   *
   * Reports are counted as well as bytes, for the reason 13-large-response
   * gives: a short byte count is a truncated response and a changed report count
   * is changed framing, and they are different news.
   */
  async function collect(device, since, want, { signal, timeoutMs = 30000 }) {
    const expected = Math.ceil(want / REPORT);
    const deadline = Date.now() + timeoutMs;

    let reports = device.reportsSince(IFACE.VENDOR, since);
    while (reports.length < expected && Date.now() < deadline) {
      await device.sleep(100, { signal });
      reports = device.reportsSince(IFACE.VENDOR, since);
    }
    return { reports, bytes: Buffer.concat(reports).subarray(0, want) };
  }

  /**
   * Put keys in RSA slots, and leave the device where they can be USED.
   *
   * One config-mode session for however many keys are asked for: OKSETPRIV needs
   * config mode, and every message that uses a key needs to be out of it -
   * OKSIGN and OKDECRYPT are not among the messages config mode admits and
   * OKGETPUBKEY is refused outright there, printing to the console with no
   * vendor reply at all.
   *
   * `readyForKeygen()` restarts first, which is also what guarantees the
   * firmware's `packet_buffer_offset` starts at zero. rsa_priv_flash() counts
   * its five reports with that global and nothing resets it on entry, so a
   * partial write left by anything earlier would land this key at an offset.
   */
  async function loadKeys(device, keys, { signal, assert }) {
    await pqc.readyForKeygen(device, { signal });

    let since = device.mark(IFACE.VENDOR);
    device.sendVendor({
      msg: okmsg.MSG.OKSETSLOT,
      slot: 1,
      field: FIELD_STORED_CHALLENGE,
      /* THE BYTE 1, not the character. See the header. */
      payload: Buffer.from([1]),
    });
    const modeAck = await device.waitHid(IFACE.VENDOR,
      { since, match: /Success|Error/, timeoutMs: 8000, signal });
    assert.ok(!/^Error/.test(okmsg.text(modeAck)),
      `setting the stored-key challenge mode failed: ${okmsg.text(modeAck)}`);

    for (const key of keys) {
      since = device.mark(IFACE.VENDOR);
      for (let i = 0; i < key.pq.length; i += CHUNK) {
        device.sendVendor({
          msg: okmsg.MSG.OKSETPRIV,
          slot: key.slot,
          /* The TYPE BYTE on every report, not a continuation marker. */
          field: key.typeByte,
          payload: key.pq.subarray(i, i + CHUNK),
        });
        await device.sleep(150, { signal });
      }

      /* No confirmation for an RSA load: rsa_priv_flash() never calls
       * process_packets(), unlike the PQC keygens. It answers when the fifth
       * report tips its offset past the key size. */
      const ack = await device.waitHid(IFACE.VENDOR,
        { since, match: /Successfully|Error/, timeoutMs: 20000, signal });
      const said = okmsg.text(ack).trim();
      assert.ok(!/^Error/.test(said), `storing the RSA key in slot ${key.slot} failed: ${said}`);
      assert.match(said, /Successfully set RSA Key/,
        `expected the RSA acknowledgement, got: ${said}`);
    }

    await device.restart({ signal });
    await device.ensureUnlocked(PINS.primary, { signal });
  }

  /**
   * OKGETPUBKEY on an RSA slot.
   *
   * buffer[6] MUST be zero: okcrypto_getpubkey() takes the RSA branch on
   * `buffer[5] < 5 && !buffer[6]`, and any other field value falls through to
   * the ECC branch, which for slot 1..4 reads an ECC slot that does not exist.
   */
  async function modulus(device, slot, { signal }) {
    const since = device.mark(IFACE.VENDOR);
    device.sendVendor({ msg: okmsg.MSG.OKGETPUBKEY, slot, field: 0 });
    return collect(device, since, MODULUS, { signal });
  }

  /**
   * Send an operation payload with process_packets()' framing, answer the one
   * press the challenge mode leaves, and read the answer.
   */
  async function operate(device, msg, slot, payload, want, { signal, assert }) {
    const primed = device.log.count(PRIMED);
    const since = device.mark(IFACE.VENDOR);

    for (let i = 0; i < payload.length; i += CHUNK) {
      const chunk = payload.subarray(i, i + CHUNK);
      device.sendVendor({
        msg, slot, field: chunk.length < CHUNK ? chunk.length : 0xFF, payload: chunk,
      });
      await device.sleep(20, { signal });
    }

    /* SURFACE: console, and only for the timing - a press before the fade ends
     * is discarded and the device tells a client nothing about the window. */
    await device.log.waitForCount(PRIMED, primed + 1, { timeoutMs: 20000, signal });
    device.press(1);

    const { reports, bytes } = await collect(device, since, want, { signal });
    assert.ok(!/^Error/.test(okmsg.text(bytes.subarray(0, REPORT))),
      `the device refused: ${okmsg.text(bytes.subarray(0, REPORT))}`);
    return { reports, bytes };
  }

  /** The device's reply to a message it will refuse before priming anything. */
  async function refusal(device, spec, { signal, timeoutMs = 15000 }) {
    const primed = device.log.count(PRIMED);
    const since = device.mark(IFACE.VENDOR);
    device.sendVendor(spec);
    const reply = await device.waitHid(IFACE.VENDOR, { since, match: /Error/, timeoutMs, signal });
    return { said: okmsg.text(reply).trim(), primedBefore: primed };
  }

  it('OKSETPRIV loads an RSA-2048 key as five chunks and OKGETPUBKEY publishes its modulus',
    async ({ device, assert, signal, log }) => {
      /* SURFACE: vendor throughout - no console at all in this test, since
       * nothing here waits for a confirmation. */
      const key = keypair();
      assert.equal(key.pq.length, MODULUS,
        'a 2048-bit key should give 128 bytes of P and 128 of Q');

      await loadKeys(device, [
        { slot: SLOT_DECRYPT, typeByte: RSA_2048 | FEATURE_DECRYPT, pq: key.pq },
      ], { signal, assert });

      const { reports, bytes } = await modulus(device, SLOT_DECRYPT, { signal });
      log(`${reports.length} reports, ${bytes.length} bytes`);

      assert.equal(reports.length, MODULUS / REPORT,
        `expected ${MODULUS / REPORT} reports for a 2048-bit modulus, got ${reports.length}`);
      assert.equal(bytes.length, MODULUS, `expected ${MODULUS} bytes of N`);

      /*
       * Two independent oracles for the same 256 bytes. OpenSSL's N says the
       * device multiplied the right two numbers; BigInt multiplying P by Q here
       * says the same thing without OpenSSL, which matters because P and Q are
       * the only material the device was given.
       */
      assert.bytes(bytes, key.n,
        'the modulus the device published is not the one OpenSSL computed for this key');

      const ours = (BigInt(`0x${key.p.toString('hex')}`) * BigInt(`0x${key.q.toString('hex')}`))
        .toString(16).padStart(MODULUS * 2, '0');
      assert.equal(bytes.toString('hex'), ours,
        'the published modulus is not P * Q');

      /* Read twice: the answer comes out of flash, not out of whatever was left
       * in the response buffer by the load. */
      const again = await modulus(device, SLOT_DECRYPT, { signal });
      assert.bytes(again.bytes, bytes, 'two reads of one RSA slot returned different moduli');
    });

  it('OKSIGN with a stored RSA key produces a PKCS#1 v1.5 signature node:crypto verifies',
    async ({ device, assert, signal, log }) => {
      /*
       * SURFACE: vendor for the signature and the modulus; console for the press
       * timing only.
       *
       * The digest length picks the hash: rsa_sign() switches on it and maps
       * 28/32/48/64 onto SHA-224/256/384/512, so 32 bytes here means the device
       * builds a SHA-256 DigestInfo. node:crypto hashes the message itself and
       * checks the padding, which is what makes this a real verification rather
       * than a comparison against something this file computed.
       */
      const key = keypair();
      await loadKeys(device, [
        { slot: SLOT_SIGN, typeByte: RSA_2048 | FEATURE_SIGN, pq: key.pq },
      ], { signal, assert });

      const published = (await modulus(device, SLOT_SIGN, { signal })).bytes;
      assert.bytes(published, key.n, 'the signing slot published the wrong modulus');
      const verifier = publicFromModulus(published);

      const message = Buffer.from('okt stored RSA-2048 signature');
      const digest = crypto.createHash('sha256').update(message).digest();

      const { reports, bytes: sig } = await operate(
        device, okmsg.MSG.OKSIGN, SLOT_SIGN, digest, MODULUS, { signal, assert },
      );
      log(`${reports.length} reports, ${sig.length} bytes of signature`);

      assert.equal(reports.length, MODULUS / REPORT,
        `a 2048-bit signature is ${MODULUS / REPORT} reports, got ${reports.length}`);
      assert.ok(crypto.verify('sha256', message, verifier, sig),
        'the signature does not verify against the modulus the device published');

      /* And it is a signature over THIS message, not any message. */
      assert.ok(!crypto.verify('sha256', Buffer.from('another message'), verifier, sig),
        'the signature verifies over a different message - it is not binding');
    });

  it('OKDECRYPT with a stored RSA key recovers a ciphertext sealed to the published modulus',
    async ({ device, assert, signal, log }) => {
      /*
       * SURFACE: vendor for the plaintext and the modulus; console for the press
       * timing only.
       *
       * The sender is node:crypto with PKCS#1 v1.5 - what rsa_decrypt() calls
       * mbedtls_rsa_rsaes_pkcs1_v15_decrypt for - and it seals to the modulus
       * the DEVICE published rather than to the host's own key object. A device
       * that stored P and Q in the wrong order, or decrypted with a D derived
       * from the wrong exponent, cannot recover this.
       *
       * The ciphertext is a full modulus - 256 bytes over five reports - and
       * okcrypto_rsadecrypt() refuses anything else, so this also exercises the
       * multi-report REQUEST path at the exact size the length check demands.
       */
      const key = keypair();
      await loadKeys(device, [
        { slot: SLOT_DECRYPT, typeByte: RSA_2048 | FEATURE_DECRYPT, pq: key.pq },
      ], { signal, assert });

      const published = (await modulus(device, SLOT_DECRYPT, { signal })).bytes;
      const secret = crypto.randomBytes(32);
      const sealed = crypto.publicEncrypt({
        key: publicFromModulus(published),
        padding: crypto.constants.RSA_PKCS1_PADDING,
      }, secret);
      assert.equal(sealed.length, MODULUS, 'a PKCS#1 v1.5 ciphertext is one modulus long');

      const { bytes } = await operate(
        device, okmsg.MSG.OKDECRYPT, SLOT_DECRYPT, sealed, 32, { signal, assert },
      );
      log(`device   ${bytes.toString('hex')}`);
      log(`expected ${secret.toString('hex')}`);

      assert.bytes(bytes, secret,
        'the device did not recover the plaintext that was sealed to its own modulus');
    });

  it('the RSA feature bits refuse OKSIGN on the decrypt slot and OKDECRYPT on the sign slot',
    async ({ device, assert, signal, log }) => {
      /*
       * SURFACE: vendor - both refusals arrive where a client can see them, so
       * this test survives into a production walk whole. The console is read
       * only to say that nothing was primed, which is a secondary assertion.
       *
       * This is the pairing 18-gui-encrypt-decrypt depends on. onlykey-pgp.js's
       * slotid() sends OKDECRYPT to RSA slot 1 and OKSIGN to RSA slot 2, and
       * nothing in the message says which use is intended - the FEATURE BITS in
       * the stored type byte decide, and the wrong pairing is refused by name.
       * Both keys go in inside one config-mode session, which is also what a
       * client setting up those pages would do.
       *
       * Note where the check happens: okcrypto_sign() reads the slot, finds
       * bit 6 clear and answers immediately, WITHOUT priming a confirmation. So
       * a client that sends a sign request to the decrypt slot gets an error
       * rather than a device waiting for a finger nobody knows to offer.
       */
      const decryptKey = keypair();
      const signKey = keypair();
      await loadKeys(device, [
        { slot: SLOT_DECRYPT, typeByte: RSA_2048 | FEATURE_DECRYPT, pq: decryptKey.pq },
        { slot: SLOT_SIGN, typeByte: RSA_2048 | FEATURE_SIGN, pq: signKey.pq },
      ], { signal, assert });

      /* Both slots hold their own key, and they are different keys - so a
       * refusal below cannot be the device reading the wrong slot. */
      assert.bytes((await modulus(device, SLOT_DECRYPT, { signal })).bytes, decryptKey.n,
        'RSA slot 1 does not hold the key that was written to it');
      assert.bytes((await modulus(device, SLOT_SIGN, { signal })).bytes, signKey.n,
        'RSA slot 2 does not hold the key that was written to it');

      const digest = crypto.createHash('sha256').update('okt wrong feature').digest();
      const sign = await refusal(device, {
        msg: okmsg.MSG.OKSIGN, slot: SLOT_DECRYPT, field: digest.length, payload: digest,
      }, { signal });
      log(`OKSIGN on the decrypt slot: ${sign.said}`);
      assert.match(sign.said, /Error key not set as signature key/,
        `expected the signature-feature refusal, got: ${sign.said}`);
      assert.equal(device.log.count(PRIMED), sign.primedBefore,
        'the device primed a confirmation for a request it was going to refuse');

      const decrypt = await refusal(device, {
        msg: okmsg.MSG.OKDECRYPT, slot: SLOT_SIGN, field: 32, payload: crypto.randomBytes(32),
      }, { signal });
      log(`OKDECRYPT on the sign slot: ${decrypt.said}`);
      assert.match(decrypt.said, /Error key not set as decryption key/,
        `expected the decryption-feature refusal, got: ${decrypt.said}`);
      assert.equal(device.log.count(PRIMED), decrypt.primedBefore,
        'the device primed a confirmation for a request it was going to refuse');
    });

  it('OKSIGN refuses an RSA digest that is not 28, 32, 48 or 64 bytes',
    async ({ device, assert, signal, log }) => {
      /*
       * SURFACE: vendor for the refusal; console for the press timing.
       *
       * The size list is the hash list - rsa_sign() maps those four lengths onto
       * SHA-224/256/384/512 - so a 20-byte SHA-1 digest, which the switch has
       * commented out, is refused. python-onlykey carries a handler for this
       * exact string, so it is a refusal clients already expect to be able to
       * read.
       *
       * It is refused AFTER the confirmation, not before: okcrypto_rsasign()
       * primes on the first pass and only checks the length once CRYPTO_AUTH
       * reaches 4. So the press is spent on a request the device was always
       * going to refuse, which is worth knowing - a client cannot avoid asking
       * its user for a finger by validating nothing.
       */
      const key = keypair();
      await loadKeys(device, [
        { slot: SLOT_SIGN, typeByte: RSA_2048 | FEATURE_SIGN, pq: key.pq },
      ], { signal, assert });

      const short = crypto.createHash('sha1').update('okt short digest').digest();
      assert.equal(short.length, 20, 'a SHA-1 digest is 20 bytes');

      const primed = device.log.count(PRIMED);
      const since = device.mark(IFACE.VENDOR);
      device.sendVendor({
        msg: okmsg.MSG.OKSIGN, slot: SLOT_SIGN, field: short.length, payload: short,
      });

      await device.log.waitForCount(PRIMED, primed + 1, { timeoutMs: 20000, signal });
      device.press(1);

      const reply = await device.waitHid(IFACE.VENDOR,
        { since, match: /Error/, timeoutMs: 20000, signal });
      const said = okmsg.text(reply).trim();
      log(`20-byte digest: ${said}`);
      assert.match(said, /Error with RSA data to sign invalid size/,
        `expected the size refusal, got: ${said}`);
    });

  it('OKGETPUBKEY says no key set for an empty RSA slot and invalid slot for slot 0',
    async ({ device, assert, signal, log }) => {
      /*
       * SURFACE: vendor - both refusals are client-visible, so this test
       * survives a production walk whole, and no key is needed to run it.
       *
       * Slot 4 is empty on a fresh fixture: okcore_flashget_RSA() reads the type
       * out of EEPROM, finds zero and says so. Slot 0 never gets that far - the
       * range check rejects it. The two answers are different sentences, which
       * is what lets a client tell "you asked for nothing" from "you asked
       * wrongly", and the next test is about what happens when they get mixed up.
       */
      await device.ensureUnlocked(PINS.primary, { signal });

      const empty = await refusal(device,
        { msg: okmsg.MSG.OKGETPUBKEY, slot: SLOT_EMPTY, field: 0 }, { signal });
      log(`empty slot ${SLOT_EMPTY}: ${empty.said}`);
      assert.match(empty.said, /Error no RSA Private Key set in this slot/,
        `expected the empty-slot refusal, got: ${empty.said}`);

      const invalid = await refusal(device,
        { msg: okmsg.MSG.OKGETPUBKEY, slot: 0, field: 0 }, { signal });
      log(`slot 0: ${invalid.said}`);
      assert.match(invalid.said, /Error invalid RSA slot/,
        `expected the invalid-slot refusal, got: ${invalid.said}`);
    });

  it('OKWIPEPRIV clears an RSA slot - with RC fix 0013 its key type too, so it reads as empty',
    async ({ device, assert, signal, log }) => {
      /*
       * SURFACE: vendor throughout.
       *
       * TWO FIRMWARES, ONE TEST. RC fix 0013 (node-onlykey-emulator
       * scripts/versions/patches-3.1.0/0013-libraries-okcore-rsa-wipe-clears-type) clears
       * the key type on an RSA wipe; firmware without it (3.1.0 as the maintainer ships
       * it, until a pin carries the fix) keeps the type, which this test pinned below.
       * Which one is answering: an emulator says in .stage/build.json `fixes`; a hard
       * key cannot, so whoever flashed it says in OKT_FIRMWARE_FIXES (e.g. 0012,0013) -
       * unset is upstream as shipped. When a pin carries 0013, the second branch goes.
       *
       * WITHOUT THE FIX (pinned): rsa_priv_flash() handles `wipe`
       * first and returns before it ever reaches okeeprom_eeset_rsakey(), so the
       * flash region is zeroed and the slot's KEY TYPE stays in EEPROM. The ECC
       * path does not have this shape: ecc_priv_flash() writes the type byte
       * unconditionally on the way in, so a wipe there records type 0 and the
       * slot really does read as empty afterwards.
       *
       * What that means for a client is the assertion below. A wiped RSA slot
       * does not answer "Error no RSA Private Key set in this slot" the way the
       * empty slot in the previous test does. okcore_flashget_RSA() believes the
       * stale type, decrypts 256 zero bytes into P and Q, multiplies them, and
       * publishes the result - so the slot goes on reporting a 2048-bit key that
       * is not a key, and is certainly not the one that was wiped.
       *
       * WITH THE FIX: the wiped slot answers OKGETPUBKEY as a never-loaded one does,
       * "Error no RSA Private Key set in this slot".
       */
      const fixed = firmwareFixes(device).includes('0013');
      log(`firmware fixes: ${firmwareFixes(device).join(', ') || 'none'} - expecting the ${fixed ? 'fixed' : 'pinned'} wipe`);
      const key = keypair();
      await loadKeys(device, [
        { slot: SLOT_DECRYPT, typeByte: RSA_2048 | FEATURE_DECRYPT, pq: key.pq },
      ], { signal, assert });

      const before = (await modulus(device, SLOT_DECRYPT, { signal })).bytes;
      assert.bytes(before, key.n, 'the slot did not hold the key that was written to it');

      /* OKWIPEPRIV needs config mode, like the write it undoes. */
      await pqc.readyForKeygen(device, { signal });
      const since = device.mark(IFACE.VENDOR);
      device.sendVendor({ msg: okmsg.MSG.OKWIPEPRIV, slot: SLOT_DECRYPT, field: 0 });
      const ack = await device.waitHid(IFACE.VENDOR,
        { since, match: /Successfully|Error/, timeoutMs: 20000, signal });
      const said = okmsg.text(ack).trim();
      log(`wipe: ${said}`);
      assert.match(said, /Successfully wiped RSA Private Key/,
        `expected the wipe acknowledgement, got: ${said}`);

      await device.restart({ signal });
      await device.ensureUnlocked(PINS.primary, { signal });

      if (fixed) {
        const wiped = await refusal(device,
          { msg: okmsg.MSG.OKGETPUBKEY, slot: SLOT_DECRYPT, field: 0 }, { signal });
        log(`after the wipe: ${wiped.said}`);
        assert.match(wiped.said, /Error no RSA Private Key set in this slot/,
          `with fix 0013 a wiped RSA slot reads as empty; it answered: ${wiped.said}`);
        return;
      }

      const { reports, bytes: after } = await modulus(device, SLOT_DECRYPT, { signal });
      log(`after the wipe: ${reports.length} reports, first bytes ` +
        `${after.subarray(0, 8).toString('hex')}`);

      /* The key material is gone - that half of the wipe worked. */
      assert.notEqual(after.toString('hex'), before.toString('hex'),
        'the wiped slot still publishes the modulus it held before the wipe');

      /* And the type byte is not - which is the breakage. */
      assert.ok(!/^Error/.test(okmsg.text(after.subarray(0, REPORT))),
        'a wiped RSA slot now refuses OKGETPUBKEY, so the EEPROM key type is being ' +
        'cleared: rsa_priv_flash() has been fixed and this test has done its job');
      assert.equal(after.length, MODULUS,
        'a wiped RSA slot still answers with a full modulus - if this changed, so did the fix');
    });
});
