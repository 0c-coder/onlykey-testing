/*
 * TC-11, phase two: the WEB APP's composite calls, against a key the CLI put on
 * the device.
 *
 * 05-composite-load proved the key arrives intact, using python to sign. This
 * asks the same device the same question through `onlykey-3rd-party.js` -
 * `composite_sign` and `composite_decrypt`, the two calls the pgp-pqc page is
 * built on - so the browser's client is checked against the same key the
 * command line loaded.
 *
 * It sits in section 2 rather than section 3's headless tier for one reason:
 * loading the key needs `onlykey-cli setkey PQC1 p` (was setpqc), and therefore a kernel device
 * node. That is section 2's admission test, and it does not stop being true
 * because the client under test happens to be the browser's. The headless tier
 * stays CI-able precisely by keeping files like this out of it.
 *
 * Both operations raise the three-button challenge - okpqc_sign() and
 * okpqc_decrypt() each prime and then do nothing until CRYPTO_AUTH reaches 4 -
 * and the library primes and polls from inside a promise rather than from a
 * child process, which is what lib/pqc.js's confirmWhilst() is for.
 *
 * The decryption half is covered three times over, deliberately, because the
 * three are different questions and only the first used to be asked:
 *
 *   - the X25519 half alone, 32 bytes in, one keyhandle out;
 *   - the ML-KEM-768 half alone, 1088 bytes, which is the MULTI-CHUNK send;
 *   - and one openpgp.decrypt() driving both, which is the page's own call
 *     path and the only one that raises TWO challenges in one operation.
 *
 * The last is what a browser used to be the only way to reach, and reaching it
 * here first is the same argument the rest of the kit makes: a failure with a
 * console in front of it is a finding, and the same failure inside nw.js is a
 * mystery.
 */
'use strict';

const crypto = require('crypto');

const { describe, it } = require('../../lib/harness');
const { PINS } = require('../../lib/config');
const cli = require('../../lib/cli');
const pqc = require('../../lib/pqc');
const webenv = require('../../lib/webenv');

const SLOT_NAME = 'PQC1';  // python-onlykey 1.3.0 names composite slots PQC1-PQC4 only
const SLOT_ID = 1;
const HALF_ECC = 0;

describe('composite operations, through the web app\'s library', {
  state: 'initialized',
  requires: ['crypto', 'client-access', 'webapp-lib', 'xwing-math'],
  timeoutMs: 240000,
}, () => {
  let blob = null;
  let ed25519Pub = null;
  let x25519Sk = null;
  let third = null;
  let composite = null;
  let armored = null;

  /*
   * ONE openpgp instance for the whole file. loadPlain() compiles a fresh
   * module every call - there is no require cache behind it - and
   * setHardwareHooks() is module state, so hooks registered on the instance
   * returned by one webenv.openpgp() are invisible to the next. Held here
   * rather than fetched per test.
   */
  let openpgp = null;

  it('loads a composite key with the CLI', async ({ device, assert, signal, log }) => {
    composite = webenv.loadPlain('composite_pgp.js');
    openpgp = webenv.openpgp();
    const generated = await composite.generateCompositeKey(openpgp, {
      userId: { name: 'Kit', email: 'kit@example.com' },
    });
    blob = Buffer.from(generated.blob);
    armored = generated.armoredPublicKey;

    const { ed25519 } = require('@noble/curves/ed25519.js');
    const { x25519 } = require('@noble/curves/ed25519.js');
    ed25519Pub = Buffer.from(ed25519.getPublicKey(blob.subarray(0, 32)));
    x25519Sk = Buffer.from(blob.subarray(64, 96));
    log(`x25519 public ${Buffer.from(x25519.getPublicKey(x25519Sk)).toString('hex').slice(0, 16)}…`);

    await device.unlock(PINS.primary, { signal });
    await device.enterConfigMode(PINS.primary, { signal });

    const result = await cli.run('onlykey-cli',
      ['setkey', SLOT_NAME, 'p', blob.toString('hex')], { timeoutMs: 60000, signal });
    assert.equal(result.code, 0, `setkey p failed: ${result.stderr || result.stdout}`);

    /* Out of config mode: OKSIGN and OKDECRYPT are not on its allow-list. */
    await device.restart({ signal });
    await device.unlock(PINS.primary, { signal });

    const imports = webenv.create(device, { signal });
    const api = webenv.load(imports, 'onlykey-api.js');
    third = webenv.load(imports, 'onlykey-3rd-party.js', api)();

    assert.ok(typeof third.composite_sign === 'function', 'no composite_sign');
    assert.ok(typeof third.composite_decrypt === 'function', 'no composite_decrypt');

    /*
     * The handshake first, and it is not optional here even though it was for
     * the derive calls.
     *
     * derive_public_key builds its own OKCONNECT inline and needs nothing
     * beforehand. The composite operations do not: prime_composite() encrypts
     * every chunk with `onlykeyApi.sharedsec`, which only exists once connect()
     * has done the NaCl exchange. Without it the very first call dies inside
     * aesgcm_encrypt with "undefined is not iterable" - a message that names
     * neither the handshake nor the key.
     */
    await new Promise((resolve, reject) => {
      api.connect((err) => (err ? reject(new Error(String(err))) : resolve()));
    });
    assert.ok(api.sharedsec, 'the library has no transit key after connect()');
  });

  it('signs with the Ed25519 half, and the signature verifies',
    async ({ device, assert, signal, log }) => {
      /*
       * The web app's own call this time, not python's. Same device, same key,
       * same digest - so a disagreement between this and 05-composite-load
       * would say the two clients frame OKSIGN differently, which nothing else
       * would catch.
       */
      const digest = crypto.createHash('sha256').update('signed for the web app').digest();
      const primed = Buffer.concat([Buffer.from([HALF_ECC]), digest]);

      const sig = await pqc.confirmWhilst(device, pqc.challengeDigitsFor(primed),
        () => third.composite_sign(SLOT_ID, HALF_ECC, digest), { signal });

      const bytes = Buffer.from(sig);
      log(`library got ${bytes.length} bytes`);
      assert.equal(bytes.length, 64, 'an Ed25519 signature is 64 bytes');

      const { ed25519 } = require('@noble/curves/ed25519.js');
      assert.ok(ed25519.verify(bytes, digest, ed25519Pub),
        'the signature does not verify against the loaded key');
    });

  it('decrypts with the X25519 half', async ({ device, assert, signal, log }) => {
    /*
     * okpqc_decrypt() picks the half by SIZE - 32 bytes is an X25519 ephemeral
     * point, 1088 an ML-KEM ciphertext - so there is no selector byte and the
     * length is the whole instruction. The ECC half is used here for the same
     * reason as the signature: its answer can be checked in one line, since
     * X25519(sk_device, ephemeral_pub) must equal X25519(sk_ephemeral, pub_device).
     */
    const { x25519 } = require('@noble/curves/ed25519.js');

    const ephemeralSk = x25519.utils.randomSecretKey();
    const ephemeralPub = x25519.getPublicKey(ephemeralSk);
    const devicePub = x25519.getPublicKey(x25519Sk);
    const expected = Buffer.from(x25519.getSharedSecret(ephemeralSk, devicePub));

    /*
     * Answered by READING the challenge off the device's console rather than
     * predicting it, unlike the signature above. Both mechanisms are live on
     * purpose: predicting checks that this kit derives the same digits the
     * firmware does, and reading is what the browser pages need, since a page
     * assembles payloads nobody outside it can reconstruct. Keeping one of each
     * means neither goes stale.
     */
    const shared = await pqc.confirmFromConsole(device,
      () => third.composite_decrypt(SLOT_ID, ephemeralPub), { signal });

    const bytes = Buffer.from(shared);
    log(`shared secret ${bytes.toString('hex').slice(0, 16)}…`);

    assert.equal(bytes.length, 32, 'an X25519 shared secret is 32 bytes');
    assert.bytes(bytes, expected,
      'the device computed a different shared secret from the same two keys');
  });

  it('decrypts with the ML-KEM-768 half, whose 1088 bytes take five sends',
    async ({ device, assert, signal, log }) => {
      /*
       * The other half of the same firmware entry point, and the only payload
       * in the kit that does not fit one keyhandle: prime_composite() splits
       * 1088 bytes into five WebAuthn ceremonies and the device hashes what
       * arrived. A chunk lost on the way does not fail loudly - it leaves the
       * device deriving its challenge digits over bytes the host never sent, so
       * the symptom is a confirmation that never matches rather than any
       * transport error. Reading the digits off the console rather than
       * predicting them means this test measures the SEND: the digits come from
       * what the device received, so they only match when all five chunks did.
       *
       * The seed is used DIRECTLY as FIPS 203's (d||z) coins - 64 bytes, no
       * SHAKE expansion, because this is an IMPORTED key and okpqc.cpp says so
       * at the decapsulation site. That is the opposite of the DERIVED X-Wing
       * path in lib/age-pqc.js, which expands a 32-byte seed with SHAKE256.
       * Using the wrong one derives a different keypair, and the mismatch is
       * indistinguishable from a lost chunk.
       */
      const { ml_kem768 } = require('@noble/post-quantum/ml-kem.js');

      const { mlkemSeed } = composite.unpackBlob(blob);
      assert.equal(mlkemSeed.length, 64, 'the blob does not carry a 64-byte ML-KEM seed');

      const { publicKey } = ml_kem768.keygen(Uint8Array.from(mlkemSeed));
      const { cipherText, sharedSecret } = ml_kem768.encapsulate(publicKey);
      assert.equal(cipherText.length, composite.MLKEM_CT_LEN,
        'not an ML-KEM-768 ciphertext');

      const shared = await pqc.confirmFromConsole(device,
        () => third.composite_decrypt(SLOT_ID, cipherText), { signal });

      const bytes = Buffer.from(shared);
      log(`ml-kem shared secret ${bytes.toString('hex').slice(0, 16)}…`);

      assert.equal(bytes.length, 32, 'an ML-KEM shared secret is 32 bytes');
      assert.bytes(bytes, Buffer.from(sharedSecret),
        'the device decapsulated to a different secret - either the 1088 bytes did not '
        + 'arrive intact, or it derives a different keypair from the stored seed');
    });

  it('decrypts a real PGP message, which asks the device twice',
    async ({ device, assert, signal, log }) => {
      /*
       * The pgp-pqc page's own call path, with no page in it.
       *
       * openpgp.decrypt() runs the two halves SEQUENTIALLY - decaps$1 takes the
       * 32-byte X25519 ephemeral point, then decaps takes the 1088-byte ML-KEM
       * ciphertext - so one decryption raises TWO challenges. Answering only the
       * first leaves the second outstanding and the library reports an abandoned
       * operation, which names neither the half that stalled nor the reason.
       * confirmFromConsole() answers every challenge the work raises, which is
       * why it is the helper here and not confirmWhilst().
       *
       * The hooks only fire because createHardwarePrivateKey() marks BOTH
       * placeholder secrets - the fork gates each hook on
       * `secret.isHardwareBacked`, so an unmarked half silently decapsulates
       * host-side with a stub key and the failure surfaces as a bad session key
       * several layers up.
       */
      const message = 'composite, through the library';

      const pub = await openpgp.readKey({ armoredKey: armored });
      composite.registerCompositeHooks(openpgp, third, SLOT_ID);
      const hwKey = openpgp.createHardwarePrivateKey(pub);

      /* Encryption is host-only - it needs the recipient's public key and
       * nothing else, which is why this half asks for no button. */
      const ciphertext = await openpgp.encrypt({
        message: await openpgp.createMessage({ text: message }),
        encryptionKeys: pub,
        format: 'armored',
      });
      assert.ok(ciphertext.startsWith('-----BEGIN PGP MESSAGE-----'),
        `not an armored PGP message: ${String(ciphertext).slice(0, 60)}`);

      const result = await pqc.confirmFromConsole(device, async () => openpgp.decrypt({
        message: await openpgp.readMessage({ armoredMessage: ciphertext }),
        decryptionKeys: hwKey,
        format: 'utf8',
      }), { signal });

      log(`the fork recovered ${JSON.stringify(String(result.data).slice(0, 40))}`);
      assert.equal(result.data, message,
        'the composite decryption did not recover the plaintext');
    });

  it('signs a real PGP message with both halves, and its own key verifies it',
    async ({ device, assert, signal, log }) => {
      /*
       * TC-11's own acceptance criterion, in the maintainer's words: "ML-DSA-65
       * signature verifies against the composite public key."
       *
       * That is the one output worth having. A shared secret can only be
       * checked by recomputing it here, which proves the device agrees with
       * this kit's maths; a signature is checked against the PUBLISHED public
       * key, which is what a correspondent does and needs no trust in either
       * side's arithmetic.
       *
       * It is also the opposite firmware path from everything above. Decryption
       * is a large REQUEST - 1088 bytes in, 32 out. Signing is a large
       * RESPONSE: a 32-byte digest in, an Ed25519 signature and then a
       * 3309-byte ML-DSA-65 one back. That retrieval is where the alpha kit's
       * hardest bug lived - store_FIDO_response() dropped anything that did not
       * fit and the device then reported "Error incorrect challenge was
       * entered" about a challenge that had been entered correctly, which is a
       * failure that points at the wrong half of the system entirely.
       *
       * Two challenges again, and for a different reason than decryption's:
       * hooks.signer fires ONCE and drives both halves sequentially itself,
       * because the device holds one CRYPTO_AUTH and one packet buffer and
       * cannot have two operations outstanding.
       */
      const message = 'signed by the device, through the library';

      const pub = await openpgp.readKey({ armoredKey: armored });
      composite.registerCompositeHooks(openpgp, third, SLOT_ID);
      const hwKey = openpgp.createHardwarePrivateKey(pub);

      const signed = await pqc.confirmFromConsole(device, async () => openpgp.sign({
        message: await openpgp.createCleartextMessage({ text: message }),
        signingKeys: hwKey,
        format: 'armored',
      }), { signal });

      assert.ok(String(signed).startsWith('-----BEGIN PGP SIGNED MESSAGE-----'),
        `not an armored signed message: ${String(signed).slice(0, 60)}`);
      log(`signed message is ${String(signed).length} chars`);

      /*
       * Verification is host-only and uses the PUBLIC key - no device, no
       * hooks, nothing this test could have influenced. `verified` is a promise
       * that REJECTS on a bad signature rather than resolving false, so it has
       * to be awaited to mean anything.
       */
      const result = await openpgp.verify({
        message: await openpgp.readCleartextMessage({ cleartextMessage: String(signed) }),
        verificationKeys: pub,
      });
      await result.signatures[0].verified;

      assert.equal(result.data, message, 'the signed message is not the one signed');
    });

  it('will not sign the same digest twice without a new confirmation',
    async ({ device, assert, signal }) => {
      /*
       * The confirmation is per-operation, not per-session. If CRYPTO_AUTH
       * stayed set, anything that reached the device afterwards could sign
       * silently - which is the whole property the three buttons exist to
       * provide, and it is invisible from a single successful signature.
       *
       * No presses are answered here: the call must NOT complete - which is
       * also why this test runs LAST. An unanswered challenge leaves the device
       * primed, and the next operation to arrive inherits it: okpqc_sign() and
       * okpqc_decrypt() both bail on `if (CRYPTO_AUTH != 4) return;` without
       * priming anything of their own, so the following test's presses would
       * answer THIS challenge and its own would never be raised. Measured -
       * that is exactly how the decrypt below failed when this test came first.
       */
      const digest = crypto.createHash('sha256').update('a second, unconfirmed signature').digest();

      const settled = await Promise.race([
        third.composite_sign(SLOT_ID, HALF_ECC, digest).then(() => 'signed', () => 'refused'),
        device.sleep(12000, { signal }).then(() => 'waiting'),
      ]);

      assert.notEqual(settled, 'signed',
        'the device signed a second digest with no confirmation - CRYPTO_AUTH is sticky');
    });
});
