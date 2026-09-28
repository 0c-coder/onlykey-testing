/*
 * The command line's own composite PQC operations: `setkey PQCn p` (setpqc before
 * python-onlykey 1.3.0), `signpqc`,
 * `decryptpqc`.
 *
 * 05-composite-load and 06-composite-ops already prove the DEVICE does these
 * things - the first through a hand-written python snippet, the second through
 * the web app's library. Neither goes through `onlykey-cli`, and that turned
 * out to matter: until this file's fixes there was no CLI route to a composite
 * decrypt or signature at all, and the library functions that were supposed to
 * provide one could not return their own output.
 *
 * WHY THE SNIPPET IN 05 EXISTS is the whole story here. It says, in its own
 * comment, that it cannot call `pqc.sign()` because `read_string()` "DROPS
 * EVERY ZERO BYTE". That was true and it was only half the problem: underneath
 * it, `read_bytes()` is a single `self._hid.read(n)` of ONE 64-byte report with
 * no reassembly, so `read_string(...)[:3309]` for an ML-DSA-65 signature was
 * impossible by construction rather than unreliable. 64 bytes is the most it
 * could ever have returned. The ML-DSA test below is therefore the one that
 * could not have passed in any form before, and it is the reason to read this
 * file: it is the first time a 3309-byte response has been reassembled by
 * python-onlykey itself rather than by a test harness working around it.
 *
 * The first test is a different kind of pin. `setpqc` used to print "Loaded
 * composite PQC PGP key (160 bytes) into RSA1" and exit 0 for a load the device
 * had refused three times over, and nothing could catch that from outside:
 * okcrypto_getpubkey() has no KEYTYPE_PQC_PGP branch, so there is no readback,
 * and the only other evidence needs a button press. A test that asserts the
 * REFUSAL is the only instrument that works, and it has to run before the key
 * is loaded or the device would be in config mode already.
 *
 * python-onlykey 1.3.0 deleted setpqc; `setkey PQCn p` replaces it and carries
 * the same pin. Its first version printed only the exception class and exited
 * 0 on a refusal (fixed in python-onlykey f4a6031), so the exit-code half of
 * this test still earns its keep.
 *
 * SURFACE: vendor for every device operation; console only for the challenge
 * digits on the ML-KEM half, which no client surface reports. See PRODUCTION.md.
 */
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { describe, it } = require('../../lib/harness');
const { PINS } = require('../../lib/config');
const cli = require('../../lib/cli');
const pqc = require('../../lib/pqc');
const webenv = require('../../lib/webenv');

const SLOT_NAME = 'PQC3';  // python-onlykey 1.3.0 names composite slots PQC1-PQC4 only
const SLOT_ID = 3;
const HALF_ECC = 0;

/*
 * RSA3, and the slot choice is load-bearing. 05-composite-load and
 * 06-composite-ops both keep a composite key in RSA1 and 02-cli/12 uses RSA4;
 * a spec that overwrites a fixture another spec depends on produces failures
 * that read exactly like a firmware regression, which has now happened twice in
 * this project's history (TEST-PLAN's RSA1 and RSA4 collisions). A fixture
 * another spec depends on needs a slot of its own.
 */

describe('onlykey-cli composite PQC operations', {
  state: 'initialized',
  requires: ['crypto', 'client-access', 'webapp-lib', 'xwing-math'],
  timeoutMs: 300000,
}, () => {
  let blob = null;
  let ed25519Pub = null;
  let mldsaPub = null;
  let x25519Sk = null;
  let mlkemSeed = null;
  let dir = null;

  const at = (name) => path.join(dir, name);

  it('generates the key the rest of the file uses', async ({ assert, log }) => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'okt-cliops-'));

    const composite = webenv.loadPlain('composite_pgp.js');
    const generated = await composite.generateCompositeKey(webenv.openpgp(), {
      userId: { name: 'Kit', email: 'kit@example.com' },
    });
    blob = Buffer.from(generated.blob);
    assert.equal(blob.length, 160, 'the blob is not 160 bytes');

    /*
     * Every public half is derived HERE, from the bytes about to be sent, and
     * never read back from the device. That is what makes each assertion below
     * a statement about the device rather than a round trip through it.
     */
    const { ed25519, x25519 } = require('@noble/curves/ed25519.js');
    const { ml_dsa65 } = require('@noble/post-quantum/ml-dsa.js');

    const parts = composite.unpackBlob(blob);
    ed25519Pub = Buffer.from(ed25519.getPublicKey(blob.subarray(0, 32)));
    x25519Sk = Buffer.from(parts.x25519Sk);
    mlkemSeed = Buffer.from(parts.mlkemSeed);
    mldsaPub = Buffer.from(ml_dsa65.keygen(Uint8Array.from(parts.mldsaSeed)).publicKey);

    void x25519;
    log(`blob ready, ml-dsa public ${mldsaPub.toString('hex').slice(0, 16)}…`);
  });

  it('setkey p refuses a load outside config mode, and says so in its exit code',
    async ({ device, assert, signal, log }) => {
      /*
       * Runs FIRST, before anything enters config mode, because that is the
       * only state in which the bug is reachable.
       *
       * The device answers each of the three chunks with "Error not in config
       * mode" (okcore.cpp's OKSETPRIV case). The CLI never read those replies,
       * so it reported a successful load of a key that was never stored - and
       * a caller had no second way to check, since a composite slot cannot be
       * read back. Both halves of the fix are asserted: the exit code, and the
       * absence of the success sentence.
       */
      await device.unlock(PINS.primary, { signal });

      const result = await cli.run('onlykey-cli',
        ['setkey', SLOT_NAME, 'p', blob.toString('hex')], { timeoutMs: 60000, signal });

      const out = `${result.stdout}${result.stderr}`;
      log(`exit ${result.code}: ${(result.stdout || '').trim().split('\n').join(' | ')}`);

      /*
       * The control, and this test needs one: "no success message" is also
       * what a CLI that never reached the device at all would produce, and
       * that would make the absence below pass for entirely the wrong reason.
       * The device's own refusal, quoted back through the CLI, is what proves
       * the channel worked and the answer is a real NO rather than silence.
       */
      assert.control('the CLI reached the device and relayed its refusal',
        /not in config mode/.test(out));

      assert.notEqual(result.code, 0,
        'setkey p exited 0 for a load the device refused');
      assert.absent(!/Loaded composite/.test(out),
        'setkey p claimed to have loaded a key the device refused');
    });

  it('setkey p loads the key in config mode', async ({ device, assert, signal }) => {
    await device.restart({ signal });
    await device.unlock(PINS.primary, { signal });
    await device.enterConfigMode(PINS.primary, { signal });

    const result = await cli.run('onlykey-cli',
      ['setkey', SLOT_NAME, 'p', blob.toString('hex')], { timeoutMs: 60000, signal });

    assert.equal(result.code, 0, `setkey p failed: ${result.stderr || result.stdout}`);
    assert.includes(`${result.stdout}${result.stderr}`, 'Loaded composite',
      `setkey p did not report a load: ${result.stdout}`);

    /* OKSIGN and OKDECRYPT are not on config mode's allow-list. */
    await device.restart({ signal });
    await device.unlock(PINS.primary, { signal });
  });

  it('signpqc ecc returns a 64-byte Ed25519 signature that verifies',
    async ({ device, assert, signal, log }) => {
      const digest = crypto.createHash('sha256').update('signpqc, ecc half').digest();

      /*
       * Digits PREDICTED here and READ from the console for the ML-KEM half
       * below. Both mechanisms stay live on purpose: predicting checks that
       * this kit derives the same digits the firmware does, reading is what
       * a payload the kit did not choose requires. Keeping one of each means
       * neither goes stale. The primed payload is [selector] + digest.
       */
      const primed = Buffer.concat([Buffer.from([HALF_ECC]), digest]);

      const result = await pqc.runWithConfirm(device, 'onlykey-cli',
        ['signpqc', SLOT_NAME, 'ecc', digest.toString('hex')],
        { digits: pqc.challengeDigitsFor(primed), timeoutMs: 90000, signal });

      assert.equal(result.code, 0, `signpqc failed: ${result.stderr || result.stdout}`);

      const hex = (result.stdout.trim().split('\n').pop() || '').trim();
      assert.match(hex, /^[0-9a-f]{128}$/, `not a 64-byte signature: ${hex.slice(0, 80)}`);
      log(`signpqc ecc -> ${hex.slice(0, 16)}…`);

      const { ed25519 } = require('@noble/curves/ed25519.js');
      assert.ok(ed25519.verify(Buffer.from(hex, 'hex'), digest, ed25519Pub),
        'the signature does not verify against the key that was loaded');
    });

  it('signpqc pqc returns a 3309-byte ML-DSA-65 signature that verifies',
    async ({ device, assert, signal, log }) => {
      /*
       * The one that could not have passed before, at any reliability.
       *
       * A 3309-byte response is 52 consecutive 64-byte reports out of
       * send_transport_response(); read_bytes() returns ONE of them. So this
       * asserts python-onlykey's reassembly as much as it asserts the device's
       * signing, and a truncation shows up as a signature that does not verify
       * rather than as a short read - which is why the length is checked
       * separately from the verification.
       *
       * Verified against an ML-DSA-65 public key derived independently, in this
       * process, from the seed at blob offset 32 - not against anything the
       * device said about itself.
       */
      const digest = crypto.createHash('sha256').update('signpqc, ml-dsa half').digest();
      const primed = Buffer.concat([Buffer.from([1]), digest]);

      const result = await pqc.runWithConfirm(device, 'onlykey-cli',
        ['signpqc', SLOT_NAME, 'pqc', digest.toString('hex')],
        { digits: pqc.challengeDigitsFor(primed), timeoutMs: 120000, signal });

      assert.equal(result.code, 0, `signpqc failed: ${result.stderr || result.stdout}`);

      const hex = (result.stdout.trim().split('\n').pop() || '').trim();
      assert.equal(hex.length, 3309 * 2,
        `an ML-DSA-65 signature is 3309 bytes, got ${hex.length / 2}`);
      log(`signpqc pqc -> ${hex.length / 2} bytes, ${hex.slice(0, 16)}…`);

      const { ml_dsa65 } = require('@noble/post-quantum/ml-dsa.js');
      assert.ok(ml_dsa65.verify(Buffer.from(hex, 'hex'), digest, mldsaPub),
        'the ML-DSA-65 signature does not verify against the seed that was loaded');
    });

  it('decryptpqc recovers the X25519 shared secret',
    async ({ device, assert, signal, log }) => {
      const { x25519 } = require('@noble/curves/ed25519.js');

      const ephemeralSk = x25519.utils.randomSecretKey();
      const ephemeralPub = Buffer.from(x25519.getPublicKey(ephemeralSk));
      const expected = Buffer.from(
        x25519.getSharedSecret(ephemeralSk, x25519.getPublicKey(x25519Sk)));

      const result = await pqc.runWithConfirm(device, 'onlykey-cli',
        ['decryptpqc', SLOT_NAME, ephemeralPub.toString('hex')],
        { digits: pqc.challengeDigitsFor(ephemeralPub), timeoutMs: 90000, signal });

      assert.equal(result.code, 0, `decryptpqc failed: ${result.stderr || result.stdout}`);

      const hex = (result.stdout.trim().split('\n').pop() || '').trim();
      assert.match(hex, /^[0-9a-f]{64}$/, `not a 32-byte shared secret: ${hex.slice(0, 80)}`);
      log(`decryptpqc x25519 -> ${hex.slice(0, 16)}…`);

      assert.bytes(Buffer.from(hex, 'hex'), expected,
        'the device computed a different shared secret from the same two keys');
    });

  it('decryptpqc recovers the ML-KEM-768 shared secret from a 1088-byte ciphertext',
    async ({ device, assert, signal, log }) => {
      /*
       * Passed as a FILE, not as an argument: 1088 bytes is 2176 hex
       * characters, which is past what several shells will accept in one
       * argument, and a command a user cannot actually type is not a feature.
       * That is the reason `_pqc_input_bytes()` takes a path at all.
       *
       * The seed is used DIRECTLY as FIPS 203's (d||z) coins - 64 bytes, no
       * SHAKE expansion - because this is an IMPORTED key. The derived X-Wing
       * path does the opposite; using the wrong one derives a different
       * keypair, and that is indistinguishable from a lost chunk.
       *
       * Digits READ from the console here rather than predicted: the send is
       * five packets, and reading the digits off what the device says it
       * hashed means they only match when every packet arrived. That makes
       * this test measure the SEND as well as the decapsulation.
       */
      const { ml_kem768 } = require('@noble/post-quantum/ml-kem.js');

      const { publicKey } = ml_kem768.keygen(Uint8Array.from(mlkemSeed));
      const { cipherText, sharedSecret } = ml_kem768.encapsulate(publicKey);
      assert.equal(cipherText.length, 1088, 'not an ML-KEM-768 ciphertext');

      const ctFile = at('mlkem-ct.hex');
      fs.writeFileSync(ctFile, Buffer.from(cipherText).toString('hex'));

      const result = await pqc.confirmFromConsole(device,
        () => cli.run('onlykey-cli', ['decryptpqc', SLOT_NAME, ctFile],
          { timeoutMs: 120000, signal }), { signal });

      assert.equal(result.code, 0, `decryptpqc failed: ${result.stderr || result.stdout}`);

      const hex = (result.stdout.trim().split('\n').pop() || '').trim();
      assert.match(hex, /^[0-9a-f]{64}$/, `not a 32-byte shared secret: ${hex.slice(0, 80)}`);
      log(`decryptpqc ml-kem -> ${hex.slice(0, 16)}…`);

      assert.bytes(Buffer.from(hex, 'hex'), Buffer.from(sharedSecret),
        'the device decapsulated to a different secret - either the 1088 bytes did not '
        + 'arrive intact, or it derives a different keypair from the stored seed');
    });

  it('cleans up after itself', async ({ assert }) => {
    fs.rmSync(dir, { recursive: true, force: true });
    assert.ok(!fs.existsSync(dir), 'the temp directory is still there');
  });
});
