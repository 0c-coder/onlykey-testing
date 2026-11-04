/*
 * Composite operations over the WebAuthn tunnel, through node-onlykey-lib -
 * the path the web app is moving onto (plan Path W).
 *
 * 06-composite-ops asks the same device the same questions through the web
 * app's BUILT-IN library, and fails: that library still seals its chunks with
 * the legacy transit (AES-GCM, tagLength 0, a fixed IV), which v3.1.0's
 * transit v2 correctly refuses - and because the device stages an error only
 * when nothing else is staged, what comes back is the stale OKCONNECT reply,
 * not a refusal (audit #1, 2026-09-28). This file asks through the library
 * that replaces it, composed exactly as a browser will compose it:
 *
 *   [host, tunnelTransport, session, device, okcrypto]
 *   okcrypto.ctap = createWebAuthnCtap({ credentials: navigator.credentials })
 *
 * The only thing standing in for the browser is `navigator.credentials`,
 * which lib/webenv already provides: it turns credentials.get() into the
 * CTAP2 GetAssertion this kit speaks to the emulated key. Nothing here uses
 * the vendor interface - the tunnel placeholder refuses it by name.
 *
 * The key is loaded by the CLI, as 05/06 do, so all three clients (python,
 * the web app's old library, this library) are asked about one key.
 */
'use strict';

const crypto = require('crypto');

const { describe, it } = require('../../lib/harness');
const { PINS } = require('../../lib/config');
const cli = require('../../lib/cli');
const pqc = require('../../lib/pqc');
const webenv = require('../../lib/webenv');

const SLOT_NAME = 'PQC1';
const SLOT_ID = 1;
const HALF_ECC = 0;

/**
 * The library's confirm(): it hands over the digits it computed from the
 * payload it sent; the emulated key is pressed once it has primed the
 * challenge. The prime count is taken BEFORE the operation starts, because the
 * device primes on the final chunk - possibly before confirm() is even called -
 * and waitForCount() resolves at once for a count already reached.
 */
function presser(device, signal) {
  let before = device.log.count(pqc.PRIMED);
  const arm = () => { before = device.log.count(pqc.PRIMED); };
  const confirm = async ({ digits }) => {
    await device.log.waitForCount(pqc.PRIMED, before + 1, {
      timeoutMs: 60000, signal, pending: device.pending,
    });
    device.pressLine(digits);
  };
  return { arm, confirm };
}

/** Compose the library the way a browser page will. */
function composeBrowserStack(device, signal) {
  const Rectify = require('@bmatusiak/rectify');
  const plugins = [
    require('node-onlykey-lib/plugins/host'),
    require('node-onlykey-lib/plugins/transport/tunnel'),
    require('node-onlykey-lib/plugins/session'),
    require('node-onlykey-lib/plugins/device'),
    require('node-onlykey-lib/plugins/okcrypto'),
  ];
  const { createWebAuthnCtap } = require('node-onlykey-lib/transport/webauthn');
  const { window } = webenv.create(device, { signal });
  plugins.config = {
    okcrypto: { ctap: createWebAuthnCtap({ credentials: window.navigator.credentials }) },
  };
  return new Promise((resolve, reject) => {
    const app = Rectify.build(plugins, (err, started) => (err ? reject(err) : resolve(started)));
    app.start();
  });
}

describe('composite operations over the WebAuthn tunnel, through node-onlykey-lib', {
  state: 'initialized',
  requires: ['crypto', 'client-access', 'xwing-math'],
  timeoutMs: 300000,
}, () => {
  let blob = null;
  let ed25519Pub = null;
  let x25519Sk = null;
  let app = null;
  let okcrypto = null;

  it('loads a composite key with the CLI, and composes the browser stack',
    async ({ device, assert, signal }) => {
      const { composite } = require('node-onlykey-lib/crypto');
      const openpgp = require('node-onlykey-lib/crypto/pgp');
      const generated = await composite.generateCompositeKey(openpgp, {
        userId: { name: 'Kit', email: 'kit@example.com' },
      });
      blob = Buffer.from(generated.blob);

      const { ed25519, x25519 } = require('node-onlykey-lib/vendor/@noble/curves/ed25519.js');
      ed25519Pub = Buffer.from(ed25519.getPublicKey(blob.subarray(0, 32)));
      x25519Sk = Buffer.from(blob.subarray(64, 96));
      assert.equal(x25519.getPublicKey(x25519Sk).length, 32);

      await device.unlock(PINS.primary, { signal });
      await device.enterConfigMode(PINS.primary, { signal });
      const result = await cli.run('onlykey-cli',
        ['setkey', SLOT_NAME, 'p', blob.toString('hex')], { timeoutMs: 60000, signal });
      assert.equal(result.code, 0, `setkey p failed: ${result.stderr || result.stdout}`);
      await device.restart({ signal });
      await device.unlock(PINS.primary, { signal });

      app = await composeBrowserStack(device, signal);
      okcrypto = app.services.okcrypto;
      assert.equal(app.services.transport.tunnelOnly, true, 'not the tunnel-only transport');
    });

  it('connects over the tunnel and reads the firmware from the plain reply',
    async ({ assert, log }) => {
      const connected = await okcrypto.connectTunnel();
      log(`status ${connected.status}; transitV2=${connected.capabilities && connected.capabilities.transitV2}`);
      assert.ok(/UNLOCKED/.test(String(connected.status)), `not an unlocked status: ${connected.status}`);
      assert.equal(connected.capabilities.transitV2, true,
        'the working tree is v3.1.0 - it speaks transit v2');
    });

  it('signs with the Ed25519 half - sealed request, challenge, v2 result - and it verifies',
    async ({ device, assert, signal, log }) => {
      const digest = crypto.createHash('sha256').update('signed through node-onlykey-lib').digest();
      const press = presser(device, signal);
      press.arm();
      const sig = Buffer.from(await okcrypto.composite_sign(SLOT_ID, HALF_ECC, digest,
        { confirm: press.confirm }));
      log(`library got ${sig.length} bytes`);
      assert.equal(sig.length, 64, 'an Ed25519 signature is 64 bytes');
      const { ed25519 } = require('node-onlykey-lib/vendor/@noble/curves/ed25519.js');
      assert.ok(ed25519.verify(sig, digest, ed25519Pub),
        'the signature does not verify against the loaded key');
    });

  it('decrypts with the X25519 half', async ({ device, assert, signal }) => {
    const { x25519 } = require('node-onlykey-lib/vendor/@noble/curves/ed25519.js');
    const ephemeralSk = x25519.utils.randomSecretKey();
    const ephemeralPub = x25519.getPublicKey(ephemeralSk);
    const expected = Buffer.from(x25519.getSharedSecret(ephemeralSk, x25519.getPublicKey(x25519Sk)));

    const press = presser(device, signal);
    press.arm();
    const shared = Buffer.from(await okcrypto.composite_decrypt(SLOT_ID, ephemeralPub,
      { confirm: press.confirm }));
    assert.equal(shared.length, 32, 'an X25519 shared secret is 32 bytes');
    assert.bytes(shared, expected, 'the device computed a different shared secret');
  });

  it('decrypts with the ML-KEM-768 half - 1088 bytes, several sealed chunks',
    async ({ device, assert, signal }) => {
      const { ml_kem768 } = require('node-onlykey-lib/vendor/@noble/post-quantum/ml-kem.js');
      const { composite } = require('node-onlykey-lib/crypto');
      const { mlkemSeed } = composite.unpackBlob(blob);
      const { publicKey } = ml_kem768.keygen(Uint8Array.from(mlkemSeed));
      const { cipherText, sharedSecret } = ml_kem768.encapsulate(publicKey);

      const press = presser(device, signal);
      press.arm();
      const shared = Buffer.from(await okcrypto.composite_decrypt(SLOT_ID, cipherText,
        { confirm: press.confirm }));
      assert.bytes(shared, Buffer.from(sharedSecret),
        'the device decapsulated to a different secret - the sealed chunks did not arrive intact');
    });

  it('tears the stack down', async () => {
    if (app) await app.destroy();
  });
});
