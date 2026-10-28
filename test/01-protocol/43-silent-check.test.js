'use strict';
/*
 * RC FIX 0015 - a getAssertion with up false does not run the extension request (node-onlykey-emulator
 * scripts/versions/patches-3.1.0/0015-libraries-fido2-silent-getassertion: the patch and its README).
 *
 * Windows' WebAuthn sends every allowCredentials request twice: a silent check first (options.up false), then the
 * real request (up true). The firmware ran an extension request - the web apps' tunnel - on the silent check: the
 * transit layer took its data and stored the answer, and the real request that followed was dropped as a repeated
 * packet ("Repeated data packet ignored"). The page never got its answer and started over, for ever (found with the
 * ok-edge web app on Windows, 2026-10-27; Chrome on Linux sends the real request alone, so it worked there).
 *
 * The kit's browser (lib/webenv.js, silentCheck) sends what Windows sends. With fix 0015 the tunnel connects and a
 * request with data - the agent public key the web app reads as its bucket identity - is answered, and answered the
 * same as without the silent check. Without the fix the same read fails: that is the bug, recorded, not a regression.
 * Any build (emulator or hard key; a hard key says what it carries with OKT_FIRMWARE_FIXES).
 */
const { describe, it } = require('../../lib/harness');
const { PINS } = require('../../lib/config');
const { firmwareFixes } = require('../../lib/firmware-fixes');
const webenv = require('../../lib/webenv');

/* the agent public key the web app reads as its bucket identity, over the tunnel, through `opts`' browser */
async function identityThrough(device, opts) {
  const { lib, okcrypto } = await webenv.browserLib(device, opts);
  try {
    const { readIdentity } = require('node-onlykey-lib/bucket').bucketIdentity;
    const { publicKey } = await readIdentity(okcrypto);
    return Buffer.from(publicKey).toString('hex');
  } finally {
    await lib.destroy();
  }
}

/* resolves to the value, or to the error it failed with - a hung read counts as failed after `ms` */
function settle(promise, ms) {
  return Promise.race([
    promise.then((value) => ({ value }), (error) => ({ error })),
    new Promise((resolve) => setTimeout(() => resolve({ error: new Error(`no answer in ${ms / 1000} s`) }), ms)),
  ]);
}

describe('a host that checks each credential silently first - Windows (RC fix 0015)', { state: 'initialized', timeoutMs: 300000 }, () => {
  it('the tunnel answers a request with data when each one is preceded by a silent check', async ({ device, assert, signal, log }) => {
    await device.ensureUnlocked(PINS.primary, { signal });
    const fixed = firmwareFixes(device).includes('0015');

    const plain = await identityThrough(device, { signal });
    log(`identity, one request each (Linux): ${plain.slice(0, 16)}`);

    const windows = await settle(identityThrough(device, { signal, silentCheck: true }), 60000);
    if (fixed) {
      assert.ok(!windows.error, `with fix 0015 the silent-check host was not answered: ${windows.error && windows.error.message}`);
      assert.equal(windows.value, plain, 'the silent-check host read another identity');
      log(`identity, silent check first (Windows): ${windows.value.slice(0, 16)} - the same`);
    } else {
      log(`without fix 0015 the silent-check host: ${windows.error ? `failed (${windows.error.message})` : `answered ${windows.value.slice(0, 16)}`}`);
      assert.ok(windows.error || windows.value !== plain, 'without fix 0015 the silent-check host was answered correctly - is the fix upstream now?');
    }
  });
});
