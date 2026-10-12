/*
 * node-onlykey-lib's deviceAge.decapsulate, against the real firmware: the
 * host seals to a label's derived X-Wing key, the device opens it, and both
 * hold the same 32-byte secret.
 *
 * WHY THIS AND NOT AN AGE FILE. A handshake (ok-rn's Guest Book key swap)
 * proves an OnlyKey holds the key for a label by opening what was sealed to
 * it - one ciphertext, no file around it. age decrypt already did this step
 * inside; decapsulate exposes it, and only the real firmware can say the
 * secret it answers is the one the host computed.
 *
 * THE NEGATIVE: X-Wing does not fail on the wrong key, it answers a different
 * secret (ML-KEM's implicit rejection). So a handshake's proof is the secret
 * MATCHING, never the call succeeding - and the second label here must open
 * the same ciphertext to something else.
 *
 * Field 30 is set to "none" first, as 02-cli/20 does, so no press is involved
 * and the result is about the math alone.
 *
 * SURFACES: the lib composed over the kit's in-process emulator
 * (lib/libstack.js, vendor path) - runs on Windows.
 */
'use strict';

const { describe, it } = require('../../lib/harness');
const { PINS } = require('../../lib/config');
const { composeLib } = require('../../lib/libstack');
const { pqc } = require('node-onlykey-lib/crypto');

const LABEL = 'okrn-contact:v1';
const OTHER_LABEL = 'okrn-contact:other';
const DERIVE_WITHOUT_TOUCH = 2;

describe('node-onlykey-lib deviceAge.decapsulate: host seals, device opens, same secret', {
  state: 'initialized',
  requires: ['crypto', 'xwing-math'],
  timeoutMs: 180000,
}, () => {
  let lib = null;

  it('sets derivation without a touch, and composes the lib', async ({ device, assert, signal }) => {
    await device.restart({ signal });
    await device.unlock(PINS.primary, { signal });
    lib = await composeLib(device);
    await lib.services.device.connect({ timeoutMs: 6000 });
    await device.enterConfigMode(PINS.primary, { signal });
    const set = await lib.services.device.setPreference('webAgentDeriveMode', DERIVE_WITHOUT_TOUCH);
    assert.match(String(set.response), /^Success/, `webAgentDeriveMode 2: ${set.response}`);
    await device.restart({ signal });
    await device.ensureUnlocked(PINS.primary, { signal });
  });

  it('the device opens a ciphertext sealed to its derived key to the host\'s secret', async ({ assert, log }) => {
    const { deviceAge } = lib.services.okcrypto;
    const id = await deviceAge.identity(LABEL, { timeoutMs: 10000 });
    assert.equal(Buffer.from(id.recipient).length, 1216, 'an X-Wing recipient is 1216 bytes');

    const { ciphertext, sharedSecret } = pqc.xwingEncapsHost(id.recipient);
    assert.equal(ciphertext.length, 1120);
    const opened = await deviceAge.decapsulate(LABEL, ciphertext, { timeoutMs: 20000 });
    log(`host ${Buffer.from(sharedSecret).toString('hex').slice(0, 16)}…, ` +
      `device ${Buffer.from(opened).toString('hex').slice(0, 16)}…`);
    assert.bytes(Buffer.from(opened), Buffer.from(sharedSecret),
      'the device opened the ciphertext to a different secret than the host sealed');

    /* Another label is another key: the same ciphertext opens to something else. */
    const wrong = await deviceAge.decapsulate(OTHER_LABEL, ciphertext, { timeoutMs: 20000 });
    assert.equal(Buffer.from(wrong).length, 32);
    assert.ok(!Buffer.from(wrong).equals(Buffer.from(sharedSecret)),
      'a different label opened the ciphertext to the same secret');
  });

  it('tears the stack down', async () => {
    if (lib) await lib.destroy();
  });
});
