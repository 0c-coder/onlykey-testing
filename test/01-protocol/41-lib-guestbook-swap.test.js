/*
 * node-onlykey-lib's Guest Book key swap (guestbook/src/swap.js) with the OnlyKey doing the
 * only private step on BOTH sides: each phone's contact identity is a derived X-Wing key, and
 * each side's "open the seal sent to me" is deviceAge.decapsulate on the real firmware.
 *
 * ONE KEY, TWO LABELS. The kit runs one emulator, so the two phones are two labels on it -
 * "okrn-contact:v1" for the phone that shows the QR, another for the one that scans. The
 * firmware derives a different X-Wing key per label, so to the protocol they are two
 * people; what this proves is that the firmware's decapsulation is exactly what the swap
 * needs, both ways, and that a peer without the QR's token never costs the shower a press.
 *
 * Field 30 = none first (as 40-lib-xwing-decapsulate does): the result is about the protocol
 * and the math, not the press.
 *
 * SURFACES: the lib over the kit's in-process emulator (vendor path) - runs on Windows.
 */
'use strict';

const crypto = require('crypto');

const { describe, it } = require('../../lib/harness');
const { PINS } = require('../../lib/config');
const { composeLib } = require('../../lib/libstack');
const { invite: inv, swap } = require('node-onlykey-lib/guestbook');

const SHOWER = 'okrn-contact:v1';
const SCANNER = 'okrn-contact:kit-scanner';
const DERIVE_WITHOUT_TOUCH = 2;
const randomBytes = (n) => new Uint8Array(crypto.randomBytes(n));

describe('node-onlykey-lib Guest Book swap: both sides opened by the firmware', {
  state: 'initialized',
  requires: ['crypto', 'xwing-math'],
  timeoutMs: 240000,
}, () => {
  let lib = null;
  const opens = { [SHOWER]: 0, [SCANNER]: 0 };
  const identityFor = async (label) => {
    const { deviceAge } = lib.services.okcrypto;
    const id = await deviceAge.identity(label, { timeoutMs: 10000 });
    return {
      publicKey: Uint8Array.from(id.recipient),
      decapsulate: (ct) => { opens[label] += 1; return deviceAge.decapsulate(label, ct, { timeoutMs: 20000 }); },
    };
  };

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

  it('the swap completes, each side opened once by the firmware, and the cards cross', async ({ assert, log }) => {
    const alice = await identityFor(SHOWER);
    const bob = await identityFor(SCANNER);
    const made = inv.makeInvite({ publicKey: alice.publicKey, randomBytes });
    log(`invite ${made.url}`);

    const a0 = swap.showerStart({ identity: alice, invite: made, randomBytes });
    const b0 = swap.scannerStart({ identity: bob, invite: inv.readInvite(made.url), randomBytes });
    const a1 = swap.showerOnOpen(a0, b0.msg);
    const b1 = swap.scannerOnKeys(b0.state, a1.msg);
    const a2 = await swap.showerOnReveal(a1.state, b1.msg);
    const b2 = await swap.scannerOnDone(b1.state, a2.msg);
    const a3 = swap.showerOnConfirm(a2.state, b2.msg);

    assert.equal(opens[SHOWER], 1, 'the shower\'s seal was not opened exactly once');
    assert.equal(opens[SCANNER], 1, 'the scanner\'s seal was not opened exactly once');
    assert.bytes(Buffer.from(a3.peer.publicKey), Buffer.from(bob.publicKey), 'the shower learned the wrong key');
    assert.bytes(Buffer.from(b2.peer.publicKey), Buffer.from(alice.publicKey), 'the scanner learned the wrong key');

    const card = { name: 'Alice', keys: [{ format: 'age', label: 'files', text: 'age1onlykey-kit-test-recipient' }] };
    const got = swap.openCard(b2.session, swap.sealCard(a3.session, card));
    assert.equal(got.name, 'Alice');
    assert.equal(got.keys[0].text, card.keys[0].text);
  });

  it('a peer without the QR\'s token is refused before the shower\'s key is asked to open anything',
    async ({ assert }) => {
      const alice = await identityFor(SHOWER);
      const bob = await identityFor(SCANNER);
      const made = inv.makeInvite({ publicKey: alice.publicKey, randomBytes });
      const before = opens[SHOWER];
      const a0 = swap.showerStart({ identity: alice, invite: made, randomBytes });
      const b0 = swap.scannerStart({ identity: bob, invite: { ...inv.readInvite(made.url), token: randomBytes(16) }, randomBytes });
      const a1 = swap.showerOnOpen(a0, b0.msg);
      const b1 = swap.scannerOnKeys(b0.state, a1.msg);
      const err = await swap.showerOnReveal(a1.state, b1.msg).then(() => null, (e) => e);
      assert.equal(err && err.code, 'ESWAP_TOKEN', `refused, but not for the token: ${err && (err.code || err.message)}`);
      assert.equal(opens[SHOWER], before, 'the firmware was asked to open a seal for a peer that never saw the QR');
    });

  it('tears the stack down', async () => {
    if (lib) await lib.destroy();
  });
});
