'use strict';
/*
 * The OnlyKey DUO - one firmware image with the classic OnlyKey, told apart at
 * boot by its own detection (okcore.cpp calibratecaptouch(): the chip's package
 * ID, then analog pin A12), and driven differently from then on:
 *
 *   - three buttons, the third being both pads at once;
 *   - PIN digits 4..6 are holds of 1..3, while the key is locked (payload());
 *   - config mode is button 1 held >= 180 rounds, not button 6;
 *   - challenge codes are mod 3, so they only ever name buttons 1..3;
 *   - its PIN is set by the App as digits (sendPinDUO), which is what the
 *     'initialized' fixture does on a DUO.
 *
 * Run it against an emulated DUO with OKEMU_HARDWARE=duo (node-onlykey-emulator's
 * board option, which leaves detection to the firmware), or a hard DUO with
 * OKT_MODEL=duo. The last test wipes the key: the self-destruct PIN, typed with
 * holds.
 */
const crypto = require('crypto');
const { describe, it } = require('../../lib/harness');
const { IFACE, okmsg } = require('../../lib/device');
const { PINS } = require('../../lib/config');
const pqc = require('../../lib/pqc');
const { MODEL_LETTER, pinPresses } = require('../../lib/model');

const SLOT = 116;                      // an ECC slot nothing else here uses
const ED25519 = 1, FEATURE_SIGN = 64, FIELD_STORED_CHALLENGE = 22;
const ED_SEED = Buffer.from('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60', 'hex');
const RECEIVED = /Received Message/g;
/* RFC 8032's first test key, as a node key: PKCS#8 for Ed25519 is this prefix + the seed. */
const ED_KEY = crypto.createPrivateKey({
  key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), ED_SEED]), format: 'der', type: 'pkcs8',
});

describe('OnlyKey DUO', { state: 'initialized', requires: ['duo', 'crypto'], timeoutMs: 600000 }, () => {
  it('says it is a DUO: INITIALIZED-D while locked, a DUO model letter once unlocked',
    async ({ device, assert, signal, log }) => {
      const locked = await device.status({ signal });
      log(`locked: ${locked.raw}`);
      assert.equal(locked.state, 'locked');
      assert.match(locked.raw, /^INITIALIZED-D/, `a locked DUO broadcasts INITIALIZED-D, got ${locked.raw}`);

      const model = await device.unlock(PINS.primary, { signal });
      log(`unlocked: ${model}`);
      assert.match(model, new RegExp(`^UNLOCKED.*${MODEL_LETTER.duo.source}`), `not a DUO model string: ${model}`);
    });

  it('takes config mode from button 1 held past 180 rounds', async ({ device, assert, signal, log }) => {
    await device.ensureUnlocked(PINS.primary, { signal });
    const wipe = async () => {
      const since = device.mark(IFACE.VENDOR);
      device.sendVendor({ msg: okmsg.MSG.OKWIPEPRIV, slot: SLOT, field: 0 });
      return okmsg.text(await device.waitHid(IFACE.VENDOR,
        { since, match: /Success|Error/, timeoutMs: 10000, signal })).trim();
    };
    const before = await wipe();
    log(`before: ${before}`);
    assert.match(before, /not in config mode/, `outside config mode the wipe should be refused, got ${before}`);

    await device.enterConfigMode(PINS.primary, { signal });   // button 1, 'long', on a DUO
    const after = await wipe();
    log(`in config mode: ${after}`);
    assert.ok(!/not in config mode/.test(after), `config mode did not take: ${after}`);
  });

  it('asks for a challenge code of buttons 1-3 only, and accepts it', async ({ device, assert, signal, log }) => {
    await pqc.readyForKeygen(device, { signal });              // restart, unlock, config mode
    let since = device.mark(IFACE.VENDOR);
    device.sendVendor({ msg: okmsg.MSG.OKSETSLOT, slot: 1, field: FIELD_STORED_CHALLENGE, payload: Buffer.from([0]) });
    await device.waitHid(IFACE.VENDOR, { since, match: /Success|Error/, timeoutMs: 8000, signal });
    since = device.mark(IFACE.VENDOR);
    device.sendVendor({ msg: okmsg.MSG.OKSETPRIV, slot: SLOT, field: ED25519 | FEATURE_SIGN, payload: ED_SEED });
    const loaded = okmsg.text(await device.waitHid(IFACE.VENDOR,
      { since, match: /Success|Error/, timeoutMs: 30000, signal }));
    assert.match(loaded, /Success/, `loading the key: ${loaded}`);
    await device.sleep(500, { signal });
    await device.restart({ signal });
    await device.ensureUnlocked(PINS.primary, { signal });

    const seen0 = device.log.count(RECEIVED);
    const msg = crypto.randomBytes(32);
    const reply = await pqc.confirmFromConsole(device, async () => {
      const s = device.mark(IFACE.VENDOR);
      device.sendVendor({ msg: okmsg.MSG.OKSIGN, slot: SLOT, field: 32, payload: msg });
      return device.waitHid(IFACE.VENDOR, { since: s, timeoutMs: 40000, signal });
    }, { signal });
    /* The digits the device asked for, from the packet it printed it hashed. */
    const packet = device.log.count(RECEIVED) > seen0 ? pqc.packetFromConsole(device) : null;
    const digitsSeen = packet ? pqc.challengeDigitsFor(packet) : [];
    /* What the DEVICE did with the presses: OnlyKey.ino prints each accepted digit of the code. */
    const entered = (device.log.text.match(/Challenge[123] entered\d/g) || []).slice(-3);
    log(`device console: ${entered.join(', ') || '(no challenge entries)'}`);
    assert.equal(entered.length, 3, 'the device should have taken three challenge digits');
    const text = okmsg.text(reply);
    log(`challenge ${digitsSeen.join(' ')}; reply: ${/^Error/.test(text) ? text : `${reply.length} bytes`}`);
    assert.ok(digitsSeen.length === 3 && digitsSeen.every((d) => d >= 1 && d <= 3),
      `a DUO challenge names buttons 1-3, got ${digitsSeen.join(' ')}`);
    assert.ok(!/^Error/.test(text), `the sign was refused: ${text}`);
    assert.ok(crypto.verify(null, msg, crypto.createPublicKey(ED_KEY), Buffer.from(reply).subarray(0, 64)),
      'the signature does not verify');
  });

  it('enters PIN digits 4-6 as holds: the self-destruct PIN 6666666 wipes the key',
    async ({ device, assert, signal, log }) => {
      await device.restart({ signal });
      const locked = await device.status({ signal });
      assert.equal(locked.state, 'locked');
      log(`typing ${PINS.selfDestruct} as ${JSON.stringify(pinPresses(PINS.selfDestruct))}`);
      device.pressLine(pinPresses(PINS.selfDestruct));
      let state = null;
      for (let i = 0; i < 12 && state !== 'uninitialized'; i++) {
        await device.sleep(2500, { signal });
        try { ({ state } = await device.status({ signal, timeoutMs: 5000 })); } catch (_) { state = null; }
      }
      log(`after the self-destruct PIN: ${state}`);
      assert.equal(state, 'uninitialized', 'holding 3 seven times should have been 6666666, the self-destruct PIN');
    });
});
