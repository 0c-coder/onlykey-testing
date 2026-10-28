/*
 * node-onlykey-lib's device plugin, against the real firmware: generateEccKey
 * (lib eeaea46), wipeSlot's every-reply result and loadKey's reply (59ddcdb),
 * and setPreference's per-firmware row (64e8f7b).
 *
 * WHY AGAINST THE FIRMWARE. Each of these changed what the lib RETURNS from a
 * device reply, and the lib's suite proves it against its fake firmware - whose
 * replies are the lib author's reading of okcore.cpp. These tests put the real
 * reply under the same calls:
 *
 *   generateEccKey  ONE OKSETPRIV with the 0xFF trigger, in config mode, and
 *                   the key read back after the restart (config mode drops
 *                   OKGETPUBKEY). The shape is checked by node:crypto loading
 *                   the point, not by a length alone.
 *   wipeSlot        wipe_slot() answers once PER FIELD - ten on 3.1.0. The old
 *                   wipeSlot resolved on the first and left nine on the bus for
 *                   the next caller to mistake for its own answer. And for
 *                   slots 1-24 the firmware wipes the WHOLE slot whatever field
 *                   byte is sent; that is pinned here, because the lib's API
 *                   takes a field and a reader would assume it means something.
 *   loadKey         returns the device's own words; a refusal carries them as
 *                   err.deviceText (okmsg.deviceError), not a timeout.
 *   setPreference   on a 3.1.0 session the derived/stored input modes are
 *                   0/1 enums, so 8 (the old "no touch" bit) and 2 (none) are
 *                   refused BEFORE a byte is sent. The firmware refuses both
 *                   too - measured here raw, so the lib's row is checked
 *                   against the device and not against itself.
 *
 * Every "nothing was sent" reads lib/libstack.js's record of the lib's writes,
 * and every one is preceded in the same test by a write the same record DID
 * catch (assert.control) - a dead recorder reads exactly like a refusal.
 *
 * SURFACES: the lib over the kit's in-process emulator (transport/embedded),
 * vendor only; presses through the firmware's debug button harness. No gadget.
 */
'use strict';

const crypto = require('crypto');

const { describe, it } = require('../../lib/harness');
const { IFACE, okmsg } = require('../../lib/device');
const { PINS } = require('../../lib/config');
const { composeLib } = require('../../lib/libstack');

const ECC_SLOT = 101;                   // ECC1
const TRIGGER = 'ff'.repeat(32);        // the firmware's "generate your own"
const SLOT = 1;                         // slot 1a
const LABEL = 'g2wipe';
const PASSWORD = 'wipe-me-123';
const FIELD_PASSWORD = 5;               // okcore.cpp OKSETSLOT case 5
const WIPE_REPLIES = 10;                // wipe_slot(): one per field, v2.1.2-3.1.0
const FIELD_DERIVED_MODE = 21;
const FIELD_STORED_MODE = 22;

const SPKI = {
  ed25519: Buffer.from('302a300506032b6570032100', 'hex'),
  x25519: Buffer.from('302a300506032b656e032100', 'hex'),
};

/*
 * What a generated key must look like, checked by node:crypto loading it -
 * an all-zero or truncated answer fails here, not just a wrong length.
 */
const TYPES = [
  { name: 'Ed25519', type: 1, use: { signature: true }, pub: 32,
    load: (k) => crypto.createPublicKey({ key: Buffer.concat([SPKI.ed25519, k]), format: 'der', type: 'spki' }) },
  { name: 'P-256', type: 2, use: { signature: true }, pub: 64,
    load: (k) => crypto.ECDH.convertKey(Buffer.concat([Buffer.from([4]), k]), 'prime256v1') },
  { name: 'secp256k1', type: 3, use: { signature: true }, pub: 64,
    load: (k) => crypto.ECDH.convertKey(Buffer.concat([Buffer.from([4]), k]), 'secp256k1') },
  { name: 'Curve25519', type: 4, use: { decryption: true }, pub: 32,
    load: (k) => crypto.createPublicKey({ key: Buffer.concat([SPKI.x25519, k]), format: 'der', type: 'spki' }) },
];

const isMsg = (msg) => (w) => w.iface === IFACE.VENDOR && w.data[4] === msg;
const labelText = (l) => (typeof l === 'string' ? l : (l && (l.label ?? l.text ?? l.name)) || '');

describe('node-onlykey-lib device writes against the real firmware', {
  state: 'initialized',
  requires: ['crypto', 'keyboard-capture'],
  negative: true,
  timeoutMs: 600000,
}, () => {
  /* Unlocked, a connected lib session (version known), then config mode. */
  async function configModeLib(device, signal) {
    await device.restart({ signal });
    await device.unlock(PINS.primary, { signal });
    const lib = await composeLib(device);
    await lib.services.device.connect({ timeoutMs: 6000 });
    await device.enterConfigMode(PINS.primary, { signal });
    return lib;
  }

  for (const t of TYPES) {
    it(`generateEccKey ${t.name} (type ${t.type}): one trigger, and the key reads back after the restart`,
      async ({ device, assert, signal, log }) => {
        const lib = await configModeLib(device, signal);
        try {
          const before = lib.writes.length;
          const made = await lib.services.device.generateEccKey(ECC_SLOT, t.type, t.use);
          const sent = lib.writes.slice(before).filter(isMsg(okmsg.MSG.OKSETPRIV));
          log(`device said ${JSON.stringify(made.response)}; type byte 0x${made.type.toString(16)}`);

          assert.match(String(made.response), /^Successfully set ECC Key/,
            `the firmware did not acknowledge the generation: ${made.response}`);
          assert.equal(sent.length, 1,
            `${sent.length} OKSETPRIV frames for one generateEccKey - a resend generates again`);
          const frame = sent[0].data;
          assert.equal(frame[5], ECC_SLOT, 'the trigger went to the wrong slot');
          assert.equal(frame[6] & 0x0F, t.type, 'the trigger carried the wrong key type');
          assert.equal(frame.subarray(7, 39).toString('hex'), TRIGGER,
            'the payload was not the 0xFF generate trigger');

          /* Config mode drops OKGETPUBKEY: the readback is after the restart. */
          await device.restart({ signal });
          await device.ensureUnlocked(PINS.primary, { signal });
          const report = Buffer.from(await lib.services.device.getPublicKey(ECC_SLOT));
          const pub = report.subarray(0, t.pub);
          log(`public key ${pub.subarray(0, 16).toString('hex')}…`);

          assert.ok(report.length >= t.pub, `the slot answered ${report.length} bytes`);
          let loaded = null;
          try { loaded = t.load(pub); } catch (err) { loaded = err; }
          assert.control(`node:crypto loads the ${t.name} public key the slot published`,
            loaded && !(loaded instanceof Error));
          assert.notEqual(pub.toString('hex'), '00'.repeat(t.pub), 'the slot published all zeros');
          if (t.type === 4) {
            /* 28-on-device-keygen's named defect: the trigger stored as the key. */
            const trigger = crypto.createPublicKey(crypto.createPrivateKey({
              key: Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), Buffer.alloc(32, 0xFF)]),
              format: 'der', type: 'pkcs8',
            })).export({ type: 'spki', format: 'der' }).subarray(12);
            assert.notEqual(pub.toString('hex'), trigger.toString('hex'),
              'the slot published the X25519 key of the all-0xFF trigger - nothing was generated');
          }
        } finally {
          await lib.destroy();
        }
      });
  }

  it('wipeSlot collects all ten replies, and wipes the WHOLE slot whatever field is named',
    async ({ device, assert, signal, log }) => {
      await device.restart({ signal });
      await device.unlock(PINS.primary, { signal });
      const lib = await composeLib(device);
      try {
        const dev = lib.services.device;
        await dev.setSlot(SLOT, { label: LABEL, password: PASSWORD });

        /* CONTROL 1: the label is there to be wiped, read by the same reader. */
        const before = (await dev.readLabels()).labels.map(labelText);
        log(`labels before: ${JSON.stringify(before.slice(0, 2))}`);
        assert.control('slot 1 holds the label just written', before.includes(LABEL));

        /* CONTROL 2: the button types the password, so silence later means something. */
        device.keys.clear();
        let typed = null;
        for (let attempt = 1; attempt <= 3 && !typed; attempt++) {
          device.press(SLOT);
          typed = await device.waitKeystrokes(PASSWORD, { timeoutMs: 6000, signal }).catch(() => null);
        }
        assert.control('pressing button 1 types the stored password', typed);
        await device.sleep(1500, { signal });

        const writesBefore = lib.writes.length;
        const wiped = await dev.wipeSlot(SLOT, 'password');
        const sent = lib.writes.slice(writesBefore).filter(isMsg(okmsg.MSG.OKWIPESLOT));
        log(`wipeSlot: ${wiped.responses.length} replies, first ${JSON.stringify(wiped.response)}`);

        assert.equal(sent.length, 1, `${sent.length} OKWIPESLOT frames for one wipeSlot`);
        assert.equal(sent[0].data[6], FIELD_PASSWORD,
          'the wipe did not carry the password field byte - this would not test the field-byte claim');
        assert.equal(wiped.responses.length, WIPE_REPLIES,
          `the firmware answers a slot wipe once per field (${WIPE_REPLIES} on 3.1.0); ` +
          `wipeSlot collected ${wiped.responses.length}: ${JSON.stringify(wiped.responses)}`);
        assert.equal(wiped.response, wiped.responses[0], 'response is not the first reply');
        assert.ok(wiped.responses.every((r) => /^Success/i.test(r)),
          `a reply was not a success: ${JSON.stringify(wiped.responses)}`);

        /*
         * THE FIELD BYTE IS IGNORED for slots 1-24: only the password was named,
         * and the label goes too. Pinned, so the day the firmware honours the
         * field this fails and the lib's API note can be revisited with it.
         */
        const after = (await dev.readLabels()).labels.map(labelText);
        log(`labels after: ${JSON.stringify(after.slice(0, 2))}`);
        assert.ok(!after.includes(LABEL),
          'the label survived a wipe that named only the password - the firmware now honours the field byte');

        device.keys.clear();
        for (let attempt = 1; attempt <= 3; attempt++) {
          device.press(SLOT);
          await device.sleep(2000, { signal });
        }
        assert.absent(!device.keystrokes.includes(PASSWORD),
          `the wiped slot still typed: ${JSON.stringify(device.keystrokes)}`);
      } finally {
        await lib.destroy();
      }
    });

  it('loadKey returns the device\'s reply; a refused load carries the firmware\'s words as deviceText',
    async ({ device, assert, signal, log }) => {
      const lib = await configModeLib(device, signal);
      try {
        const dev = lib.services.device;
        const seed = crypto.randomBytes(32);
        const loaded = await dev.loadKey(ECC_SLOT, { type: 1 | 0x40, key: seed });
        log(`loadKey said ${JSON.stringify(loaded.response)}`);
        assert.match(String(loaded.response), /^Successfully set ECC Key/,
          `loadKey did not return the device's acknowledgement: ${JSON.stringify(loaded.response)}`);

        /* okcore.cpp ecc_priv_flash: a slot outside 101..132 is refused by name. */
        const err = await dev.loadKey(133, { type: 1 | 0x40, key: seed }).then(() => null, (e) => e);
        log(`refused load: deviceText ${JSON.stringify(err && err.deviceText)}, kind ${err && err.kind}`);
        assert.ok(err, 'the firmware accepted a key for slot 133');
        assert.equal(err.deviceText, 'Error invalid ECC slot',
          `the refusal does not carry the firmware's words: ${err && err.message}`);

        /* CONTROL: the accepted load really landed - the slot publishes the seed's key. */
        await device.restart({ signal });
        await device.ensureUnlocked(PINS.primary, { signal });
        const pub = Buffer.from(await dev.getPublicKey(ECC_SLOT)).subarray(0, 32);
        const expected = crypto.createPublicKey(crypto.createPrivateKey({
          key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]),
          format: 'der', type: 'pkcs8',
        })).export({ type: 'spki', format: 'der' }).subarray(-32);
        assert.control('the slot publishes the Ed25519 key of the loaded seed', pub.equals(expected));
      } finally {
        await lib.destroy();
      }
    });

  it('setPreference on 3.1.0 refuses derivedChallengeMode 8 and storedChallengeMode 2 before sending; 1 is acked',
    async ({ device, assert, signal, log }) => {
      const lib = await configModeLib(device, signal);
      try {
        const dev = lib.services.device;
        assert.equal(dev.capabilities && dev.capabilities.userInputModeEnum, true,
          'the connected session does not read 3.1.0 as the enum input modes');

        const before = lib.writes.length;
        const derived8 = await dev.setPreference('derivedChallengeMode', 8).then(() => null, (e) => e);
        const stored2 = await dev.setPreference('storedChallengeMode', 2).then(() => null, (e) => e);
        const sentByRefusals = lib.writes.length - before;
        log(`lib: ${derived8 && derived8.message} | ${stored2 && stored2.message}`);
        assert.ok(derived8 instanceof RangeError, `derivedChallengeMode 8 was not refused: ${derived8}`);
        assert.ok(stored2 instanceof RangeError, `storedChallengeMode 2 was not refused: ${stored2}`);

        /* CONTROL: an in-range value goes out through the same record and is acked. */
        const ok = await dev.setPreference('storedChallengeMode', 1);
        const sent = lib.writes.slice(before).filter(isMsg(okmsg.MSG.OKSETSLOT));
        log(`storedChallengeMode 1: ${JSON.stringify(ok.response)}`);
        assert.control('an in-range storedChallengeMode went out as OKSETSLOT field 22 and the firmware acked it',
          sent.length === 1 && sent[0].data[6] === FIELD_STORED_MODE && sent[0].data[7] === 1
          && /^Successfully set stored key challenge mode/.test(String(ok.response)));
        assert.absent(sentByRefusals === 0,
          `${sentByRefusals} frame(s) went out for values the lib refused`);

        /*
         * WHO IS TRUE: the same two values sent raw, past the lib. The lib's row
         * says the firmware refuses them; this asks the firmware.
         */
        const raw = async (field, value) => {
          const since = device.mark(IFACE.VENDOR);
          device.sendVendor({ msg: okmsg.MSG.OKSETSLOT, slot: 1, field, payload: Buffer.from([value]) });
          const reply = await device.waitHid(IFACE.VENDOR,
            { since, match: /^(Success|Error)/, timeoutMs: 5000, signal });
          return okmsg.text(reply).trim();
        };
        const fw8 = await raw(FIELD_DERIVED_MODE, 8);
        const fw2 = await raw(FIELD_STORED_MODE, 2);
        log(`firmware: field 21 = 8 -> ${JSON.stringify(fw8)}; field 22 = 2 -> ${JSON.stringify(fw2)}`);
        assert.match(fw8, /^Error invalid user input mode/,
          'the firmware accepted derivedChallengeMode 8 - the lib refuses a value the device takes');
        assert.match(fw2, /^Error unsupported user input mode/,
          'the firmware accepted storedChallengeMode 2 - an OK_ALLOW_NO_PRESS build, or the lib row is wrong');
      } finally {
        await lib.destroy();
      }
    });
});
