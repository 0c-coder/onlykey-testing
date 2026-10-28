/*
 * node-onlykey-lib's okcrypto, against the real firmware: X-Wing asks the
 * version first (lib 204bd28), and a low-order X25519 point never leaves the
 * host (lib 267d199).
 *
 * WHY AGAINST THE FIRMWARE when the lib already tests both. The lib's tests run
 * on its fake firmware, which answers what the lib's author believes the
 * firmware answers. The two claims here are both about what the REAL device
 * says when nobody has told the lib anything:
 *
 *   - a LOCKED key answers OKCONNECT with INITIALIZED and no version. The X-Wing
 *     fix rests entirely on that reply having no version in it, and on the lib
 *     then refusing (XWING_VERSION_UNKNOWN) instead of guessing the pre-3.1.0
 *     64-byte shape. If 3.1.0 ever put its version in the locked reply, the
 *     refusal would never fire - and nothing in the lib's suite would notice.
 *   - an UNLOCKED key nobody connected: the lib must learn 3.1.0 over the vendor
 *     interface and take the custody shape. Before the fix it read "unknown" as
 *     "old" and sliced a 1216-byte recipient into a 64-byte pair - a valid-looking
 *     recipient of a key nobody holds, which no length check can see.
 *
 * THE ORACLE FOR THE SHAPE is a second stack on the same device that connected
 * FIRST, the path that was always right. Both run the same lib code; the claim
 * of G-6 is precisely that "nobody connected" and "connected" now give the same
 * recipient. Under the bug they differ (the split recipient re-expands the
 * first 64 bytes of pk_M), so equality is the test, not a tautology.
 *
 * THE GUARD: v3.0.4 computes X25519 with whatever it is sent and answers a
 * 32-byte zero secret for a low-order point; only the host can refuse that on
 * the installed base. The control is the same call with a GOOD point, which
 * must reach the firmware, be confirmed and agree with node:crypto - only then
 * does "the low-order ones never reached it" mean anything.
 *
 * SURFACES: the lib composed over the kit's in-process emulator
 * (lib/libstack.js, transport/embedded) - vendor and FIDO, no gadget, so this
 * runs on Windows. The challenge press goes through the firmware's debug
 * button harness like every other press in section 1.
 */
'use strict';

const crypto = require('crypto');

const { describe, it } = require('../../lib/harness');
const { IFACE, okmsg } = require('../../lib/device');
const { PINS } = require('../../lib/config');
const { composeLib } = require('../../lib/libstack');
const { x25519guard } = require('node-onlykey-lib/crypto');

const LABEL = 'age:g2-xwing@example.com';
const XWING_RECIPIENT = 1216;           // pk_M (1184) | pk_X (32), 3.1.0+
const IDENTITY = { gpg: 'okt G2 <g2@example.com>' };
const KEYTYPE_CURVE25519 = 4;
const PRIMED = /Encrypted Buffer/g;     // the firmware staged an answer and waits for the press
const X25519_SPKI = Buffer.from('302a300506032b656e032100', 'hex');

const isConnect = (w) => w.data[4] === okmsg.MSG.OKCONNECT;

describe('node-onlykey-lib okcrypto: X-Wing version first, low-order X25519 refused', {
  state: 'initialized',
  requires: ['crypto'],
  negative: true,
  timeoutMs: 300000,
}, () => {
  it('X-Wing on a LOCKED key is refused XWING_VERSION_UNKNOWN, and nothing reaches FIDO',
    async ({ device, assert, signal, log }) => {
      /* Locked by construction: a reboot relocks, and nothing here unlocks. */
      await device.restart({ signal });
      const lib = await composeLib(device);
      try {
        const since = device.mark(IFACE.VENDOR);
        const err = await lib.services.okcrypto.deviceAge
          .identity(LABEL, { timeoutMs: 6000 })
          .then(() => null, (e) => e);

        const asked = lib.vendorWrites().filter(isConnect);
        const answered = device.reportsSince(IFACE.VENDOR, since)
          .map((r) => okmsg.text(r)).filter((t) => /INITIALIZED/.test(t));
        const identity = lib.services.device.identity;
        log(`asked ${asked.length}x, firmware said ${JSON.stringify(answered[0] || null)}, ` +
          `lib identity version ${identity && identity.version}`);

        /*
         * THE CONTROL: the lib DID ask (a vendor OKCONNECT is in the record) and
         * the real firmware DID answer it, with the locked status. Without both,
         * "no FIDO write" below could be a dead recorder or a lib that never
         * got as far as wanting one.
         */
        assert.control('the lib asked the version over vendor OKCONNECT and the locked firmware answered INITIALIZED',
          asked.length >= 1 && answered.length >= 1);
        assert.ok(identity && !identity.version,
          `the locked firmware's reply carried a version (${identity && identity.version}) - ` +
          'then the X-Wing refusal can never fire, and this file is measuring the wrong thing');

        assert.ok(err, 'X-Wing derived on a LOCKED key - the lib went ahead without a version');
        assert.equal(err.code, 'XWING_VERSION_UNKNOWN',
          `refused, but not by name: ${err && (err.code || err.message)}`);
        assert.absent(lib.fidoWrites().length === 0,
          `${lib.fidoWrites().length} frame(s) went to the FIDO interface without a known X-Wing shape`);
      } finally {
        await lib.destroy();
      }
    });

  it('X-Wing on an UNLOCKED key nobody connected: the lib learns 3.1.0 and returns the 1216-byte custody recipient',
    async ({ device, assert, signal, log }) => {
      await device.restart({ signal });
      await device.ensureUnlocked(PINS.primary, { signal });

      /* Stack A: nobody connected it - ok-rn's hard key, unlocked on the keypad. */
      const a = await composeLib(device);
      let fromUnconnected;
      try {
        assert.ok(!a.services.device.identity || !a.services.device.identity.version,
          'the stack knew a version before anything asked - it is not the unconnected case');
        fromUnconnected = await a.services.okcrypto.deviceAge.identity(LABEL, { timeoutMs: 20000 });

        const writes = a.writes;
        const firstConnect = writes.findIndex((w) => w.iface === IFACE.VENDOR && isConnect(w));
        const firstFido = writes.findIndex((w) => w.iface === IFACE.FIDO);
        log(`version learned: ${a.services.device.identity.version}; ` +
          `vendor OKCONNECT at write #${firstConnect}, first FIDO at #${firstFido}`);
        assert.match(String(a.services.device.identity.version), /3\.1\.0/,
          'the lib did not learn this firmware\'s version');
        assert.ok(firstConnect >= 0 && firstFido > firstConnect,
          'the version was not asked BEFORE the derive went to the FIDO interface');
      } finally {
        await a.destroy();
      }

      /* Stack B: connected first - the path that was always right. */
      const b = await composeLib(device);
      let fromConnected;
      try {
        const c = await b.services.device.connect({ timeoutMs: 6000 });
        assert.equal(c.capabilities.xwingDeviceCustody, true,
          'a connected stack does not read 3.1.0 as X-Wing custody');
        fromConnected = await b.services.okcrypto.deviceAge.identity(LABEL, { timeoutMs: 20000 });
      } finally {
        await b.destroy();
      }

      const recipient = Buffer.from(fromUnconnected.recipient);
      log(`recipient ${recipient.length} bytes, pk_X ${Buffer.from(fromUnconnected.pkX).toString('hex').slice(0, 16)}…`);
      assert.equal(recipient.length, XWING_RECIPIENT, 'an X-Wing recipient is 1216 bytes');
      assert.equal(fromUnconnected.mlkemSeed, undefined,
        'the unconnected stack took the SPLIT path (it carries an ML-KEM seed) against a 3.1.0 key');
      assert.bytes(Buffer.from(fromUnconnected.pkX), recipient.subarray(XWING_RECIPIENT - 32),
        'pk_X is not the tail of the recipient - not the 3.1.0+ [pk_M | pk_X] layout');
      /*
       * The oracle - see the header. Equal recipients from the two stacks is
       * what "unknown is no longer read as old" means on the wire.
       */
      assert.control('the connected stack derived a custody recipient for the same label',
        fromConnected && Buffer.from(fromConnected.recipient).length === XWING_RECIPIENT);
      assert.bytes(recipient, Buffer.from(fromConnected.recipient),
        'the unconnected stack derived a DIFFERENT recipient from the connected one - the G-9 split shape');
    });

  it('agent.ecdh refuses every low-order X25519 point host-side (LOW_ORDER_POINT); a good point reaches the device',
    async ({ device, assert, signal, log }) => {
      /*
       * Derived keys (codes > 200) take field 21's input mode. Set to BUTTON
       * PRESS so the control's confirmation is one press, not a challenge whose
       * spare presses would land on slots - through the lib's own setPreference,
       * on a connected session, in config mode as the firmware requires.
       */
      await device.restart({ signal });
      await device.unlock(PINS.primary, { signal });
      const lib = await composeLib(device);
      try {
        await lib.services.device.connect({ timeoutMs: 6000 });
        await device.enterConfigMode(PINS.primary, { signal });
        const set = await lib.services.device.setPreference('derivedChallengeMode', 1);
        assert.match(String(set.response), /^Success/, `derivedChallengeMode 1: ${set.response}`);
        await device.restart({ signal });
        await device.ensureUnlocked(PINS.primary, { signal });

        const { agent } = lib.services.okcrypto;
        const devicePub = Buffer.from(await agent.publicKey(IDENTITY, { keyType: KEYTYPE_CURVE25519 }));
        log(`derived X25519 ${devicePub.toString('hex').slice(0, 16)}…`);

        /* THE CONTROL: a good point goes out, is confirmed, and agrees with node:crypto. */
        const eph = crypto.generateKeyPairSync('x25519');
        const ephPub = eph.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
        const expected = crypto.diffieHellman({
          privateKey: eph.privateKey,
          publicKey: crypto.createPublicKey({
            key: Buffer.concat([X25519_SPKI, devicePub]), format: 'der', type: 'spki',
          }),
        });
        const primedAtGood = device.log.count(PRIMED);
        const writesAtGood = lib.vendorWrites().length;
        const secret = await agent.ecdh(IDENTITY, ephPub, {
          keyType: KEYTYPE_CURVE25519,
          timeoutMs: 30000,
          confirm: async () => {
            await device.log.waitForCount(PRIMED, primedAtGood + 1, { timeoutMs: 20000, signal });
            device.press(1);
          },
        });
        assert.control('a good X25519 point went out over vendor, was confirmed, and the firmware answered',
          lib.vendorWrites().length > writesAtGood && device.log.count(PRIMED) > primedAtGood);
        assert.bytes(Buffer.from(secret), expected,
          'the device and node:crypto disagree on the X25519 secret for a good point');

        /* Now every listed low-order u, raw and in gpg's 0x40-prefixed form. */
        const writesBefore = lib.vendorWrites().length;
        const primedBefore = device.log.count(PRIMED);
        let refused = 0;
        for (const u of x25519guard.LOW_ORDER_U) {
          for (const peer of [Uint8Array.from(u), Uint8Array.of(0x40, ...u)]) {
            const err = await agent.ecdh(IDENTITY, peer, { keyType: KEYTYPE_CURVE25519, timeoutMs: 3000 })
              .then(() => null, (e) => e);
            assert.ok(err, `a low-order point ${Buffer.from(peer).toString('hex').slice(0, 12)}… was accepted`);
            assert.equal(err.code, 'LOW_ORDER_POINT',
              `refused, but not by the guard: ${err && (err.code || err.message)}`);
            refused += 1;
          }
        }
        log(`${refused} low-order points refused host-side`);
        assert.absent(lib.vendorWrites().length === writesBefore,
          `${lib.vendorWrites().length - writesBefore} frame(s) of a low-order ECDH reached the device`);
        assert.absent(device.log.count(PRIMED) === primedBefore,
          'the firmware staged an answer for a low-order point');
      } finally {
        await lib.destroy();
      }
    });
});
