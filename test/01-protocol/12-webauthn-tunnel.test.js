/*
 * Vendor commands smuggled through a WebAuthn assertion - the third protocol
 * plane, and the one the web app actually uses.
 *
 * A browser cannot reach the vendor interface: WebHID would prompt, and the
 * RawHID2 interface is not exposed to pages at all. So the firmware accepts a
 * vendor request hidden in the one place a page can put arbitrary bytes - the
 * `allowList` credential ID of an ordinary getAssertion - and answers in the
 * one field that carries arbitrary bytes back, the assertion's SIGNATURE.
 *
 * The old kit reached this through @vincss-public-projects/fido2-client over
 * hidapi, so it needed a kernel device node. Riding the kit's own CTAP2 layer
 * instead puts it in section 1, which means CI can run it.
 *
 * The rpId is not a free choice: webcryptcheck() admits only apps.crp.to and
 * apps.onlykey.io. It does not change derived keys - those have no origin in
 * them any more. lib/device/tunnel.js explains both and picks the default.
 */
'use strict';

const crypto = require('crypto');

const { describe, it } = require('../../lib/harness');
const { PINS } = require('../../lib/config');
const { Ctap2 } = require('../../lib/device/ctap2');
const tunnel = require('../../lib/device/tunnel');
const okmsg = require('../../lib/device/okmsg');

/* An X25519 public key wrapped as SPKI, which is what node:crypto imports. */
const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');

describe('WebAuthn tunnel',
  { state: 'initialized', requires: ['crypto'], timeoutMs: 120000 }, () => {
    let ctap = null;
    let handshake = null;
    let vendorVersion = null;

    it('unlocks and opens a channel', async ({ device, assert, signal }) => {
      const model = await device.unlock(PINS.primary, { signal });
      vendorVersion = model;                      // for the cross-plane check below

      ctap = new Ctap2(device, { signal });
      await ctap.init();
      assert.ok(ctap.cid, 'no CTAPHID channel');
    });

    it('answers a vendor command sent as a credential id',
      async ({ device, assert, log, signal }) => {
        let pressed = 0;
        handshake = await tunnel.send(ctap, {
          cmd: okmsg.MSG.OKCONNECT,
          data: crypto.randomBytes(32),           // an ephemeral public key
        }, {
          timeoutMs: 30000,
          signal,
          onKeepAlive: async (status) => {
            if (status === 2 && !pressed) {
              pressed++;
              log('tunnel asked for user presence - pressing button 1');
              device.press(1);
            }
          },
        });

        assert.equal(handshake.status, 'SUCCESS',
          `the device refused the tunnelled command: ${handshake.error || handshake.status}`);
        assert.ok(handshake.data && handshake.data.length >= 33,
          `expected a key and a status back, got ${handshake.data && handshake.data.length} bytes`);
      });

    it('returns a usable X25519 public key', async ({ assert }) => {
      /*
       * The first 32 bytes are the device's half of a NaCl box handshake. It
       * being a real curve point is checkable without the private half: node
       * will refuse to import it otherwise.
       */
      const publicKey = handshake.data.subarray(0, 32);
      const imported = crypto.createPublicKey({
        key: Buffer.concat([X25519_SPKI_PREFIX, publicKey]),
        format: 'der',
        type: 'spki',
      });

      assert.equal(imported.asymmetricKeyType, 'x25519');
      assert.notEqual(publicKey.toString('hex'), '0'.repeat(64), 'an all-zero key is not a key');
    });

    it('agrees with the vendor interface about the firmware version',
      async ({ assert }) => {
        /*
         * The strongest thing this file can assert, and it needs two planes to
         * say it: the status text tunnelled out through a WebAuthn signature
         * matches what the vendor interface reported over RawHID2. Two
         * different transports, two different code paths inside the firmware,
         * one answer.
         */
        const text = handshake.data.subarray(32).toString('latin1').replace(/\0/g, '');

        assert.match(text, /^UNLOCKED/, `unexpected status text: ${JSON.stringify(text)}`);
        assert.match(text, /v\d+\.\d+\.\d+/, 'no firmware version in the tunnelled status');
        assert.equal(text, vendorVersion,
          'the tunnel and the vendor interface disagree about the firmware version');
      });

    it('generates a fresh key for every handshake', async ({ device, assert, log, signal }) => {
      /*
       * A real property, not a formality: if the device reused its handshake
       * key, every session that ever talked to it would share a secret.
       */
      let pressed = 0;
      const second = await tunnel.send(ctap, {
        cmd: okmsg.MSG.OKCONNECT,
        data: crypto.randomBytes(32),
      }, {
        timeoutMs: 30000,
        signal,
        onKeepAlive: async (status) => {
          if (status === 2 && !pressed) { pressed++; device.press(1); }
        },
      });

      assert.equal(second.status, 'SUCCESS');
      assert.notEqual(
        second.data.subarray(0, 32).toString('hex'),
        handshake.data.subarray(0, 32).toString('hex'),
        'the device reused its handshake key between sessions'
      );
    });

    it('rejects a command it does not implement, without the magic being ignored',
      async ({ assert, signal }) => {
        /*
         * 0x01 is not a vendor message. What matters is HOW it fails: a status
         * back means the firmware read the magic, recognised a tunnelled
         * request and rejected its contents. A CTAP2 NO_CREDENTIALS instead
         * would mean the magic was missed entirely and the assertion was
         * treated as an ordinary one - a framing bug wearing a device-error
         * costume.
         */
        const reply = await tunnel.send(ctap, { cmd: 0x01 }, { timeoutMs: 20000, signal });

        assert.notEqual(reply.status, 'SUCCESS', 'an unimplemented command should not succeed');
        assert.ok(reply.code > 0, `expected a CTAP1 error status, got ${reply.status}`);
      });
  });
