/*
 * Web-derived ECC keys have no origin in them.
 *
 * DECIDED 2026-09-22: web-and-agent derived P-256 / secp256k1 / X25519 keys
 * follow derived X-Wing and stop mixing in the browser origin. okcrypto_hkdf()
 * v1 used SHA256(rpId) - scanned out of ctap_buffer+4 - as the HKDF info, so
 * apps.crp.to and apps.onlykey.io derived different keys for one label. v2 is
 *
 *     PRK = HMAC(salt = [0 | label tag], IKM = slot-128 key)
 *     key = HKDF-Expand(PRK, "onlykey/derive/ecc/v2", 32)
 *
 * This file pins the decision from outside: the same label, asked for from both
 * trusted origins, is the same public key, byte for byte - and a different
 * label is not, which is the control that the comparison can tell keys apart.
 *
 * Both origins are in webcryptcheck()'s table, so this runs unchanged on a
 * DEBUG build and on an enforcing one. DERIVE_PUBLIC_KEY needs no touch (it is
 * public data), so nothing here presses a button.
 *
 * SURFACES - FIDO only: a derive request is an OKCONNECT with opt1 = 1.
 */
'use strict';

const crypto = require('crypto');

const { describe, it } = require('../../lib/harness');
const { okmsg } = require('../../lib/device');
const { Ctap2 } = require('../../lib/device/ctap2');
const tunnel = require('../../lib/device/tunnel');
const transit = require('../../lib/device/transit');
const { PINS } = require('../../lib/config');

const ORIGINS = ['apps.crp.to', 'apps.onlykey.io'];
const DERIVE_PUBLIC_KEY = 1;

/* Wire keytypes (the firmware adds one): 0 -> X25519, 1 -> P-256, 2 -> secp256k1. */
const TYPES = [
  { name: 'X25519', wire: 0, size: 32 },
  { name: 'P-256', wire: 1, size: 65 },
  { name: 'secp256k1', wire: 2, size: 65 },
];

/** SHA256(utf8(label)) - the tag the web app sends. */
const labelTag = (label) => crypto.createHash('sha256').update(label, 'utf8').digest();

describe('web-derived ECC keys do not depend on the origin', {
  state: 'initialized',
  requires: ['crypto'],
  timeoutMs: 300000,
}, () => {
  /**
   * DERIVE_PUBLIC_KEY from `rpId`. The reply is
   * [transit pub(32) | "UNLOCKEDv…" + model byte + NUL | derived public key],
   * sent in the clear (opt3 = 0), so the key starts one past the NUL.
   */
  async function derivePub(ctap, rpId, label, type, { signal }) {
    const ours = transit.keypair();
    const data = Buffer.concat([transit.connectPayload(ours.publicKey), labelTag(label)]);
    const reply = await tunnel.send(ctap, {
      cmd: okmsg.MSG.OKCONNECT, opt1: DERIVE_PUBLIC_KEY, opt2: type.wire, opt3: 0, data,
    }, { rpId, timeoutMs: 30000, signal });
    if (!reply || !reply.data) throw new Error(`${rpId}: no answer (${reply && (reply.error || reply.status)})`);
    const nul = reply.data.indexOf(0, 32);
    if (nul < 0) throw new Error(`${rpId}: no model string in the reply`);
    const key = reply.data.subarray(nul + 1, nul + 1 + type.size);
    if (key.length !== type.size) {
      throw new Error(`${rpId}: ${type.name} key came back ${key.length} bytes, not ${type.size}`);
    }
    return key;
  }

  for (const type of TYPES) {
    it(`${type.name}: one label is one key on both trusted origins`,
      async ({ device, assert, signal, log }) => {
        await device.ensureUnlocked(PINS.primary, { signal });
        const ctap = new Ctap2(device, { signal });
        await ctap.init();

        const keys = [];
        for (const rpId of ORIGINS) {
          keys.push(await derivePub(ctap, rpId, 'no-origin', type, { signal }));
        }
        const other = await derivePub(ctap, ORIGINS[1], 'no-origin, another label', type, { signal });
        log(`${ORIGINS[0]} ${keys[0].toString('hex').slice(0, 24)}...`);
        log(`${ORIGINS[1]} ${keys[1].toString('hex').slice(0, 24)}...`);

        assert.control('a different label derives a different key, so the comparison ' +
          'below can tell keys apart', !keys[1].equals(other));
        assert.ok(!keys[0].equals(Buffer.alloc(type.size)), 'the derived key is all zeros');
        assert.bytes(keys[0], keys[1],
          `the ${type.name} key for one label differs between ${ORIGINS[0]} and ${ORIGINS[1]} - ` +
          'the origin is still in the derivation');
      });
  }
});
