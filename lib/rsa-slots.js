'use strict';
/*
 * RSA SLOTS FROM A HOST - the helpers 01-protocol/19-rsa-keys and the patch tests that load an RSA key share (RC fix
 * 0013's: a wiped RSA slot reads as empty). Moved out of 19 as they were (2026-10-28), so one test and a patch's test
 * load, read and refuse exactly the same way.
 */
const crypto = require('crypto');
const { IFACE, okmsg } = require('./device');
const { PINS } = require('./config');
const pqc = require('./pqc');

const REPORT = 64;
const CHUNK = 57;                       // payload bytes per report, buffer[7..63]

/* The low nibble of the type byte is the modulus size in 128-byte units. */
const RSA_2048 = 2;
const MODULUS = RSA_2048 * 128;         // 256 bytes of N, and of P||Q
const FEATURE_DECRYPT = 32;             // is_bit_set(features, 5)
const FEATURE_SIGN = 64;                // is_bit_set(features, 6)

/*
 * The slots onlykey-pgp.js hardcodes. `slotid()` returns 2 for OKSIGN and 1 for
 * everything else, +100 only when the key is ECC - so the classic PGP pages
 * reach RSA slot 1 to decrypt and RSA slot 2 to sign, and 18-gui-encrypt-decrypt
 * needs exactly this pair. A fresh fixture image per file, so they are reused
 * freely between tests.
 */
const SLOT_DECRYPT = 1;
const SLOT_SIGN = 2;
const SLOT_EMPTY = 4;

const FIELD_STORED_CHALLENGE = 22;      // PGPCHALENGEMODE -> stored_key_challenge_mode

/* done_process_packets()'s last line before it waits for a finger. */
const PRIMED = /Encrypted Buffer/g;

/**
 * An RSA-2048 keypair, as the two things the device and the host each need.
 *
 * `p` and `q` are exactly 128 bytes each for a 2048-bit key - OpenSSL sets the
 * top bit of both primes - so P||Q is 256 and needs no padding. `n` is
 * OpenSSL's own modulus, which is what makes it an oracle rather than an echo:
 * the device computes N itself, from P and Q, with mbedtls.
 */
function keypair() {
  const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = privateKey.export({ format: 'jwk' });
  const p = Buffer.from(jwk.p, 'base64url');
  const q = Buffer.from(jwk.q, 'base64url');
  return { privateKey, jwk, p, q, pq: Buffer.concat([p, q]), n: Buffer.from(jwk.n, 'base64url') };
}

/** A verifier for a modulus the DEVICE published, with the E the firmware assumes. */
const publicFromModulus = (n) => crypto.createPublicKey({
  key: { kty: 'RSA', n: n.toString('base64url'), e: 'AQAB' },
  format: 'jwk',
});

/**
 * Read `want` bytes off the vendor interface as consecutive reports.
 *
 * Reports are counted as well as bytes, for the reason 13-large-response
 * gives: a short byte count is a truncated response and a changed report count
 * is changed framing, and they are different news.
 */
async function collect(device, since, want, { signal, timeoutMs = 30000 }) {
  const expected = Math.ceil(want / REPORT);
  const deadline = Date.now() + timeoutMs;

  let reports = device.reportsSince(IFACE.VENDOR, since);
  while (reports.length < expected && Date.now() < deadline) {
    await device.sleep(100, { signal });
    reports = device.reportsSince(IFACE.VENDOR, since);
  }
  return { reports, bytes: Buffer.concat(reports).subarray(0, want) };
}

/**
 * Put keys in RSA slots, and leave the device where they can be USED.
 *
 * One config-mode session for however many keys are asked for: OKSETPRIV needs
 * config mode, and every message that uses a key needs to be out of it -
 * OKSIGN and OKDECRYPT are not among the messages config mode admits and
 * OKGETPUBKEY is refused outright there, printing to the console with no
 * vendor reply at all.
 *
 * `readyForKeygen()` restarts first, which is also what guarantees the
 * firmware's `packet_buffer_offset` starts at zero. rsa_priv_flash() counts
 * its five reports with that global and nothing resets it on entry, so a
 * partial write left by anything earlier would land this key at an offset.
 */
async function loadKeys(device, keys, { signal, assert }) {
  await pqc.readyForKeygen(device, { signal });

  let since = device.mark(IFACE.VENDOR);
  device.sendVendor({
    msg: okmsg.MSG.OKSETSLOT,
    slot: 1,
    field: FIELD_STORED_CHALLENGE,
    /* THE BYTE 1, not the character. See the header. */
    payload: Buffer.from([1]),
  });
  const modeAck = await device.waitHid(IFACE.VENDOR,
    { since, match: /Success|Error/, timeoutMs: 8000, signal });
  assert.ok(!/^Error/.test(okmsg.text(modeAck)),
    `setting the stored-key challenge mode failed: ${okmsg.text(modeAck)}`);

  for (const key of keys) {
    since = device.mark(IFACE.VENDOR);
    for (let i = 0; i < key.pq.length; i += CHUNK) {
      device.sendVendor({
        msg: okmsg.MSG.OKSETPRIV,
        slot: key.slot,
        /* The TYPE BYTE on every report, not a continuation marker. */
        field: key.typeByte,
        payload: key.pq.subarray(i, i + CHUNK),
      });
      await device.sleep(150, { signal });
    }

    /* No confirmation for an RSA load: rsa_priv_flash() never calls
     * process_packets(), unlike the PQC keygens. It answers when the fifth
     * report tips its offset past the key size. */
    const ack = await device.waitHid(IFACE.VENDOR,
      { since, match: /Successfully|Error/, timeoutMs: 20000, signal });
    const said = okmsg.text(ack).trim();
    assert.ok(!/^Error/.test(said), `storing the RSA key in slot ${key.slot} failed: ${said}`);
    assert.match(said, /Successfully set RSA Key/,
      `expected the RSA acknowledgement, got: ${said}`);
  }

  await device.restart({ signal });
  await device.ensureUnlocked(PINS.primary, { signal });
}

/**
 * OKGETPUBKEY on an RSA slot.
 *
 * buffer[6] MUST be zero: okcrypto_getpubkey() takes the RSA branch on
 * `buffer[5] < 5 && !buffer[6]`, and any other field value falls through to
 * the ECC branch, which for slot 1..4 reads an ECC slot that does not exist.
 */
async function modulus(device, slot, { signal }) {
  const since = device.mark(IFACE.VENDOR);
  device.sendVendor({ msg: okmsg.MSG.OKGETPUBKEY, slot, field: 0 });
  return collect(device, since, MODULUS, { signal });
}

/**
 * Send an operation payload with process_packets()' framing, answer the one
 * press the challenge mode leaves, and read the answer.
 */
async function operate(device, msg, slot, payload, want, { signal, assert }) {
  const primed = device.log.count(PRIMED);
  const since = device.mark(IFACE.VENDOR);

  for (let i = 0; i < payload.length; i += CHUNK) {
    const chunk = payload.subarray(i, i + CHUNK);
    device.sendVendor({
      msg, slot, field: chunk.length < CHUNK ? chunk.length : 0xFF, payload: chunk,
    });
    await device.sleep(20, { signal });
  }

  /* SURFACE: console, and only for the timing - a press before the fade ends
   * is discarded and the device tells a client nothing about the window. */
  await device.log.waitForCount(PRIMED, primed + 1, { timeoutMs: 20000, signal });
  device.press(1);

  const { reports, bytes } = await collect(device, since, want, { signal });
  assert.ok(!/^Error/.test(okmsg.text(bytes.subarray(0, REPORT))),
    `the device refused: ${okmsg.text(bytes.subarray(0, REPORT))}`);
  return { reports, bytes };
}

/** The device's reply to a message it will refuse before priming anything. */
async function refusal(device, spec, { signal, timeoutMs = 15000 }) {
  const primed = device.log.count(PRIMED);
  const since = device.mark(IFACE.VENDOR);
  device.sendVendor(spec);
  const reply = await device.waitHid(IFACE.VENDOR, { since, match: /Error/, timeoutMs, signal });
  return { said: okmsg.text(reply).trim(), primedBefore: primed };
}

module.exports = {
  REPORT, CHUNK, RSA_2048, MODULUS, FEATURE_DECRYPT, FEATURE_SIGN, SLOT_DECRYPT, SLOT_SIGN, SLOT_EMPTY,
  FIELD_STORED_CHALLENGE, PRIMED,
  keypair, publicFromModulus, collect, loadKeys, modulus, operate, refusal,
};
