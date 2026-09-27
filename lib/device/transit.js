/*
 * transit.js - the WebAuthn tunnel's data-in-transit encryption.
 *
 * `lib/device/tunnel.js` frames a vendor command as a fabricated credential ID
 * and reads the answer out of an assertion's signature. That is enough for
 * OKCONNECT, which is how `12-webauthn-tunnel` gets by without this file. It is
 * NOT enough for any other tunnelled command: `bridge_to_onlykey()` runs
 * `okcrypto_aes_crypto_box(client_handle, handle_len, true)` over the whole
 * payload before it looks at the command, so an unencrypted request is
 * decrypted into noise and dispatched as noise.
 *
 * So this is the second half of the client, and it is written here rather than
 * borrowed from the shipped library for the reason section 1 exists: a test that
 * needs `onlykey-fido2` needs `webapp-lib` and stops being hardware-capable.
 * `03-xwing-derive` takes the other route deliberately - it lets the library
 * send the option bytes - and that is the right call there because the SUBJECT
 * is the library. Here the subject is the firmware's chunking, so the client has
 * to be ours.
 *
 * THE HANDSHAKE, from `ok_extension.cpp`'s OKCONNECT branch:
 *
 *   1. The client sends its own X25519 public key inside a 43-byte prefix -
 *      `set_time()` reads a big-endian epoch at payload[5..8], the public key is
 *      at payload[9..40], then a browser byte and an OS byte. The 43 is
 *      confirmed by the derive path, which reads its own argument at
 *      `client_handle + 43`.
 *   2. The device generates a keypair with `crypto_box_keypair()` and answers
 *      with its 32-byte public key followed by its model string.
 *   3. Both sides compute `crypto_box_beforenm()` and SHA256 it:
 *
 *          transit_key = SHA256( HSalsa20( X25519(sk, pk), 16 zero bytes ) )
 *
 *      That is NaCl's beforenm, NOT the raw X25519 output - which is the one
 *      thing here that node:crypto cannot do on its own, and the reason this
 *      file needs `@noble/ciphers`' `hsalsa`.
 *
 * THE BOX IS TRANSIT v2, AND v1 IS GONE FROM THE FIRMWARE. What used to be here
 * - `okcrypto_aes_crypto_box()`, AES-256-GCM under a TWELVE-BYTE ZERO IV with
 * the tag check commented out - was a raw keystream, reused for every message of
 * a session, with no authentication. `okcrypto_transit_seal()` and
 * `okcrypto_transit_open()` replaced it (okcrypto.cpp), and the wire format is:
 *
 *     [counter big-endian(4)][ciphertext(n)][tag(16)]
 *     IV = [dir(1)][counter big-endian(4)][zero(7)]
 *     dir 0 = device -> host,  dir 1 = host -> device
 *
 * Three things follow that the v1 client did not have to think about, and each
 * of them is a way to get an unattributable timeout rather than a clean error:
 *
 *   - THE COUNTER IS STATE. It travels in the clear so neither side tracks the
 *     other's, but each side must not repeat its own under one key - so a
 *     session object holds it, and `session()` is called wherever the handshake
 *     is, because the key and the counter are established together.
 *   - IT IS NO LONGER LENGTH-PRESERVING. A sealed frame is 20 bytes longer than
 *     its plaintext, at both ends. A request chunk therefore holds 171 plaintext
 *     bytes, not 228: a credential ID carries 245 payload bytes, 245 - 20 = 225,
 *     and every chunk but the message's last must be a whole number of the
 *     firmware's 57-byte packets, so 171 = 3 * 57. And a response grows the same
 *     way, which moves the MAX_LARGE_RESP_CHUNK boundary: a 512-byte RSA-4096
 *     signature is staged as 532 bytes and served in TWO chunks.
 *   - A BAD TAG IS A DISCARD, NOT A CORRUPTION. `okcrypto_transit_open()` wipes
 *     the frame and returns -1, and ok_extension.cpp then dispatches nothing -
 *     not the command, not the slot, not one chunk. From the host that looks
 *     like the device ignoring the request entirely.
 *
 * `open()` here throws on a bad tag rather than returning noise, for the same
 * reason: a caller that silently accepted it would report a chunking failure.
 *
 * AND THE SUNDAE LAYER DOES NOT APPLY, which is worth writing down because
 * `okcrypto_aes_gcm_encrypt2()` looks like it does. Its first statement is
 * `okcrypto_split_sundae(state, iv1, len, function1, s)` under `#ifdef
 * FACTORYKEYS`, which IS defined - but `split_sundae()` opens with
 * `if ((*certified_hw != 1 && *certified_hw != 3) || s == false) return;` and the
 * box passes `s = false` both ways. So the extra ChaCha/Salsa layers are skipped
 * for transit and only the AES-GCM keystream remains.
 */
'use strict';

const crypto = require('crypto');

const SIGMA = 'expand 32-byte k';
const PREFIX = 43;              // the OKCONNECT payload prefix, before any data
const CTR_LEN = 4;              // OKCRYPTO_TRANSIT_CTR_LEN
const TAG_LEN = 16;             // OKCRYPTO_TRANSIT_TAG_LEN
const OVERHEAD = CTR_LEN + TAG_LEN;   // OKCRYPTO_TRANSIT_OVERHEAD
const DIR_OUT = 0;              // device -> host
const DIR_IN = 1;               // host -> device

/* Probe rather than require at load: @noble/ciphers is optional here, the same
 * way lib/age-pqc.js treats its own dependencies, so a file that needs this
 * skips with a reason instead of failing to load. */
function probe() {
  try {
    require('@noble/ciphers/salsa.js');
    return { ok: true };
  } catch (err) {
    return {
      ok: false,
      why: '@noble/ciphers is not installed - the tunnel transit box needs hsalsa ' +
        `for NaCl's crypto_box_beforenm (${err.code || err.message})`,
    };
  }
}

const le = (buf) => new Uint32Array(
  Uint8Array.from(buf).buffer, 0, buf.length / 4,
);

/**
 * NaCl's `crypto_box_beforenm`: HSalsa20 over the X25519 shared point.
 * @param {Buffer} theirPublic 32 raw bytes
 * @param {crypto.KeyObject} ourPrivate an x25519 private key
 * @returns {Buffer} 32 bytes
 */
function beforenm(theirPublic, ourPrivate) {
  const { hsalsa } = require('@noble/ciphers/salsa.js');

  const shared = crypto.diffieHellman({
    privateKey: ourPrivate,
    publicKey: crypto.createPublicKey({
      key: Buffer.concat([Buffer.from('302a300506032b656e032100', 'hex'), theirPublic]),
      format: 'der',
      type: 'spki',
    }),
  });

  const out = new Uint32Array(8);
  hsalsa(
    le(Buffer.from(SIGMA, 'latin1')),
    le(shared),
    le(Buffer.alloc(16)),
    out,
  );
  return Buffer.from(out.buffer, out.byteOffset, 32);
}

/**
 * The AES key both sides use, from the device's public half and our private one.
 */
function transitKey(devicePublic, ourPrivate) {
  return crypto.createHash('sha256').update(beforenm(devicePublic, ourPrivate)).digest();
}

/** An X25519 pair, with the public half as the 32 raw bytes the wire wants. */
function keypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
  return {
    privateKey,
    publicKey: publicKey.export({ format: 'der', type: 'spki' }).subarray(-32),
  };
}

/**
 * The 43-byte OKCONNECT payload.
 * @param {Buffer} publicKey our 32 raw bytes
 */
function connectPayload(publicKey, { when = Date.now(), browser = 0x63, os = 0x6C } = {}) {
  const out = Buffer.alloc(PREFIX);
  out.writeUInt32BE(Math.floor(when / 1000), 5);
  publicKey.copy(out, 9);
  out[41] = browser;
  out[42] = os;
  return out;
}

/**
 * A transit session: the key, plus the host's outbound counter.
 *
 * Held together because they are established together - a derive request is
 * itself an OKCONNECT and replaces the key mid-session, and a counter carried
 * across that rekey is the one failure this shape makes impossible to write.
 */
function session(key) {
  return { key, ctr: 0 };
}

/** `[dir][counter BE(4)][zero(7)]`, which is okcrypto_transit_iv(). */
function transitIv(dir, ctr) {
  const iv = Buffer.alloc(12);
  iv[0] = dir;
  iv.writeUInt32BE(ctr >>> 0, 1);
  return iv;
}

/**
 * Seal a host -> device payload and advance the session counter.
 * @returns {Buffer} `[counter(4)][ciphertext(n)][tag(16)]`
 */
function seal(sess, data) {
  const ctr = sess.ctr++;
  const c = crypto.createCipheriv('aes-256-gcm', sess.key, transitIv(DIR_IN, ctr));
  const ct = Buffer.concat([c.update(Buffer.from(data)), c.final()]);
  const head = Buffer.alloc(CTR_LEN);
  head.writeUInt32BE(ctr >>> 0, 0);
  return Buffer.concat([head, ct, c.getAuthTag()]);
}

/**
 * Open a device -> host frame. Throws if the tag does not check, which is the
 * point - see the header.
 * @param {Buffer|{key: Buffer}} key the transit key, or the session holding it
 */
function open(key, frame) {
  const k = Buffer.isBuffer(key) ? key : key.key;
  if (frame.length < OVERHEAD) {
    throw new RangeError(
      `a transit frame is at least ${OVERHEAD} bytes of framing; got ${frame.length}`);
  }
  const ptlen = frame.length - OVERHEAD;
  const ctr = frame.readUInt32BE(0);
  const d = crypto.createDecipheriv('aes-256-gcm', k, transitIv(DIR_OUT, ctr));
  d.setAuthTag(frame.subarray(CTR_LEN + ptlen));
  return Buffer.concat([d.update(frame.subarray(CTR_LEN, CTR_LEN + ptlen)), d.final()]);
}

/**
 * Check the beforenm implementation against NaCl's own published vector before
 * trusting it against a device.
 *
 * These are the alice/bob keys from the NaCl documentation, whose beforenm value
 * is the `k` every NaCl box test uses. Getting this wrong would produce a
 * plausible-looking 32 bytes and a device that answers noise, which is a much
 * worse failure to debug than an assertion here.
 *
 * @returns {{ok: boolean, got: string, want: string}}
 */
function selfTest() {
  const aliceSk = Buffer.from(
    '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a', 'hex');
  const bobPk = Buffer.from(
    'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f', 'hex');
  const want = '1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389';

  const privateKey = crypto.createPrivateKey({
    key: Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), aliceSk]),
    format: 'der',
    type: 'pkcs8',
  });
  const got = beforenm(bobPk, privateKey).toString('hex');
  return { ok: got === want, got, want };
}

module.exports = {
  probe, keypair, beforenm, transitKey, connectPayload, selfTest,
  session, seal, open, PREFIX, OVERHEAD, CTR_LEN, TAG_LEN,
};
