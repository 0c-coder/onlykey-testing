/*
 * tunnel.js - vendor commands smuggled through a WebAuthn assertion.
 *
 * The third protocol plane, and the one the web app actually uses. A browser
 * cannot reach OnlyKey's vendor interface: WebHID would prompt, and the vendor
 * RawHID interface is not exposed to pages at all. So the firmware accepts a
 * vendor request hidden somewhere a page CAN put arbitrary bytes - the
 * `allowList` credential ID of an ordinary authenticatorGetAssertion - and
 * answers in the one field of the response that carries arbitrary bytes back,
 * the assertion's SIGNATURE.
 *
 * Ported from onlykey.github.io/src/onlykey-fido2/onlykey/onlykey-api.js
 * (encode_ctaphid_request_as_keyhandle / decode_ctaphid_response_from_signature)
 * by way of onlykey-alpha-testing/lib/fido2/ctaphid.js, which is the version
 * already proven against hardware. What changes here is the transport: the old
 * one needed a real WebAuthn client over hidapi, and this rides the kit's own
 * CTAP2 layer, so it works on the in-process bus and stays in section 1.
 *
 * The credential ID layout, which the firmware's is_extension_request() looks
 * for:
 *
 *   [0]     command        a vendor message id (OKCONNECT, OKGETPUBKEY, ...)
 *   [1..3]  opt1, opt2, opt3
 *   [4..7]  8C 27 90 F6    the magic that marks this as a vendor request
 *   [8]     0
 *   [9]     payload length
 *   [10..]  payload, zero-padded so the whole thing is at least 26 bytes
 *
 * The rpId is not a free choice, for two independent reasons:
 *
 *   ADMISSION. webcryptcheck() (fido2/device.cpp) admits exactly two origins -
 *   apps.crp.to and apps.onlykey.io - and refuses the extension to anything
 *   else. A DEBUG build hides this: it returns "trust all" before the table is
 *   read, which is why this default used to be the staging site and nothing
 *   noticed. On a production-control-flow build that default was refused on
 *   the first request.
 *
 *   DERIVATION does not depend on it. Web-derived P-256 / Curve25519 / NaCl
 *   keys (okcrypto_hkdf v2, "onlykey/derive/ecc/v2") and derived X-Wing
 *   (seed/v3) have no origin in them, so every admitted rpId gets the same key
 *   for a label. Until 2026-09-22 the ECC keys were bound to the rpId;
 *   01-protocol/30-derive-no-origin pins that they are not.
 *
 * So the default is a production origin. apps.onlykey.io rather than
 * apps.crp.to because it is the site new firmware routes to.
 */
'use strict';

const crypto = require('crypto');

const MAGIC = [0x8C, 0x27, 0x90, 0xF6];
const HEADER = 10;
const MIN_DATA = 16;             // is_extension_request wants at least this much

/** A production origin: admitted by webcryptcheck() on every build. */
const RP_ID = 'apps.onlykey.io';

/* CTAP1/U2F status codes, which is what comes back in the signature's first
 * byte - not the CTAP2 codes the surrounding assertion uses. */
const STATUS = {
  0x00: 'SUCCESS',
  0x01: 'INVALID_COMMAND',
  0x02: 'INVALID_PARAMETER',
  0x03: 'INVALID_LENGTH',
  0x04: 'INVALID_SEQ',
  0x05: 'TIMEOUT',
  0x06: 'CHANNEL_BUSY',
  0x0A: 'LOCK_REQUIRED',
  0x0B: 'INVALID_CHANNEL',
};

/**
 * Build the fabricated credential ID.
 * @param {object} req {cmd, opt1, opt2, opt3, data}
 * @returns {Buffer}
 */
function encodeRequest({ cmd, opt1 = 0, opt2 = 0, opt3 = 0, data = Buffer.alloc(0) }) {
  const payload = Buffer.from(data);
  if (HEADER + payload.length > 255) {
    throw new RangeError(`tunnel payload is ${payload.length} bytes; a credential ID holds 245`);
  }

  const pad = payload.length < MIN_DATA ? MIN_DATA - payload.length : 0;
  const out = Buffer.alloc(HEADER + payload.length + pad);

  out[0] = cmd & 0xFF;
  out[1] = opt1 & 0xFF;
  out[2] = opt2 & 0xFF;
  out[3] = opt3 & 0xFF;
  MAGIC.forEach((b, i) => { out[4 + i] = b; });
  out[8] = 0;
  out[9] = payload.length & 0xFF;   // the LENGTH, not the padded size
  payload.copy(out, HEADER);

  return out;
}

/**
 * Read the answer back out of an assertion.
 * @param {object} assertion the decoded CTAP2 getAssertion response (a Map)
 * @returns {{status:string, code:number, data:Buffer|null, error:string|null, count:number}}
 */
function decodeResponse(assertion) {
  const authData = assertion.get(2);
  const signature = assertion.get(3);
  if (!signature || !signature.length) throw new Error('the assertion carried no signature');

  const code = signature[0];
  const status = STATUS[code] || `0x${code.toString(16)}`;
  const data = signature.length > 1 ? signature.subarray(1) : null;

  /*
   * A short ASCII "Error ..." in the data is the device talking, not binary
   * payload - the same convention the vendor interface uses on its own wire.
   */
  let error = null;
  if (data && data.length < 73 && data.subarray(0, 6).toString('latin1') === 'Error ') {
    const end = data.indexOf(0x00);
    error = data.subarray(0, end === -1 ? data.length : end).toString('latin1');
  }

  return {
    status,
    code,
    data,
    error,
    /* The authenticator's signature counter, which the reference client reads
     * for its own bookkeeping. */
    count: authData && authData.length >= 37 ? authData.readUInt32BE(33) : null,
  };
}

/**
 * Send one vendor command through the tunnel.
 *
 * @param {object} ctap  a connected Ctap2
 * @param {object} req   {cmd, opt1, opt2, opt3, data}
 * @param {object} [opts] {rpId, timeoutMs, onKeepAlive, signal}
 */
async function send(ctap, req, opts = {}) {
  const credentialId = encodeRequest(req);

  const params = new Map([
    [1, opts.rpId || RP_ID],
    [2, opts.clientDataHash || crypto.randomBytes(32)],
    [3, [new Map([['id', credentialId], ['type', 'public-key']])]],
  ]);

  const assertion = await ctap.getAssertion(params, opts);
  return decodeResponse(assertion);
}

module.exports = { encodeRequest, decodeResponse, send, RP_ID, MAGIC, STATUS };
