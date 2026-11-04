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
 *
 * THE ENCODING NOW COMES FROM node-onlykey-lib (protocol.ctap - one lib, any
 * GUI; the test CLI is a GUI): encodeRequest and the assertion decoding are
 * the library's, checked byte for byte identical before the switch. What
 * stays here: send(), which rides the kit's own CTAP2 layer; the default rpId
 * above (the library defaults to apps.crp.to - both are in its RP_IDS); and
 * the kit's status vocabulary - 'SUCCESS', 'INVALID_COMMAND' - which the tests
 * compare against, where the library says 'CTAP1_SUCCESS',
 * 'CTAP1_ERR_INVALID_COMMAND'. The prefix is stripped, nothing else.
 */
'use strict';

const crypto = require('crypto');
const { ctap } = require('node-onlykey-lib/protocol');

/* The kit's default - see the header. The library's is apps.crp.to. */
const RP_ID = 'apps.onlykey.io';

/* 8C 27 90 F6 - what marks a credential ID as a vendor request. */
const MAGIC = ctap.MAGIC;

/* The library's CTAP status names, without the CTAP1_ / CTAP2_ / ERR_ prefix:
 * the vocabulary the kit's tests compare against. */
const shortName = (name) => String(name).replace(/^CTAP[12]_(ERR_)?/, '');
const STATUS = Object.fromEntries(
  Object.entries(ctap.STATUS).map(([code, name]) => [code, shortName(name)]));

const toBuffer = (u8) => Buffer.from(u8.buffer, u8.byteOffset, u8.byteLength);

/** A vendor request as a credential ID (the library's encoder). */
function encodeRequest(req) {
  return toBuffer(ctap.encodeRequest(req));
}

/**
 * The vendor answer carried in an assertion's signature.
 * @returns {{status: string, code: number, data: Buffer|null,
 *            error: string|null, count: number|null}}
 */
function decodeResponse(assertion) {
  const r = ctap.decodeAssertion(assertion);
  return { ...r, status: shortName(r.status), data: r.data ? toBuffer(r.data) : null };
}

/**
 * Send one vendor request through a getAssertion on the kit's CTAP2 layer.
 * @param {object} ctap2  the kit's Ctap2 (anything with getAssertion)
 */
async function send(ctap2, req, opts = {}) {
  const credentialId = encodeRequest(req);

  const params = new Map([
    [1, opts.rpId || RP_ID],
    [2, opts.clientDataHash || crypto.randomBytes(32)],
    [3, [new Map([['id', credentialId], ['type', 'public-key']])]],
  ]);

  const assertion = await ctap2.getAssertion(params, opts);
  return decodeResponse(assertion);
}

module.exports = { encodeRequest, decodeResponse, send, RP_ID, MAGIC, STATUS };
