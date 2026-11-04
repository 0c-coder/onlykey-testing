/*
 * cbor.js - CTAP2 canonical CBOR, from node-onlykey-lib.
 *
 * ONE LIB, ANY GUI - AND THE TEST KIT IS A GUI. This used to be the kit's own
 * implementation, kept here on purpose as a readable test oracle rather than a
 * dependency. The library's cbor was ported from it byte for byte, and the
 * kit's outputs are now FROZEN in node-onlykey-lib's
 * test/vectors/kit-reference.json (from this repo at adac782, the last commit
 * with the original), so the oracle survives the switch: the library is
 * checked against what this file used to produce, on every `npm test` there.
 * The original is in this repo's history.
 *
 * What stays here is the one difference in shape. The library works in
 * Uint8Array; the kit's tests call Buffer methods on what they get back
 * (.toString('hex'), .equals). So encode() returns a Buffer, and decoded byte
 * strings come back as Buffer VIEWS over the same memory - no copy, same
 * bytes. Input can be either; a Buffer is a Uint8Array.
 *
 * Canonical ordering still matters and is still the library's job: the
 * authenticator hashes some of what it receives, so two encodings of the same
 * map are not interchangeable. Keys sort by encoded length first, then
 * bytewise.
 */
'use strict';

const lib = require('node-onlykey-lib/protocol').cbor;

const toBuffer = (u8) => Buffer.from(u8.buffer, u8.byteOffset, u8.byteLength);

/** Uint8Array -> Buffer view, through maps (keys too) and arrays. */
function buffers(value) {
  if (value instanceof Uint8Array && !Buffer.isBuffer(value)) return toBuffer(value);
  if (value instanceof Map) {
    const out = new Map();
    for (const [k, v] of value) out.set(buffers(k), buffers(v));
    return out;
  }
  if (Array.isArray(value)) return value.map(buffers);
  return value;
}

function encode(value) {
  return toBuffer(lib.encode(value));
}

function decode(buf) {
  return buffers(lib.decode(buf));
}

function decodeFirst(buf, pos = 0) {
  const r = lib.decodeFirst(buf, pos);
  return { ...r, value: buffers(r.value) };
}

/* buffers() too: ctap2.js hands the library's decoded CTAP replies through it. */
module.exports = { encode, decode, decodeFirst, plain: lib.plain, buffers };
