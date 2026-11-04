/*
 * backup.js - the OnlyKey backup file, parsed and reassembled in JS.
 *
 * The device types its backup out over the keyboard interface, one character
 * at a time, wrapped in PEM-style markers:
 *
 *   -----BEGIN ONLYKEY BACKUP-----
 *   <base64 line>
 *   <base64 line>
 *   --<base64 SHA256>
 *   -----END ONLYKEY BACKUP-----
 *
 * Restoring sends the same bytes back as OKRESTORE packets. Both halves are
 * done in JS rather than shelled out to python-onlykey's restore_from_backup(),
 * for the same reason as the rest of the client protocol: section 1 has to
 * reach the device without a kernel device node, and python-onlykey finds it
 * through hidapi. The JS now comes from node-onlykey-lib (one lib, any GUI -
 * the test CLI is a GUI): device.parsers parses and verifies, device.chunker
 * builds the restore packets. Checked before the switch: restore frames byte
 * for byte identical at 1, 56, 57, 58, 114, 200 and 1558 bytes, and parse()
 * identical on complete, truncated, hashless and corrupted backups.
 *
 * The hash is the interesting part, and the reason this file is worth having
 * on its own. It is not a hash OF the backup - it is a CHAIN: starting from 32
 * zero bytes, each data line folds in as sha256(previous || line). Computing
 * that here and comparing it against the line the device typed is a real
 * pure-JS crypto check against the device's own arithmetic, and it is what
 * says the keystrokes were captured without a dropped character - which,
 * over 600 keystrokes of a paced HID stream, is not a given.
 */
'use strict';

const { parsers, chunker } = require('node-onlykey-lib/device');

const BEGIN = parsers.BACKUP_BEGIN;   // '-----BEGIN ONLYKEY BACKUP-----'
const END = parsers.BACKUP_END;       // '-----END ONLYKEY BACKUP-----'

/* python-onlykey sends 57 data bytes per packet: 64 - 4 header - 1 message
 * type - 1 length byte, rounded to what its own client uses. */
const RESTORE_CHUNK = chunker.CHUNK_BYTES;

const hexToBuffer = (hex) => Buffer.from(hex, 'hex');

/**
 * Parse a captured backup.
 * @returns {{data: Buffer, computedHash: Buffer, storedHash: Buffer|null,
 *            lines: number, complete: boolean}}
 *   The library computes the chain and decodes the data; what stays here is the
 *   shape the tests read - a capture that lost its END marker, or every data
 *   line, is still reported rather than thrown.
 */
function parse(text) {
  const complete = text.includes(BEGIN) && text.includes(END);
  const lines = String(text).split('\n').map((l) => l.trim())
    .filter((l) => l && !l.startsWith('--')).length;

  let data = Buffer.alloc(0);
  try { data = hexToBuffer(parsers.parseBackup(text)); } catch { /* no data lines */ }

  const v = parsers.verifyBackup(text);
  return {
    data,
    computedHash: hexToBuffer(v.digest),
    storedHash: v.expected ? hexToBuffer(v.expected) : null,
    lines,
    complete,
  };
}

/** The chained hash the device typed matches the one computed over its lines. */
function verify(parsed) {
  return !!(parsed.storedHash &&
    parsed.storedHash.length === 32 &&
    parsed.computedHash.equals(parsed.storedHash));
}

/**
 * The OKRESTORE payloads for a backup's bytes: [length-or-0xFF][up to 57
 * bytes] each, 0xFF meaning "more follow" - device.chunker's hexPackets, in
 * the payload form the kit hands to okmsg.build().
 */
function toRestorePackets(data) {
  return chunker.hexPackets(Buffer.from(data).toString('hex'))
    .map((p) => Buffer.concat([Buffer.from([p.header]), Buffer.from(p.data)]));
}

module.exports = { parse, verify, toRestorePackets, BEGIN, END, RESTORE_CHUNK };
