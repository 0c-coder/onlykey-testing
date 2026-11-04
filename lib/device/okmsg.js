/*
 * okmsg.js - the OnlyKey client protocol, from node-onlykey-lib.
 *
 * This is the vendor RawHID2 interface (usage page 0xFFAB, emulator iface 2) -
 * the one the app, the CLI and lib-agent all speak. It was reimplemented here
 * rather than shelled out to python-onlykey because section 1's admission test
 * is "does this reach the device without a kernel device node", and every real
 * client finds the device through hidapi. That still holds; the implementation
 * now comes from node-onlykey-lib (one lib, any GUI - the test CLI is a GUI),
 * whose okmsg was ported from this file. Checked before the switch: the 18
 * message ids, PIN_KIND, the header, build() on every shape the tests use,
 * setTimePayload() and text() all produce identical bytes.
 *
 * Frame layout, from the firmware's own dispatch (okcore.cpp: recv_buffer[4] is
 * the message type) and confirmed against python-onlykey's send_message():
 *
 *   0..3  FF FF FF FF     header
 *   4     message type
 *   5     slot id         (only for messages that take one)
 *   6     field id        (only for OKSETSLOT-style messages)
 *   7..   payload
 *   pad to 64 with 0x00
 *
 * There is deliberately NO report ID here. The proven hardware client always
 * prepends a zero byte, but the emulator's delivery path pads to 64 and does
 * not strip a leading report ID - so identical test code would put different
 * bytes on the wire in each mode. Payloads carry no report ID; the hardware
 * adapter adds it.
 *
 * The one thing this file adds is shape: the library's build() returns a
 * Uint8Array and the tests call Buffer methods on reports, so build() returns
 * a Buffer view over the library's bytes. setTimePayload() is a plain byte
 * array in both, and is passed through.
 */
'use strict';

const { msg, okmsg } = require('node-onlykey-lib/protocol');

const toBuffer = (u8) => Buffer.from(u8.buffer, u8.byteOffset, u8.byteLength);

/* okcore.h: #define OKxxx (TYPE_INIT | 0xNN), TYPE_INIT = 0x80. The library's
 * table is a superset of the 18 this file used to define, same values. */
const { MSG, PIN_KIND } = msg;
const { REPORT_SIZE, HEADER, text, setTimePayload } = okmsg;

/**
 * Build one 64-byte report.
 * @param {object} spec  { msg, slot?, field?, payload? } - payload may be a
 *                       Buffer, a byte array, or a string (taken as latin1)
 * @returns {Buffer}
 */
function build(spec) {
  return toBuffer(okmsg.build(spec));
}

module.exports = { MSG, PIN_KIND, HEADER, REPORT_SIZE, build, setTimePayload, text };
