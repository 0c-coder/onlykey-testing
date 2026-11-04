/*
 * ctap2.js - the FIDO2 client protocol, over whichever bus the device is on.
 *
 * The protocol layer is ported from @vincss-public-projects/fido2-client
 * (VinCSS R&D, MIT) - specifically src/Transports/HIDPacket.js's framing and
 * src/CTAP2/CTAP2.js's sendCBOR loop, which is the shape the old kit already
 * proved against real hardware. What is NOT ported is src/Transports/USB.js,
 * its node-hid transport, and that omission is the entire point: that transport
 * needs a kernel device node, and needing one would push every FIDO2 test out
 * of section 1 and into a section that cannot run in CI. Here the transport is
 * whatever the device handle is - the emulator's in-process bus, or hidraw on a
 * physical key - so the same ceremony runs in both places.
 *
 * Three things about the wire are worth knowing before reading the code:
 *
 *   Fragmentation. A CTAPHID message is an init packet (channel, command,
 *   16-bit total length, then 57 bytes) followed by continuation packets
 *   (channel, sequence 0..127, then 59 bytes). Anything past a GetInfo needs
 *   it, so it is here rather than deferred.
 *
 *   KEEPALIVE is not noise, it is the user-presence prompt. While the
 *   authenticator waits for a button press it sends KEEPALIVE(0x02) roughly
 *   ten times a second. A client that treats those as errors cannot complete a
 *   ceremony; a TEST that watches for them knows exactly when to press.
 *
 *   The first byte of a CBOR response is the CTAP status, not CBOR. Zero is
 *   success and everything else is an error code, so the payload has to be
 *   split before it is decoded.
 */
'use strict';

const cbor = require('./cbor');
const { TimeoutError, CancelledError } = require('./waits');

const IFACE_FIDO = 1;

/*
 * THE PROTOCOL NOW COMES FROM node-onlykey-lib (protocol.ctaphid - one lib, any
 * GUI; the test CLI is a GUI): the CTAPHID and authenticator command codes,
 * the CTAP2 status table, Ctap2Error and the packet framing. Checked before
 * the switch: frame() identical at 0, 1, 57, 58, 116, 200 and 1024 bytes (and
 * pinned by the library's frozen vectors from this file); CTAPHID, KEEPALIVE,
 * TYPE_INIT and the broadcast CID identical; CTAP2_CMD a superset.
 *
 * The status NAMES are the library's full spellings now - 'CTAP2_ERR_PIN_
 * INVALID' where this file said 'PIN_INVALID' - so an error reads "CTAP2 error
 * CTAP2_ERR_NO_CREDENTIALS". The tests match the distinctive part
 * (/NO_CREDENTIALS/, /PIN_NOT_SET/, /PIN_AUTH_INVALID/), which both carry.
 * The table is the firmware's own ctap_errors.h; this file also named 0x3E
 * UP_REQUIRED, a CTAP 2.1 code this firmware neither defines nor sends.
 *
 * What stays here is the Ctap2 class below: it is built on the kit's Device -
 * its HID history cursors, abort signals and keepalive record - which the
 * library's CtapHid does not have yet.
 */
const lib = require('node-onlykey-lib/protocol').ctaphid;

const toBuffer = (u8) => Buffer.from(u8.buffer, u8.byteOffset, u8.byteLength);

const {
  CTAPHID, TYPE_INIT, CTAP2_CMD, CTAP2_ERROR, KEEPALIVE, Ctap2Error,
  INIT_PAYLOAD, CONT_PAYLOAD,
} = lib;

/* A Buffer, because the kit compares CIDs with .equals(). */
const BROADCAST_CID = toBuffer(lib.BROADCAST_CID);

/* ---- framing ------------------------------------------------------------- */

/** Split a message into 64-byte CTAPHID packets (Buffer views). */
function frame(cid, cmd, payload) {
  return lib.frame(cid, cmd, payload).map(toBuffer);
}

/**
 * A node-onlykey-lib transport over the kit's Device - the two things
 * CtapHid needs: on('report') and write().
 *
 * Reports come from the Device's own recorder (_hidSubscribers is called with
 * the interface after every report is appended to its history), so what the
 * library reads is exactly what the kit records and what reportsSince()/
 * waitHid() see - one feed, not two.
 */
function deviceTransport(device) {
  return {
    on(event, listener) {
      if (event !== 'report') return () => {};
      const fn = (iface) => {
        const list = device.hid[iface];
        if (list && list.length) listener({ iface, data: list[list.length - 1] });
      };
      device._hidSubscribers.add(fn);
      return () => device._hidSubscribers.delete(fn);
    },
    async write(iface, packet) {
      device.send(iface, packet);
      return packet.length;
    },
  };
}

/**
 * The client protocol, bound to a device handle: node-onlykey-lib's CtapHid,
 * over the kit's Device.
 *
 * What the kit adds, and why each is here:
 *
 * - CANCELLATION. Every exchange runs under the Device's combined signal - the
 *   test's own, the device dying, and the runner's external ones (watchdog,
 *   deadlines) - so a dead device or a stopped run ends the wait at once
 *   instead of at its timeout (the library's signal support exists for this).
 * - NO RESEND. The library resends a multi-packet request the firmware refused
 *   as INVALID_COMMAND - the wipe-timer defect - which is right for a GUI. A
 *   test harness must see the firmware's own answer; 32-ctaphid-wipe-timer is
 *   about exactly that refusal.
 * - PENDING. Each exchange is registered in the Device's pending set, so a
 *   failure or a watchdog report says what was being waited for.
 * - THE KIT'S ERRORS. The library's AbortError and timeout become the kit's
 *   CancelledError / TimeoutError, the types and wording every other wait in
 *   the kit uses.
 * - BUFFERS. Decoded replies come back with Buffer byte strings, as before.
 * - _receive(), the cursor-based read over the Device's HID history that
 *   32-ctaphid-wipe-timer drives by hand with raw frames.
 */
class Ctap2 extends lib.CtapHid {
  constructor(device, opts = {}) {
    super(deviceTransport(device), { iface: IFACE_FIDO, resendCutRequest: false });
    this.device = device;
    this.baseSignal = opts.signal;
  }

  /** Run one exchange under the Device's signal, pending set and error types. */
  async _run(desc, opts, fn) {
    const d = this.device._opts({ signal: this.baseSignal, ...opts });
    const untrack = d.pending ? d.pending.add(desc) : null;
    try {
      return cbor.buffers(await fn({ ...opts, signal: d.signal }));
    } catch (err) {
      if (err && err.name === 'AbortError') {
        const why = d.signal && d.signal.reason && d.signal.reason.message
          ? d.signal.reason.message : (d.signal && d.signal.reason) || '';
        throw new CancelledError(desc, why);
      }
      const t = err && /no CTAPHID reply within (d+)ms/.exec(err.message);
      if (t) throw new TimeoutError(`${desc} (${err.message})`, Number(t[1]));
      throw err;
    } finally {
      if (untrack) untrack();
    }
  }

  init(opts = {}) {
    return this._run('a CTAPHID channel (INIT on the broadcast CID)', opts,
      (o) => super.init(o));
  }

  send(cmd, data = Buffer.alloc(0), opts = {}) {
    return this._run(`a CTAP2 reply to command 0x${cmd.toString(16)}`, opts,
      (o) => super.send(cmd, data, o));
  }

  /**
   * Read one whole CTAPHID message on this channel from the Device's HID
   * history, starting at the cursor `since` - for a test that writes its own
   * raw frames (32-ctaphid-wipe-timer). Not the library's reader: it reads the
   * recorded history, so a reply that arrived before the call is still found.
   * @returns {Promise<{cmd: number, payload: Buffer, next: number}>}
   */
  async _receive(opts = {}) {
    const since = opts.since !== undefined ? opts.since : this.device.mark(IFACE_FIDO);
    const cid = Buffer.from(this.cid);
    const wait = (match) => this.device.waitHid(IFACE_FIDO, {
      signal: this.baseSignal, timeoutMs: 10000, ...opts, since, match,
    });

    const initPacket = await wait((buf) =>
      buf.subarray(0, 4).equals(cid) && (buf[4] & TYPE_INIT) !== 0);

    const cmd = initPacket[4] & 0x7F;
    const total = initPacket.readUInt16BE(5);
    const chunks = [initPacket.subarray(7, 7 + Math.min(total, INIT_PAYLOAD))];
    let have = chunks[0].length;

    const offset = this.device.reportsSince(IFACE_FIDO, since).indexOf(initPacket);
    let last = since + (offset < 0 ? 0 : offset);

    let seq = 0;
    while (have < total) {
      const wanted = seq;
      const cont = await wait((buf) => buf.subarray(0, 4).equals(cid) && buf[4] === wanted);
      const slice = cont.subarray(5, 5 + Math.min(total - have, CONT_PAYLOAD));
      chunks.push(slice);
      have += slice.length;
      seq++;
      const at = this.device.reportsSince(IFACE_FIDO, since).indexOf(cont);
      if (at >= 0) last = Math.max(last, since + at);
    }

    return { cmd, payload: Buffer.concat(chunks), next: last + 1 };
  }
}

module.exports = {
  Ctap2, Ctap2Error, frame,
  CTAPHID, CTAP2_CMD, CTAP2_ERROR, KEEPALIVE, BROADCAST_CID, TYPE_INIT,
};
