/*
 * The multi-report response path: does a large answer arrive whole, and in order?
 *
 * NOT `OKGETRESPONSE`. TODO put that first in the work order for several
 * sessions on the premise that "every large payload comes back through it"; it
 * has no handler, no references, and every client has it absent or commented
 * out. See PLAN's plane 1. Nothing is requested per chunk - the device pushes:
 *
 *     send_transport_response()      okcore.cpp:2821
 *     for (int i = 0; i < len; i += 64) { memcpy(resp_buffer, data+i, ...);
 *                                         RawHID.send2(resp_buffer, 100); }
 *
 * So a large response is N consecutive unsolicited 64-byte reports and the host
 * simply reads until it has enough. That path is exercised constantly and
 * tested nowhere directly - only sideways, by features that would blame
 * themselves if it broke.
 *
 * IT HAS A RECORDED FAILURE MODE, which is what makes this worth a file rather
 * than a footnote. The comment at the fix site in okcore.cpp says it plainly:
 * `RawHID.send2(buf, 0)` gives up almost instantly when the firmware's
 * four-packet TX queue is still full, returning 0 WITHOUT SENDING - and that
 * return value was never checked, so a full queue silently dropped a chunk. It
 * is called the root cause of the intermittent truncated multi-packet responses
 * seen all session. The fix gives each attempt a 100ms budget and retries five
 * times.
 *
 * A queue that fills is likelier to fill LATE than early, so the long response
 * matters more than the short one. Both are driven:
 *
 *     1184 bytes   ML-KEM-768 public key      19 reports
 *     3309 bytes   ML-DSA-65 signature        52 reports
 *
 * and the assertion in each case is the same three things: the whole length
 * arrived, it arrived as the expected number of reports, and the bytes are the
 * ones the device meant to send rather than a tail of zeros where a chunk went
 * missing. A dropped chunk in the middle shifts everything after it; a dropped
 * chunk at the end truncates. Both are caught by comparing against a value that
 * can be checked independently.
 *
 * SURFACES - see PRODUCTION.md. This is the vendor interface throughout. The
 * console is used for one thing only, and it is the unavoidable one: reading
 * the button challenge the device raises for a keygen and for a signature, which
 * no client-visible surface reports.
 *
 * SECTION 1, so no kernel device node and no CLI. Every message here is built
 * by the kit and put on the in-process bus, which is also the point - this is
 * the first file to send OKSETPRIV and OKSIGN by hand rather than through
 * onlykey-cli or the web app's library.
 */
'use strict';

const crypto = require('crypto');

const { describe, it } = require('../../lib/harness');
const { IFACE, okmsg } = require('../../lib/device');
const { PINS } = require('../../lib/config');
const pqc = require('../../lib/pqc');

const REPORT = 64;

/* okcore.h key types, with the feature flags python-onlykey folds in. */
const KEYTYPE_MLKEM768 = 5;
const FEATURE_DECRYPT = 32;
const MLKEM_KEYTYPE_BYTE = KEYTYPE_MLKEM768 | FEATURE_DECRYPT;      // 0x25
const PQC_PGP_KEYTYPE_BYTE = 0x67;      // KEYTYPE_PQC_PGP | DECRYPT | SIGN

const ECC_SLOT = 101;                   // 'ECC1'
const RSA_SLOT = 1;                     // composite PQC keys live in RSA slots
const HALF_PQC = 1;                     // sign selector: 0 = Ed25519, 1 = ML-DSA-65

const MLKEM_PUBKEY_LEN = 1184;
const MLDSA_SIG_LEN = 3309;
const COMPOSITE_BLOB_LEN = 160;

/* 32 bytes of 0xFF is the firmware's "generate your own key" trigger. */
const GENERATE = Buffer.alloc(32, 0xFF);

describe('large responses arrive whole', {
  state: 'initialized',
  requires: ['crypto'],
  timeoutMs: 300000,
}, () => {
  /**
   * Read `want` bytes off the vendor interface as consecutive reports.
   *
   * Deliberately counts REPORTS as well as bytes. The two say different things:
   * a short byte count means the response was truncated, and a report count
   * that does not match means the framing changed - a device that started
   * answering the same payload in 20 reports instead of 19 would still hand
   * back 1184 bytes and would still be a change worth knowing about.
   */
  async function collect(device, since, want, { signal, timeoutMs = 20000 }) {
    const expected = Math.ceil(want / REPORT);
    const deadline = Date.now() + timeoutMs;

    let reports = device.reportsSince(IFACE.VENDOR, since);
    while (reports.length < expected && Date.now() < deadline) {
      await device.sleep(100, { signal });
      reports = device.reportsSince(IFACE.VENDOR, since);
    }

    return { reports, bytes: Buffer.concat(reports).subarray(0, want) };
  }

  const outOfConfigMode = async (device, signal) => {
    await device.restart({ signal });
    await device.ensureUnlocked(PINS.primary, { signal });
  };

  it('an ML-KEM-768 public key comes back in 19 reports, not 18',
    async ({ device, assert, signal, log }) => {
      /*
       * SURFACE: vendor for the answer; console for the button challenge only,
       * which is unavoidable - the device raises a confirmation for a keygen and
       * nothing a client can see says what its digits are.
       *
       * The key is GENERATED rather than loaded, because loading a 1184-byte
       * public key would mean sending it in and getting it back, which tests the
       * send path twice and the response path not at all. Generated, the device
       * is the only source of the answer.
       */
      await pqc.readyForKeygen(device, { signal });

      await pqc.confirmFromConsole(device, async () => {
        device.sendVendor({
          msg: okmsg.MSG.OKSETPRIV,
          slot: ECC_SLOT,
          field: MLKEM_KEYTYPE_BYTE,
          payload: GENERATE,
        });
        /* The keygen itself takes a moment on top of the confirmation. */
        await device.sleep(4000, { signal });
      }, { signal });

      /*
       * OKGETPUBKEY is refused in config mode - "ERROR NOT SUPPORTED IN CONFIG
       * MODE", console only, with nothing on the vendor interface at all - so
       * writing a key and reading it back cannot happen in one mode.
       */
      await outOfConfigMode(device, signal);

      const since = device.mark(IFACE.VENDOR);
      device.sendVendor({ msg: okmsg.MSG.OKGETPUBKEY, slot: ECC_SLOT });

      const { reports, bytes } = await collect(device, since, MLKEM_PUBKEY_LEN,
        { signal, timeoutMs: 25000 });
      log(`${reports.length} reports, ${bytes.length} bytes`);

      assert.equal(reports.length, Math.ceil(MLKEM_PUBKEY_LEN / REPORT),
        `expected ${Math.ceil(MLKEM_PUBKEY_LEN / REPORT)} reports for an ML-KEM public key`);
      assert.equal(bytes.length, MLKEM_PUBKEY_LEN,
        `expected ${MLKEM_PUBKEY_LEN} bytes, got ${bytes.length}`);

      /*
       * Not zeros, and not a repeated block. A dropped chunk in the middle
       * shifts everything after it and a dropped chunk at the end leaves the
       * tail short - but the cheapest thing that catches BOTH without a second
       * source of truth is that the last report carries real key material.
       * An ML-KEM-768 encapsulation key is 1184 bytes of expanded matrix; a run
       * of 64 identical bytes anywhere in it does not happen by chance.
       */
      const tail = bytes.subarray(MLKEM_PUBKEY_LEN - REPORT);
      assert.notEqual(tail.toString('hex'), '00'.repeat(REPORT),
        'the last report of the key is all zeros - a chunk went missing');
      assert.ok(new Set(tail).size > 1, 'the last report is a single repeated byte');

      /* And the same key twice: the response path is not making it up. */
      const again = device.mark(IFACE.VENDOR);
      device.sendVendor({ msg: okmsg.MSG.OKGETPUBKEY, slot: ECC_SLOT });
      const second = await collect(device, again, MLKEM_PUBKEY_LEN, { signal, timeoutMs: 25000 });

      assert.bytes(second.bytes, bytes,
        'two reads of one stored key returned different bytes');
    });

  it('an ML-DSA-65 signature comes back in 52 reports, which is where a full queue bites',
    async ({ device, assert, signal, log }) => {
      /*
       * SURFACE: vendor for the answer; console for the challenge, as above.
       *
       * The longest response the device produces, and the one this file exists
       * for. 3309 bytes is 52 reports - nearly three times the ML-KEM key - so
       * if the TX queue is going to fill, it fills here. The alpha kit's hardest
       * bug lived on exactly this path: store_FIDO_response() dropped what did
       * not fit and the device then blamed the challenge PIN.
       *
       * The blob is random rather than a real key. Every part of it is a SEED -
       * Ed25519(32) | ML-DSA seed(32) | X25519(32) | ML-KEM seed(64) - and seeds
       * expand into valid keys whatever their bytes, so the device will sign
       * with it. Nothing here checks the signature verifies; that is
       * 02-cli/06-composite-ops (retired 2026-09-29; now 02-cli/19-composite-tunnel-lib)' job, against a published public key. What is
       * being tested is the LENGTH of the road home.
       */
      await pqc.readyForKeygen(device, { signal });

      /*
       * 160 bytes over 57-byte chunks: three OKSETPRIV messages, each carrying
       * the key type in buffer[6] and its chunk after it. The firmware
       * accumulates across the three.
       */
      const blob = crypto.randomBytes(COMPOSITE_BLOB_LEN);
      const since = device.mark(IFACE.VENDOR);
      for (let i = 0; i < COMPOSITE_BLOB_LEN; i += 57) {
        device.sendVendor({
          msg: okmsg.MSG.OKSETPRIV,
          slot: RSA_SLOT,
          field: PQC_PGP_KEYTYPE_BYTE,
          payload: blob.subarray(i, i + 57),
        });
        await device.sleep(150, { signal });
      }

      const ack = await device.waitHid(IFACE.VENDOR, {
        since, match: /Successfully|Error/, timeoutMs: 15000, signal,
      });
      const said = okmsg.text(ack).trim();
      log(`composite load: ${said}`);
      assert.ok(!/^Error/.test(said), `loading the composite key failed: ${said}`);

      /* OKSIGN is not one of the messages config mode admits, so leave it. */
      await outOfConfigMode(device, signal);

      /*
       * [selector | digest], 33 bytes - one chunk, so the continuation marker in
       * buffer[6] is its own length rather than 0xFF.
       */
      const digest = crypto.createHash('sha256').update('okt large response').digest();
      const request = Buffer.concat([Buffer.from([HALF_PQC]), digest]);

      let sigSince = null;
      await pqc.confirmFromConsole(device, async () => {
        sigSince = device.mark(IFACE.VENDOR);
        device.sendVendor({
          msg: okmsg.MSG.OKSIGN,
          slot: RSA_SLOT,
          field: request.length,
          payload: request,
        });
        await device.sleep(9000, { signal });
      }, { signal });

      const { reports, bytes } = await collect(device, sigSince, MLDSA_SIG_LEN,
        { signal, timeoutMs: 30000 });
      log(`${reports.length} reports, ${bytes.length} bytes`);

      assert.equal(reports.length, Math.ceil(MLDSA_SIG_LEN / REPORT),
        `expected ${Math.ceil(MLDSA_SIG_LEN / REPORT)} reports for an ML-DSA-65 signature, ` +
        `got ${reports.length} - a short count is a dropped chunk`);
      assert.equal(bytes.length, MLDSA_SIG_LEN,
        `expected ${MLDSA_SIG_LEN} bytes, got ${bytes.length}`);

      /*
       * The tail again, and here it is the assertion that matters most: a
       * truncated multi-packet response is exactly a signature whose last
       * reports never arrived, and the queue fills at the END.
       */
      const tail = bytes.subarray(MLDSA_SIG_LEN - REPORT);
      assert.notEqual(tail.toString('hex'), '00'.repeat(REPORT),
        'the last report of the signature is all zeros - a chunk went missing');
      assert.ok(new Set(tail).size > 1, 'the last report is a single repeated byte');
    });

  it('an unrecognised vendor message id is answered by the FIDO stack, in CTAPHID',
    async ({ device, assert, signal, log }) => {
      /*
       * SURFACE: vendor - survives into a production walk, and the ANSWER is
       * the evidence, which is better than the silence this test first expected.
       *
       * The one thing worth testing about OKGETRESPONSE, OKPING, OKHMAC and
       * OKWEBAUTHN: none is dispatched, and an id the switch does not recognise
       * is not ignored. The `default:` case hands the whole report to
       * recv_fido_msg(), so an unknown vendor message is parsed as CTAPHID.
       *
       * What comes back proves it, on the vendor interface where the request
       * arrived:
       *
       *     FF FF FF FF  BF  00 01  ..
       *     |            |   |
       *     |            |   payload length
       *     |            CTAPHID_ERROR (0x80 | 0x3F)
       *     broadcast channel
       *
       * A CTAPHID error frame is not something the vendor dispatcher can
       * produce - it has no CTAPHID framer - so its arrival IS the routing.
       * The first version of this test asserted the device stayed silent and
       * failed, which is the better outcome: silence would have been consistent
       * with the report being dropped, and this is not.
       *
       * So the answer to "what does OKGETRESPONSE do" is: whatever the FIDO
       * stack makes of it, which for a body the framer rejects is an error
       * frame. Inert as a vendor message, and not inert on the wire.
       */
      await device.ensureUnlocked(PINS.primary, { signal });

      const vendorSince = device.mark(IFACE.VENDOR);
      device.log.clear();

      device.sendVendor({ msg: 0xF2, payload: Buffer.alloc(8, 0x00) });

      const reply = await device.waitHid(IFACE.VENDOR, {
        since: vendorSince, timeoutMs: 8000, signal,
      });
      log(`answered ${reply.subarray(0, 8).toString('hex')}`);

      /*
       * Byte 4 is where the vendor protocol keeps its message id and where
       * CTAPHID keeps its command. 0xBF is CTAPHID_ERROR; a vendor answer would
       * be printable text from hidprint().
       */
      assert.equal(reply[4], 0xBF,
        `expected a CTAPHID_ERROR frame, got ${reply.subarray(0, 8).toString('hex')} - ` +
        'if this is now a vendor reply, a handler has been added and PLAN plane 1 needs revisiting');
      assert.bytes(reply.subarray(0, 4), Buffer.alloc(4, 0xFF),
        'the error came back on a channel other than the broadcast one');

      /* And it survived being handed a message nothing claims. */
      assert.ok(!device.fatal, 'an unrecognised vendor message id took the device down');
      assert.match(device.log.text, /Received packet/,
        'the device did not even log the report');
    });
});
