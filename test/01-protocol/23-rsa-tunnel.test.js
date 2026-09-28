/*
 * Classic RSA over the WebAuthn tunnel, at the 512-byte boundary.
 *
 * THE LEAD. The alpha report's `ctap_end_get_assertion()` finding ends: "It also
 * affects the classic RSA path, which shares this transport, for any response
 * served in more than one chunk." Written as a prediction and never verified.
 * This drives it.
 *
 * The bug it refers to sized a WebAuthn response from `pending_operation`, a
 * global that `process_packets()` rewrites on every inbound raw-HID packet -
 * including the polls being answered. When the gate failed the assertion fell to
 * a 72-byte default while the cursor advanced a full 512, so the host got one
 * byte in seven. **A response that fits one chunk is immune**, because that path
 * finishes inside `send_stored_response()`, which sets `pending_operation` itself
 * before returning. So the failure split by response SIZE and looked exactly
 * like a buffer-capacity bug.
 *
 * WHY 512 IS THE NUMBER TO DRIVE, and why an RSA-2048 signature is NOT the
 * multi-chunk case the lead assumed. The chunk is `MAX_LARGE_RESP_CHUNK` = 512
 * (ok_extension.cpp:116) - not a 64-byte HID report. A classic RSA response is
 * `type * 128` and `store_FIDO_response()` does not grow it
 * (`large_resp_buffer_offset = len`, and the box is length-preserving), so:
 *
 *     RSA-1024   128 B     RSA-3072   384 B
 *     RSA-2048   256 B     RSA-4096   512 B   <- exactly one full chunk
 *
 * TRANSIT v2 MOVED THAT BOUNDARY, and moved it the useful way. The old box was
 * length-preserving, so 512 bytes of signature were 512 bytes on the wire -
 * exactly one chunk, and the multi-chunk path the alpha report pointed at could
 * only be reached by a PQC-sized response. `okcrypto_transit_seal()` frames a
 * response as `[counter(4)][ciphertext][tag(16)]`, so the same signature is
 * staged as 532 bytes and served as 512 + 20. RSA-4096 is therefore now the
 * SMALLEST classic response that crosses the boundary, which is what this file
 * wanted all along: the assertion is no longer "512 arrives whole" but "512 + 20
 * arrives in two chunks and reassembles", and a cursor compared before it is
 * advanced, or a `>` that should be `>=`, fails it. RSA-2048 (256 + 20 = 276) is
 * the one-chunk control beside it.
 *
 * THE CLIENT HAD TO BE BUILT, and `lib/device/transit.js` is where it went.
 * `tunnel.js` alone cannot reach any command but OKCONNECT:
 * `bridge_to_onlykey()` opens every non-OKCONNECT keyhandle with
 * `okcrypto_transit_open()` before it looks at the command, and a frame that
 * does not authenticate is discarded whole - not dispatched as noise, simply
 * never dispatched, which from here looks like the device ignoring the request. Written in the kit rather than borrowed from the shipped library
 * deliberately - `03-xwing-derive` lets the library send its option bytes because
 * the library IS its subject, and here the subject is the firmware's chunking, so
 * a second client would just be testing the library again. It also keeps this
 * file in section 1, where a test is worth double.
 *
 * HOW THE TWO HALVES ARE TOLD APART, which matters because a wrong transit key
 * and a chunking bug both end in "the signature does not verify":
 *
 *   the REQUEST   is proven by the device's own console dump - it prints
 *                 "Received Message" and the bytes it is about to hash, so the
 *                 test asserts the device received exactly the digest that was
 *                 sent. That is the transit box working, independent of any
 *                 response.
 *   the RESPONSE  is then the only remaining variable, and it is checked by
 *                 verifying the signature against the modulus the device
 *                 published over the vendor interface.
 *
 * SURFACES - see PRODUCTION.md. The FIDO interface carries the whole operation
 * and the vendor interface carries the key setup and the modulus, so the
 * assertions are client-visible. The console is read for two things that no
 * client surface reports: when the confirmation has primed, and which bytes the
 * device received. The second is the request/response discriminator above and is
 * the reason this file can attribute a failure at all.
 */
'use strict';

const crypto = require('crypto');

const { describe, it } = require('../../lib/harness');
const { IFACE, okmsg } = require('../../lib/device');
const { Ctap2 } = require('../../lib/device/ctap2');
const tunnel = require('../../lib/device/tunnel');
const transit = require('../../lib/device/transit');
const { PINS } = require('../../lib/config');
const pqc = require('../../lib/pqc');

const CHUNK = 57;                       // vendor-interface payload per report
const REQUEST_CHUNK = 171;              // u2fSignBuffer's 57 * 3 - see below
const MAX_LARGE_RESP_CHUNK = 512;       // ok_extension.cpp:116
/*
 * 171, not 228, and the arithmetic is the whole reason: a credential ID carries
 * 245 payload bytes, a transit v2 frame costs 20 of them, and every chunk but
 * the message's last must be a whole number of the firmware's 57-byte packets -
 * `process_packets()` takes 57 from a packet not marked final whatever its real
 * length. 245 - 20 = 225, and the largest multiple of 57 at or under 225 is 171.
 * The shipped web app's u2fSignBuffer() uses the same number for the same reason.
 */
const FEATURE_SIGN = 64;
const FEATURE_DECRYPT = 32;
const SLOT_SIGN = 2;                    // slotid() sends OKSIGN here
const SLOT_DECRYPT = 1;                 // ...and everything else here
const FIELD_STORED_CHALLENGE = 22;
const FIELD_WEBCRYPT_POLICY = 31;      // set_slot()'s webcrypt policy bitfield
const OKWC_ALLOW_STORED_KEY = 0x01;     // okcore.h - stored-slot OKSIGN/OKDECRYPT
const PRIMED = /Encrypted Buffer/g;

describe('classic RSA over the WebAuthn tunnel', {
  state: 'initialized',
  requires: ['crypto'],
  timeoutMs: 600000,
}, () => {
  function keypair(bits) {
    const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: bits });
    const jwk = privateKey.export({ format: 'jwk' });
    return {
      pq: Buffer.concat([
        Buffer.from(jwk.p, 'base64url'), Buffer.from(jwk.q, 'base64url'),
      ]),
      n: Buffer.from(jwk.n, 'base64url'),
    };
  }

  const verifier = (n) => crypto.createPublicKey({
    key: { kty: 'RSA', n: n.toString('base64url'), e: 'AQAB' }, format: 'jwk',
  });

  async function collectVendor(device, since, want, { signal, timeoutMs = 30000 }) {
    const expected = Math.ceil(want / 64);
    const deadline = Date.now() + timeoutMs;
    let reports = device.reportsSince(IFACE.VENDOR, since);
    while (reports.length < expected && Date.now() < deadline) {
      await device.sleep(100, { signal });
      reports = device.reportsSince(IFACE.VENDOR, since);
    }
    return Buffer.concat(reports).subarray(0, want);
  }

  /** Load an RSA key into a slot and leave config mode. Vendor interface. */
  async function loadKey(device, {
    bits, typeNibble, slot = SLOT_SIGN, feature = FEATURE_SIGN,
  }, { signal, assert, log }) {
    const key = keypair(bits);
    await pqc.readyForKeygen(device, { signal });

    let since = device.mark(IFACE.VENDOR);
    device.sendVendor({
      msg: okmsg.MSG.OKSETSLOT, slot: 1, field: FIELD_STORED_CHALLENGE,
      payload: Buffer.from([1]),          // the BYTE 1 - see 19-rsa-keys
    });
    await device.waitHid(IFACE.VENDOR, { since, match: /Success|Error/, timeoutMs: 8000, signal });

    /*
     * OPT IN TO STORED-SLOT PGP OVER FIDO2, which this whole file is.
     *
     * ok_extension.cpp gates every stored-slot OKSIGN/OKDECRYPT behind field 31
     * bit 0, and the bit is OFF by default - "derived keys yes, PGP no". Without
     * it the device answers `Error stored key use over FIDO2 not enabled` on the
     * vendor interface and serves an empty stored response, so the FIDO poll
     * below simply never sees `Encrypted Buffer` and times out 30s later with
     * nothing to attribute it to. That is not a chunking failure and this file
     * should not report it as one.
     *
     * It goes here because field 31 needs config mode, this helper opens the
     * only config-mode window in the file, and the restart at the end is what
     * leaves it. The byte survives the restart - it is EEPROM.
     *
     * NOT EXERCISED ON THE EMULATOR, and saying so is the point. webcryptcheck()
     * opens with `#ifdef DEBUG ... return 2; // Trust all origins for debug
     * firmware`, which returns before the policy byte is read - so on a debug
     * build this write changes nothing and removing it would not turn the file
     * red. It is here for the hardware run, where the early return is compiled
     * out and the default is level 1. Read from device.cpp, not measured; the
     * only thing measured here is that the device accepted the write.
     */
    since = device.mark(IFACE.VENDOR);
    device.sendVendor({
      msg: okmsg.MSG.OKSETSLOT, slot: 1, field: FIELD_WEBCRYPT_POLICY,
      payload: Buffer.from([OKWC_ALLOW_STORED_KEY]),
    });
    const policy = await device.waitHid(IFACE.VENDOR,
      { since, match: /Success|Error/, timeoutMs: 8000, signal });
    assert.match(okmsg.text(policy).trim(), /Successfully set webcrypt policy/,
      `enabling stored-key use over FIDO2: ${okmsg.text(policy).trim()}`);

    since = device.mark(IFACE.VENDOR);
    for (let i = 0; i < key.pq.length; i += CHUNK) {
      device.sendVendor({
        msg: okmsg.MSG.OKSETPRIV, slot, field: typeNibble | feature,
        payload: key.pq.subarray(i, i + CHUNK),
      });
      await device.sleep(150, { signal });
    }
    const ack = await device.waitHid(IFACE.VENDOR,
      { since, match: /Successfully|Error/, timeoutMs: 30000, signal });
    assert.match(okmsg.text(ack).trim(), /Successfully set RSA Key/,
      `storing the ${bits}-bit key: ${okmsg.text(ack).trim()}`);

    await device.restart({ signal });
    await device.ensureUnlocked(PINS.primary, { signal });

    since = device.mark(IFACE.VENDOR);
    device.sendVendor({ msg: okmsg.MSG.OKGETPUBKEY, slot, field: 0 });
    const published = await collectVendor(device, since, key.pq.length, { signal });
    assert.bytes(published, key.n, 'the slot published a different modulus than it was given');
    log(`${bits}-bit key loaded into slot ${slot}; modulus ${published.length} bytes`);
    return { ...key, published };
  }

  /** OKCONNECT over the tunnel, and the transit key that follows from it. */
  async function handshake(device, ctap, { signal, assert, log }) {
    const ours = transit.keypair();
    const reply = await tunnel.send(ctap, {
      cmd: okmsg.MSG.OKCONNECT,
      data: transit.connectPayload(ours.publicKey),
    }, { timeoutMs: 30000, signal });

    assert.ok(reply.data && reply.data.length >= 32,
      `the handshake carried no public key: ${JSON.stringify(reply)}`);
    const devicePublic = reply.data.subarray(0, 32);
    const model = okmsg.text(reply.data.subarray(32));
    log(`handshake: device pub ${devicePublic.subarray(0, 8).toString('hex')}…, model ${model}`);
    assert.match(model, /UNLOCKED/, `the device did not report itself unlocked: ${model}`);

    /* The counter starts with the key, not with the process - see transit.js. */
    return transit.session(transit.transitKey(devicePublic, ours.privateKey));
  }

  /**
   * Send a tunnelled request, sealed, in 228-byte chunks with an advancing opt3.
   *
   * opt3 must strictly increase: `last_request_opt3` drops any packet whose opt3
   * is not greater than the last one, which is the Windows 10 1903
   * double-fire guard. opt2 marks the final chunk and is what makes the firmware
   * set `recv_buffer[6]` to the real length instead of 0xFF.
   */
  async function sendSealed(ctap, sess, { cmd, slot, payload, startAt = 1 }, opts) {
    let opt3 = startAt;
    let last = null;
    for (let i = 0; i < payload.length; i += REQUEST_CHUNK) {
      const piece = payload.subarray(i, i + REQUEST_CHUNK);
      const final = i + REQUEST_CHUNK >= payload.length;
      last = await tunnel.send(ctap, {
        cmd, opt1: slot, opt2: final ? 1 : 0, opt3, data: transit.seal(sess, piece),
      }, opts);
      opt3 += 1;
    }
    return { reply: last, nextOpt3: opt3 };
  }

  /**
   * Poll until the whole response has been served, counting the chunks.
   *
   * The chunk count is the assertion this file exists for, so it is returned
   * rather than hidden: the same bytes arriving in one chunk or in two say
   * different things about `send_stored_response()`.
   *
   * `want` is the FRAMED length - plaintext + transit.OVERHEAD - because that is
   * what is staged and therefore what has to arrive before the frame can be
   * opened. Polling for the plaintext length stops one tag short and the open
   * below fails on a truncated frame, which reads as a crypto failure and is not
   * one.
   */
  async function poll(ctap, sess, want, { opt3, tries = 8 }, opts) {
    const chunks = [];
    let next = opt3;
    for (let i = 0; i < tries && Buffer.concat(chunks).length < want; i++) {
      const reply = await tunnel.send(ctap, {
        cmd: 0xF3,                                  // OKPING, the poll
        opt3: next, data: transit.seal(sess, Buffer.alloc(16)),
      }, opts);
      next += 1;
      if (reply.error) throw new Error(`the device refused the poll: ${reply.error}`);
      if (reply.data && reply.data.length > 1) chunks.push(reply.data);
    }
    return { chunks, bytes: Buffer.concat(chunks) };
  }

  /** Drive one signature end to end and return everything worth asserting on. */
  async function signOverTunnel(device, ctap, key, sess, { signal, assert, log }) {
    const message = Buffer.from(`okt tunnel rsa ${key.pq.length * 8}`);
    const digest = crypto.createHash('sha256').update(message).digest();

    /* CLEAR FIRST, THEN COUNT. Counting before the clear reads a marker the
     * PREVIOUS test left, so the wait below asks for one more than can arrive and
     * times out - which passes alone and fails in sequence. Caught by the
     * natural-order run, which is what it is for. */
    device.log.clear();
    const primed = device.log.count(PRIMED);

    const { nextOpt3 } = await sendSealed(ctap, sess, {
      cmd: okmsg.MSG.OKSIGN, slot: SLOT_SIGN, payload: digest,
    }, { timeoutMs: 30000, signal });

    /* SURFACE: console, and this is the request/response discriminator - the
     * device prints the bytes it is about to hash. If the transit box were wrong
     * this would not be the digest, and the failure would be attributable here
     * instead of showing up as an unverifiable signature. */
    await device.log.waitForCount(PRIMED, primed + 1, { timeoutMs: 30000, signal });
    const received = pqc.packetFromConsole(device);
    log(`device received ${received && received.length} bytes`);
    assert.bytes(received, digest,
      'the device did not receive the digest that was sent - the transit box is wrong, ' +
      'so nothing below is about chunking');

    device.press(1);
    const answer = await poll(ctap, sess, key.pq.length + transit.OVERHEAD,
      { opt3: nextOpt3 }, { timeoutMs: 30000, signal });

    /*
     * THE RESPONSE IS SEALED TOO, and this is the one asymmetry that is easy to
     * miss because the vendor path does not have it. `okcrypto_rsasign()` ends:
     *
     *     if (outputmode == WEBAUTHN) send_transport_response(rsa_signature, (type*128), true, true);
     *     else                        send_transport_response(rsa_signature, (type*128), false, false);
     *
     * so the tunnelled signature goes through `store_FIDO_response(data, len,
     * encrypt=1)`, which boxes it with the transit key before staging. The
     * vendor path passes 0 and stages plaintext. Measured: the first run of this
     * test collected exactly 256 bytes in exactly 1 chunk - the right length and
     * the right framing - and failed to verify, because the bytes were still
     * sealed.
     *
     * The frame wraps the WHOLE staged response before any chunking, so the
     * concatenation of the chunks is what gets opened, not each chunk on its own -
     * there is exactly one counter and one tag for the response, however many
     * OKPING polls it took to collect it. `open()` throws on a bad tag rather
     * than handing back noise, so a failure here is attributable.
     */
    const opened = transit.open(sess, answer.bytes);

    return { message, digest, ...answer, sealed: answer.bytes, bytes: opened };
  }

  it('an RSA-4096 signature crosses MAX_LARGE_RESP_CHUNK once framed, and reassembles',
    async ({ device, assert, signal, log, skip }) => {
      /*
       * SURFACE: FIDO for the operation, vendor for the modulus, console for the
       * two things no client reports. THE boundary case: 512 is both
       * MAX_LARGE_RESP_CHUNK and MAX_RSA_KEY_SIZE, and transit v2's 20 bytes of
       * framing push the staged response exactly 20 bytes past the chunk.
       */
      /*
       * UNGATED 2026-09-22, AND WHAT THE GATE USED TO SAY IS THE HISTORY.
       * Loading a 4096-bit key used to abort the firmware - `rsa_priv_flash()`'s
       * type-4 branch guarded on `packet_buffer_offset <= 456` and then memcpy'd
       * a literal 57, so the ninth chunk wrote index 512 of a 512-byte array
       * (FINDING-rsa4096-overflow.md). That could not be pinned as a passing
       * test the way a wrong ANSWER can: the failure killed the device host and
       * the runner classified it as a run-level abort before any assertion ran,
       * so the case skipped behind OKT_EXPECT_RSA4096_FIX instead.
       *
       * The copy is clamped to `MAX_RSA_KEY_SIZE - packet_buffer_offset` now, so
       * the key loads and - measured, not read - its stored modulus equals `p*q`
       * byte for byte. `25-rsa4096-load.test.js` is what pins that, and it
       * replaced the file that pinned the defect. The env var is gone with it.
       * If this case ever fails by killing the device, the clamp has been
       * removed; it is not this test being wrong.
       */
      /*
       * EMULATED ONLY, AND THE ENV VAR MUST NOT BE ABLE TO OVERRIDE THAT.
       *
       * This is the one test in the file that is not hardware-capable, and it is
       * gated at the TEST rather than on the suite because the other two ran
       * against a physical key on 2026-08-06 and passed - gating the file would
       * have thrown away real coverage.
       *
       * The reason is asymmetric in a way the env var alone does not capture.
       * What makes this case safe to drive is `_FORTIFY_SOURCE`, which is the
       * EMULATOR's: the one-byte overflow in `rsa_priv_flash()` aborts at the
       * point of the write, which is how the defect was found at all. On a key
       * there is no such build, so the same write lands silently and corrupts
       * whatever follows `rsa_private_key`. Setting the variable on a hardware
       * run would therefore aim a known out-of-bounds write at a real device
       * with nothing to catch it - so the capability is checked FIRST and the
       * variable can only ever arm this where the abort exists.
       */
      if (!device.capabilities.has('emulated')) {
        skip('a 4096-bit key load is a known out-of-bounds WRITE ' +
          '(FINDING-rsa4096-overflow.md); it is only safe to drive where ' +
          '_FORTIFY_SOURCE aborts it, which is the emulator - on a key the same ' +
          'write lands silently');
      }
      if (!transit.probe().ok) skip(transit.probe().why);
      const self = transit.selfTest();
      assert.ok(self.ok,
        `the transit key derivation disagrees with NaCl's published beforenm vector: ` +
        `got ${self.got}, want ${self.want}`);

      const key = await loadKey(device, { bits: 4096, typeNibble: 4 }, { signal, assert, log });
      assert.equal(key.pq.length, MAX_LARGE_RESP_CHUNK,
        'an RSA-4096 P||Q should be exactly 512 bytes');

      const ctap = new Ctap2(device, { signal });
      await ctap.init();
      const sess = await handshake(device, ctap, { signal, assert, log });

      const got = await signOverTunnel(device, ctap, key, sess, { signal, assert, log });
      log(`${got.chunks.length} chunk(s), ${got.sealed.length} framed, ` +
        `${got.bytes.length} bytes of signature`);

      assert.equal(got.bytes.length, MAX_LARGE_RESP_CHUNK,
        `expected a ${MAX_LARGE_RESP_CHUNK}-byte signature, got ${got.bytes.length} - ` +
        'a short count here IS the ctap_end_get_assertion failure the alpha report predicted');
      assert.equal(got.sealed.length, MAX_LARGE_RESP_CHUNK + transit.OVERHEAD,
        `a sealed 512-byte signature is ${MAX_LARGE_RESP_CHUNK + transit.OVERHEAD} bytes on the ` +
        `wire; ${got.sealed.length} arrived`);
      assert.equal(got.chunks.length, 2,
        `512 + 20 is served in TWO chunks; ${got.chunks.length} means send_stored_response()'s ` +
        'cursor or its comparison is wrong at the boundary - one chunk means it truncated, ' +
        'three means it re-served');

      assert.ok(crypto.verify('sha256', got.message, verifier(key.published), got.bytes),
        'the signature does not verify against the modulus the device published - the ' +
        'bytes arrived in the wrong places, which is exactly the predicted failure');
    });

  it('an RSA-2048 signature over the tunnel is 256 bytes, which is what the PGP pages use',
    async ({ device, assert, signal, log, skip }) => {
      /*
       * SURFACE: as above. Second because it is NOT the boundary - 256 bytes is
       * half a chunk - but it is what `onlykey-pgp.js` actually drives, so a pass
       * here is the prerequisite `18-gui-encrypt-decrypt` rests on.
       */
      if (!transit.probe().ok) skip(transit.probe().why);

      const key = await loadKey(device, { bits: 2048, typeNibble: 2 }, { signal, assert, log });

      const ctap = new Ctap2(device, { signal });
      await ctap.init();
      const sess = await handshake(device, ctap, { signal, assert, log });

      const got = await signOverTunnel(device, ctap, key, sess, { signal, assert, log });
      log(`${got.chunks.length} chunk(s), ${got.sealed.length} framed, ` +
        `${got.bytes.length} bytes of signature`);

      assert.equal(got.bytes.length, 256, `expected 256 bytes, got ${got.bytes.length}`);
      assert.equal(got.chunks.length, 1,
        'a 256-byte signature is 276 bytes framed, still inside one chunk - this is the ' +
        'control for the 4096 case above');
      assert.ok(crypto.verify('sha256', got.message, verifier(key.published), got.bytes),
        'the signature does not verify against the published modulus');
    });

  it('an RSA-2048 decrypt is TWO keyhandles, and last_request_opt3 no longer drops the first',
    async ({ device, assert, signal, log, skip }) => {
      /*
       * SURFACE: FIDO for the operation, vendor for the modulus, console for the
       * priming and for the received-bytes discriminator.
       *
       * THE SECOND LEAD, from ok_extension.cpp:150. `last_request_opt3` used to
       * live in `packet_buffer_details[3]`, which `process_packets()` overwrites
       * with TWO RANDOM BYTES the moment a message completes:
       *
       *     RNG2(packet_buffer_details + 3, 2);   // response channel id
       *
       * Two meanings on one byte and the random one wins, so the next
       * multi-keyhandle request met a random 0-255 threshold and its early chunks
       * were dropped SILENTLY - no error, no print. The device hashed whatever
       * survived and then asked for challenge digits over bytes the host never
       * sent. Measured upstream on the PQC path: a 1088-byte ML-KEM ciphertext
       * arrived as its final 176-byte chunk alone.
       *
       * The comment says it "affects the classic RSA path identically - any
       * payload needing more than one keyhandle", and that it hid from humans
       * because `wipetasks()` zeroes the byte on a 5-second timer while a person
       * takes longer than that between operations. A scripted caller does not, so
       * this test is exactly the caller that would have seen it.
       *
       * A DECRYPT IS WHERE CLASSIC RSA CROSSES THE KEYHANDLE BOUNDARY, which a
       * signature never does: a signature request is a 32-byte digest, one
       * keyhandle. A PKCS#1 v1.5 ciphertext is a whole modulus - 256 bytes for
       * RSA-2048 - so it goes as 171 + 85, two keyhandles with opt3 1 then 2. The
       * fix moved the high-water mark to its own static, and what this asserts is
       * that BOTH chunks land: the device's own dump must be the full 256 bytes,
       * not the 28-byte tail.
       */
      if (!transit.probe().ok) skip(transit.probe().why);

      const key = await loadKey(device,
        { bits: 2048, typeNibble: 2, slot: SLOT_DECRYPT, feature: FEATURE_DECRYPT },
        { signal, assert, log });

      const secret = crypto.randomBytes(32);
      const sealed = crypto.publicEncrypt({
        key: verifier(key.published), padding: crypto.constants.RSA_PKCS1_PADDING,
      }, secret);
      assert.equal(sealed.length, 256, 'a PKCS#1 v1.5 ciphertext is one modulus long');
      const keyhandles = Math.ceil(sealed.length / REQUEST_CHUNK);
      log(`ciphertext ${sealed.length} bytes over ${keyhandles} keyhandle(s)`);
      assert.equal(keyhandles, 2, 'this test is pointless unless the request spans two keyhandles');

      const ctap = new Ctap2(device, { signal });
      await ctap.init();
      const sess = await handshake(device, ctap, { signal, assert, log });

      /* Clear first, then count - see signOverTunnel(). */
      device.log.clear();
      const primed = device.log.count(PRIMED);

      const { nextOpt3 } = await sendSealed(ctap, sess, {
        cmd: okmsg.MSG.OKDECRYPT, slot: SLOT_DECRYPT, payload: sealed,
      }, { timeoutMs: 30000, signal });

      /*
       * The assertion this test exists for. If the high-water mark were still
       * being clobbered, the first keyhandle would be dropped and this would be
       * 28 bytes - the tail alone - which is the exact shape the comment
       * describes.
       */
      await device.log.waitForCount(PRIMED, primed + 1, { timeoutMs: 30000, signal });
      const received = pqc.packetFromConsole(device);
      log(`device received ${received && received.length} bytes of the ${sealed.length} sent`);
      assert.equal(received && received.length, sealed.length,
        `the device accumulated ${received && received.length} bytes of a ${sealed.length}-byte ` +
        'request - a short count means an early keyhandle was dropped silently, which is ' +
        'the last_request_opt3 failure from ok_extension.cpp:150');
      assert.bytes(received, sealed, 'the device received different bytes than were sent');

      device.press(1);
      const answer = await poll(ctap, sess, 32 + transit.OVERHEAD, { opt3: nextOpt3 },
        { timeoutMs: 30000, signal });
      const plaintext = transit.open(sess, answer.bytes).subarray(0, 32);
      log(`device plaintext ${plaintext.toString('hex')}`);
      log(`expected         ${secret.toString('hex')}`);

      assert.bytes(plaintext, secret,
        'the device did not recover the secret sealed to its own published modulus');
    });
});
