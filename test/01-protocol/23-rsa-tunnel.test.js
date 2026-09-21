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
 * `chunk_len = remaining > MAX_LARGE_RESP_CHUNK ? MAX_LARGE_RESP_CHUNK :
 * remaining`, so on a reading of the code even 512 is served whole. **That is
 * exactly what reading cannot be trusted for**: 512 is simultaneously
 * MAX_LARGE_RESP_CHUNK and MAX_RSA_KEY_SIZE, and one `>` that should be `>=`, or
 * a cursor compared before it is advanced, splits it into 512 + 0 and puts the
 * host back in the 71-bytes-per-chunk failure. So RSA-4096 is driven first and
 * RSA-2048 second.
 *
 * THE CLIENT HAD TO BE BUILT, and `lib/device/transit.js` is where it went.
 * `tunnel.js` alone cannot reach any command but OKCONNECT:
 * `bridge_to_onlykey()` runs `okcrypto_aes_crypto_box()` over the whole payload
 * before it looks at the command, so an unencrypted request is dispatched as
 * noise. Written in the kit rather than borrowed from the shipped library
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
const REQUEST_CHUNK = 228;              // u2fSignBuffer's 57 * 4
const MAX_LARGE_RESP_CHUNK = 512;       // ok_extension.cpp:116
const FEATURE_SIGN = 64;
const FEATURE_DECRYPT = 32;
const SLOT_SIGN = 2;                    // slotid() sends OKSIGN here
const SLOT_DECRYPT = 1;                 // ...and everything else here
const FIELD_STORED_CHALLENGE = 22;
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

    return transit.transitKey(devicePublic, ours.privateKey);
  }

  /**
   * Send a tunnelled request, sealed, in 228-byte chunks with an advancing opt3.
   *
   * opt3 must strictly increase: `last_request_opt3` drops any packet whose opt3
   * is not greater than the last one, which is the Windows 10 1903
   * double-fire guard. opt2 marks the final chunk and is what makes the firmware
   * set `recv_buffer[6]` to the real length instead of 0xFF.
   */
  async function sendSealed(ctap, key, { cmd, slot, payload, startAt = 1 }, opts) {
    let opt3 = startAt;
    let last = null;
    for (let i = 0; i < payload.length; i += REQUEST_CHUNK) {
      const piece = payload.subarray(i, i + REQUEST_CHUNK);
      const final = i + REQUEST_CHUNK >= payload.length;
      last = await tunnel.send(ctap, {
        cmd, opt1: slot, opt2: final ? 1 : 0, opt3, data: transit.box(key, piece),
      }, opts);
      opt3 += 1;
    }
    return { reply: last, nextOpt3: opt3 };
  }

  /**
   * Poll until the whole response has been served, counting the chunks.
   *
   * The chunk count is the assertion this file exists for, so it is returned
   * rather than hidden: a 512-byte response arriving in one chunk and the same
   * bytes arriving in two say different things about `send_stored_response()`.
   */
  async function poll(ctap, key, want, { opt3, tries = 8 }, opts) {
    const chunks = [];
    let next = opt3;
    for (let i = 0; i < tries && Buffer.concat(chunks).length < want; i++) {
      const reply = await tunnel.send(ctap, {
        cmd: 0xF3,                                  // OKPING, the poll
        opt3: next, data: transit.box(key, Buffer.alloc(16)),
      }, opts);
      next += 1;
      if (reply.error) throw new Error(`the device refused the poll: ${reply.error}`);
      if (reply.data && reply.data.length > 1) chunks.push(reply.data);
    }
    return { chunks, bytes: Buffer.concat(chunks) };
  }

  /** Drive one signature end to end and return everything worth asserting on. */
  async function signOverTunnel(device, ctap, key, transitKey, { signal, assert, log }) {
    const message = Buffer.from(`okt tunnel rsa ${key.pq.length * 8}`);
    const digest = crypto.createHash('sha256').update(message).digest();

    /* CLEAR FIRST, THEN COUNT. Counting before the clear reads a marker the
     * PREVIOUS test left, so the wait below asks for one more than can arrive and
     * times out - which passes alone and fails in sequence. Caught by the
     * natural-order run, which is what it is for. */
    device.log.clear();
    const primed = device.log.count(PRIMED);

    const { nextOpt3 } = await sendSealed(ctap, transitKey, {
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
    const answer = await poll(ctap, transitKey, key.pq.length, { opt3: nextOpt3 },
      { timeoutMs: 30000, signal });

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
     * The box is one keystream XORed, so opening it is the same call as sealing.
     * It is applied to the WHOLE staged response before any chunking, so the
     * concatenation of the chunks is what gets opened, not each chunk on its own.
     */
    const opened = transit.box(transitKey, answer.bytes);

    return { message, digest, ...answer, sealed: answer.bytes, bytes: opened };
  }

  it('an RSA-4096 signature is exactly one MAX_LARGE_RESP_CHUNK and arrives whole',
    async ({ device, assert, signal, log, skip }) => {
      /*
       * SURFACE: FIDO for the operation, vendor for the modulus, console for the
       * two things no client reports. THE boundary case: 512 bytes is both
       * MAX_LARGE_RESP_CHUNK and MAX_RSA_KEY_SIZE.
       */
      /*
       * IT WAS GATED OFF BY DEFAULT, AND THE GATE WAS THE BUG REPORT. Loading a
       * 4096-bit key used to abort the firmware: `rsa_priv_flash()`'s type-4
       * branch guards on `packet_buffer_offset <= 456` and then memcpy'd a
       * literal 57, so the ninth chunk wrote index 512 of a 512-byte array. See
       * FINDING-rsa4096-overflow.md.
       *
       * It could not be pinned as a passing test the way a wrong ANSWER can:
       * the failure killed the device host, and the runner classifies that as a
       * run-level abort before any assertion executes, so nothing inside a test
       * could observe it. Left ungated it aborted every run of this file and
       * both its order gates - hence `OKT_EXPECT_RSA4096_FIX`, which was there
       * to be removed by whoever clamped the copy.
       *
       * The copy is clamped, so the variable is gone and this runs by default.
       * It is now simply the boundary test the file was written for: 512 bytes
       * is both MAX_LARGE_RESP_CHUNK and MAX_RSA_KEY_SIZE.
       */
      /*
       * STILL EMULATED ONLY, FOR A DIFFERENT REASON THAN BEFORE.
       *
       * The old reason was that the write was known to be out of bounds and
       * only `_FORTIFY_SOURCE` - the EMULATOR's build, not a key's - would stop
       * it rather than let it land silently on whatever follows
       * `rsa_private_key`. That reason is spent: there is no overflow to catch.
       *
       * What replaces it is provenance. The emulator stages and builds firmware
       * from this checkout, so it demonstrably carries the clamp. A physical key
       * runs whatever is flashed on it, and nothing here can tell whether that
       * build has the fix - so an unguarded run would aim the old out-of-bounds
       * write at a real device with nothing to catch it. The capability check
       * stays until the suite can read a firmware version it trusts.
       */
      if (!device.capabilities.has('emulated')) {
        skip('a 4096-bit key load was an out-of-bounds WRITE before the clamp ' +
          '(FINDING-rsa4096-overflow.md); only the emulator is built from this ' +
          'checkout and so known to carry the fix - a key runs whatever is ' +
          'flashed on it');
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
      const transitKey = await handshake(device, ctap, { signal, assert, log });

      const got = await signOverTunnel(device, ctap, key, transitKey, { signal, assert, log });
      log(`${got.chunks.length} chunk(s), ${got.bytes.length} bytes of signature`);

      assert.equal(got.bytes.length, MAX_LARGE_RESP_CHUNK,
        `expected a ${MAX_LARGE_RESP_CHUNK}-byte signature, got ${got.bytes.length} - ` +
        'a short count here IS the ctap_end_get_assertion failure the alpha report predicted');
      assert.equal(got.chunks.length, 1,
        `512 bytes should be served in ONE chunk; ${got.chunks.length} means the cursor or ` +
        'the comparison in send_stored_response() splits at the boundary');

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
      const transitKey = await handshake(device, ctap, { signal, assert, log });

      const got = await signOverTunnel(device, ctap, key, transitKey, { signal, assert, log });
      log(`${got.chunks.length} chunk(s), ${got.bytes.length} bytes of signature`);

      assert.equal(got.bytes.length, 256, `expected 256 bytes, got ${got.bytes.length}`);
      assert.equal(got.chunks.length, 1, 'a 256-byte response is half a chunk');
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
       * RSA-2048 - so it goes as 228 + 28, two keyhandles with opt3 1 then 2. The
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
      const transitKey = await handshake(device, ctap, { signal, assert, log });

      /* Clear first, then count - see signOverTunnel(). */
      device.log.clear();
      const primed = device.log.count(PRIMED);

      const { nextOpt3 } = await sendSealed(ctap, transitKey, {
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
      const answer = await poll(ctap, transitKey, 32, { opt3: nextOpt3 },
        { timeoutMs: 30000, signal });
      const plaintext = transit.box(transitKey, answer.bytes).subarray(0, 32);
      log(`device plaintext ${plaintext.toString('hex')}`);
      log(`expected         ${secret.toString('hex')}`);

      assert.bytes(plaintext, secret,
        'the device did not recover the secret sealed to its own published modulus');
    });
});
