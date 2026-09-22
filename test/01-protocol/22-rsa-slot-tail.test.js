/*
 * The RSA slot tail: a smaller key stored after a larger one is READ must leave
 * NOTHING of the larger one in flash.
 *
 * THIS FILE USED TO PIN THE LEAK AND NOW PINS ITS ABSENCE. It was written to
 * settle by measurement a question `19-rsa-keys` had raised by reading, and it
 * settled it the wrong way round: a 2048-bit key, read once and then written
 * over with a 1024-bit key, left 85 contiguous bytes of its own P||Q on the
 * medium in the clear. The fix is two lines in `rsa_priv_flash()`:
 *
 *     memset(rsa_private_key + keysize, 0, MAX_RSA_KEY_SIZE - keysize);
 *     okcore_aes_gcm_encrypt(rsa_private_key, buffer[5], buffer[6], profilekey, keysize);
 *
 * plus clamping each chunk copy to `keysize - packet_buffer_offset` instead of a
 * literal 57, so the host's report padding never enters the tail either.
 *
 * SO THE ASSERTIONS ARE NEGATIVE NOW, and that changes what this file owes the
 * reader. An absence measured with a broken instrument looks exactly like an
 * absence measured with a working one, and this file has three ways to have a
 * broken instrument - a stale flash.bin, a mapping that never reached the file,
 * and the word-order transform in `flash()`. It therefore declares
 * `negative: true` and proves the instrument in every test before believing
 * anything it does not find. That is the discipline `--controls` gates and the
 * one `lib/harness.js` cites this file for.
 *
 * The two questions are still measured SEPARATELY, because they were different
 * severities while the leak was live and the distinction is what a future
 * regression would be judged against:
 *
 *   1. Is the previous key's plaintext present in flash at all?
 *   2. Is any of it reachable through a normal device operation, rather than
 *      only by reading raw flash?
 *
 * THE MECHANISM UNDER TEST, so a regression can be checked against a prediction
 * rather than fished for. Three sites in `rsa_priv_flash()` and
 * `okcore_flashget_RSA()` (okcore.cpp):
 *
 *   a. `okcore_flashget_RSA()` decrypts a stored key IN PLACE into the
 *      `rsa_private_key` global - so after any READ of an RSA slot, that global
 *      holds `type * 128` bytes of somebody's private key in the clear.
 *   b. `rsa_priv_flash()` accumulates a new key into the SAME global, and only
 *      as far as the new key goes: the chunk guard for a 1024-bit key stops at
 *      offset 114, so bytes past 171 were never written.
 *   c. It then encrypts only `keysize` bytes - `okcore_aes_gcm_encrypt(...,
 *      keysize)` - and copies **all MAX_RSA_KEY_SIZE (512)** bytes of the global
 *      into the flash sector. Everything past `keysize` goes to flash exactly as
 *      it sits in RAM, which is why (c) is the site that matters and why the fix
 *      is a memset rather than a shorter copy.
 *
 * What that produced, for a 2048-bit key read and then a 1024-bit key stored:
 *
 *   flash slot-B region, offset 0..127     E(B), the new key, encrypted
 *   flash slot-B region, offset 128..170   the third chunk's report padding
 *   flash slot-B region, offset 171..255   *** key A's PLAINTEXT, bytes 171..255
 *   flash slot-B region, offset 256..511   whatever the global held before
 *
 * A's P||Q is P at 0..127 and Q at 128..255, so bytes 171..255 were the LOW 85
 * bytes of A's 128-byte Q. That number is why this was worth fixing rather than
 * documenting: known low bits of one factor is the Coppersmith setting, and 85
 * of 128 bytes is far past the half-the-bits threshold that attack needs. The
 * test still reports the longest run it finds rather than a boolean, so a
 * PARTIAL regression - a fix that shortens the residue without removing it -
 * reads as the finding it would be.
 *
 * WHY IT NEEDS THE READ IN THE MIDDLE. Without step (a) the global holds only
 * zeros from boot, and the tail written to flash is a tail of zeros - which is
 * why this went unnoticed and why `19-rsa-keys` does not trip it. The read is
 * not exotic: `OKGETPUBKEY` does it, and so does every `OKSIGN` and `OKDECRYPT`,
 * because all three call `okcore_flashget_RSA()` first.
 *
 * SURFACES - see PRODUCTION.md. The first test's oracle is `flash.bin` itself,
 * which is not a client-visible surface at all: it is the emulator's backing
 * store, so this file carries `storage-files` and is emulated-only BY ITS
 * SUBJECT rather than by convenience. That is exactly the point of separating
 * the two questions - test 1 says the bytes are there, and only something with
 * raw flash access can see them. The second test is on the vendor surface and
 * says the device itself will not hand them over.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const { describe, it } = require('../../lib/harness');
const { IFACE, okmsg } = require('../../lib/device');
const { PINS } = require('../../lib/config');
const pqc = require('../../lib/pqc');

const CHUNK = 57;
const REPORT = 64;
const MAX_RSA_KEY_SIZE = 512;           // okcore.h - the per-slot flash stride

const FEATURE_DECRYPT = 32;

const SLOT_A = 1;                       // holds the 2048-bit key
const SLOT_B = 2;                       // the 1024-bit key written afterwards

describe('the RSA slot tail', {
  state: 'initialized',
  requires: ['crypto', 'storage-files'],
  negative: true,                       // every assertion below is an absence
  timeoutMs: 300000,
}, () => {
  /** A keypair, as P||Q for the device and n for checking what it publishes. */
  function keypair(bits) {
    const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: bits });
    const jwk = privateKey.export({ format: 'jwk' });
    const p = Buffer.from(jwk.p, 'base64url');
    const q = Buffer.from(jwk.q, 'base64url');
    return { p, q, pq: Buffer.concat([p, q]), n: Buffer.from(jwk.n, 'base64url') };
  }

  /** Load a key into an RSA slot. Needs config mode; leaves it. */
  async function store(device, { slot, typeByte, pq }, { signal, assert }) {
    const since = device.mark(IFACE.VENDOR);
    for (let i = 0; i < pq.length; i += CHUNK) {
      device.sendVendor({
        msg: okmsg.MSG.OKSETPRIV, slot, field: typeByte, payload: pq.subarray(i, i + CHUNK),
      });
      await device.sleep(150, { signal });
    }
    const ack = await device.waitHid(IFACE.VENDOR,
      { since, match: /Successfully|Error/, timeoutMs: 20000, signal });
    const said = okmsg.text(ack).trim();
    assert.match(said, /Successfully set RSA Key/, `storing into slot ${slot}: ${said}`);
  }

  /** Read `want` bytes of a vendor answer as consecutive reports. */
  async function collect(device, since, want, { signal, timeoutMs = 25000 }) {
    const expected = Math.ceil(want / REPORT);
    const deadline = Date.now() + timeoutMs;
    let reports = device.reportsSince(IFACE.VENDOR, since);
    while (reports.length < expected && Date.now() < deadline) {
      await device.sleep(100, { signal });
      reports = device.reportsSince(IFACE.VENDOR, since);
    }
    return { reports, bytes: Buffer.concat(reports).subarray(0, want) };
  }

  async function modulus(device, slot, want, { signal }) {
    const since = device.mark(IFACE.VENDOR);
    device.sendVendor({ msg: okmsg.MSG.OKGETPUBKEY, slot, field: 0 });
    return collect(device, since, want, { signal });
  }

  /**
   * The device's flash, as LOGICAL bytes.
   *
   * FLASH.BIN IS NOT A FLAT BYTE IMAGE, and this cost the second run of this
   * file. `okcore_flashset_common()` (okcore.cpp:3233) packs each four bytes into
   * one longword BIG-endian - `ptr[z]` becomes the most significant byte - and
   * hands it to `flashProgramWord()`. Storing that longword on a little-endian
   * core puts `ptr[z]` at the HIGHEST address of the word, so every aligned
   * 4-byte group is byte-reversed relative to the bytes the firmware thinks it
   * wrote. `okcore_flashget_common()` mirrors the unpack, so the device is
   * perfectly self-consistent and only an out-of-band reader ever sees it.
   *
   * It is FIRMWARE behaviour, not an emulator artifact - the same words land
   * byte-reversed in a real key's flash - so anyone dumping a physical key's
   * flash has to do this too.
   *
   * Measured, when a label probe went missing: `oktflashprobe960` was written and
   * `ftkohsalborp069e` was on the medium. Un-reversing each word gives the label
   * back exactly, at 0x3c820.
   *
   * Read after a restart rather than live, which is belt and braces rather than
   * required: the mapping is MAP_SHARED file-backed (see lib/host/device-host.js)
   * so writes are visible immediately, but what this file is about is what is
   * durably on the medium.
   */
  function flash(device) {
    const raw = fs.readFileSync(path.join(device.storageDir, 'flash.bin'));
    const out = Buffer.alloc(raw.length);
    for (let i = 0; i + 4 <= raw.length; i += 4) {
      out[i] = raw[i + 3];
      out[i + 1] = raw[i + 2];
      out[i + 2] = raw[i + 1];
      out[i + 3] = raw[i];
    }
    return out;
  }

  /** Longest run of `needle` present contiguously in `hay`, and where. */
  function longestRun(hay, needle) {
    for (let len = needle.length; len >= 8; len -= 1) {
      for (let start = 0; start + len <= needle.length; start += 1) {
        const at = hay.indexOf(needle.subarray(start, start + len));
        if (at >= 0) return { len, at, offsetInKey: start };
      }
    }
    return { len: 0, at: -1, offsetInKey: -1 };
  }

  /**
   * Arrange the leak: store A (2048), READ it - which is what puts its
   * plaintext in the global - then store B (1024) into another slot WITHOUT a
   * reboot in between.
   *
   * THE NO-REBOOT PART IS THE WHOLE EXPERIMENT, and getting it wrong is how the
   * first run of this file measured nothing at all. `pqc.readyForKeygen()`
   * restarts before entering config mode - deliberately, and documented as such,
   * because a reboot is the cheapest way to know which state the device is in -
   * and a reboot re-runs `setup()`, which reconstructs the firmware's C++
   * globals. `rsa_private_key` comes back zeroed and there is no residue left to
   * carry. The null result was the harness, not the firmware.
   *
   * So the read and the write have to happen in ONE boot, and they can:
   *
   *   OKGETPUBKEY  needs unlocked and NOT config mode (it is refused there)
   *   OKSETPRIV    needs config mode
   *   entering config mode  is a long press of 6, which relocks and re-auths -
   *                         and does NOT reboot. The branch in OnlyKey.ino sets
   *                         `configmode = true`, clears `unlocked`, and returns.
   *                         No CPU_RESTART anywhere in it.
   *
   * `device.enterConfigMode()` is exactly that sequence and nothing more, so it
   * is used directly here in place of `readyForKeygen()`. Which also bounds the
   * finding usefully: the residue lives in RAM, so it only ever reaches flash
   * within the same boot as the read that produced it.
   */
  async function arrange(device, { signal, assert, log }) {
    const a = keypair(2048);
    const b = keypair(1024);

    await pqc.readyForKeygen(device, { signal });
    await store(device, { slot: SLOT_A, typeByte: 2 | FEATURE_DECRYPT, pq: a.pq },
      { signal, assert });

    /* OKGETPUBKEY is refused in config mode, so leave it - and this is the last
     * reboot before the measurement. */
    await device.restart({ signal });
    await device.ensureUnlocked(PINS.primary, { signal });
    const published = await modulus(device, SLOT_A, 256, { signal });
    assert.bytes(published.bytes, a.n, 'slot A did not come back with its own modulus');
    log('slot A read back - its plaintext is now in the rsa_private_key global');

    /* NO RESTART. See above - a reboot here zeroes the global and the whole
     * experiment measures nothing. */
    await device.enterConfigMode(PINS.primary, { signal });
    await store(device, { slot: SLOT_B, typeByte: 1 | FEATURE_DECRYPT, pq: b.pq },
      { signal, assert });

    await device.restart({ signal });
    await device.ensureUnlocked(PINS.primary, { signal });
    return { a, b };
  }

  /**
   * Prove flash.bin reflects what the device wrote, before believing anything it
   * does NOT contain.
   *
   * A null result on a raw-image search is worthless without this: if the
   * mapping never reached the file, or the file is a stale copy, or the bytes are
   * not in the order the search expects, every search comes back empty and reads
   * as "no leak". All three were live possibilities here and the third was true -
   * see `flash()`. Slot LABELS are the cheap control: `set_slot()` case 1 writes
   * them with no `okcore_aes_gcm_encrypt()` call at all, so a label is on the
   * medium in the clear, and finding one says both that the file is current and
   * that the byte order is being handled.
   *
   * Exactly 16 characters, because `EElen_label` is 16 (okeeprom.h:95) and
   * `okcore_flashset_label()` writes that many - a longer marker is truncated on
   * the device and then never matches, which is its own way of looking like an
   * absence.
   */
  async function instrumentWorks(device, { signal, assert, log }) {
    const marker = `oktprobe${String(process.pid).padStart(8, '0')}`.slice(0, 16);
    const since = device.mark(IFACE.VENDOR);
    device.sendVendor({ msg: okmsg.MSG.OKSETSLOT, slot: 3, field: 1, payload: marker });
    const ack = await device.waitHid(IFACE.VENDOR,
      { since, match: /Successfully set|Error/, timeoutMs: 8000, signal });
    assert.ok(!/Error/.test(okmsg.text(ack)), `the label probe was refused: ${okmsg.text(ack)}`);

    await device.restart({ signal });
    await device.ensureUnlocked(PINS.primary, { signal });

    const image = flash(device);
    const at = image.indexOf(Buffer.from(marker, 'latin1'));
    log(`instrument control: the label probe is at flash offset ` +
      `${at >= 0 ? `0x${at.toString(16)}` : 'NOT FOUND'}`);
    assert.control(
      'a slot label the device wrote is findable in flash.bin, so this file can see ' +
      'the medium and is handling its word order', at >= 0);

    /* Second control, on the SEARCH rather than the image: longestRun() is what
     * every absence below is measured with, so it has to be shown finding
     * something that is really there before its misses count. */
    const found = longestRun(image, Buffer.from(marker, 'latin1'));
    assert.control(
      'longestRun() locates a byte string that IS present in this image',
      found.len >= 8 && found.at >= 0);
    return marker;
  }

  it('a 1024-bit key stored after a 2048-bit key is READ leaves NOTHING of it in flash.bin',
    async ({ device, assert, signal, log }) => {
      /*
       * SURFACE: flash.bin - not a client-visible surface at all. See the header:
       * this test's whole subject is what is on the medium, so it is
       * emulated-only by its subject and carries `storage-files`.
       */
      await device.ensureUnlocked(PINS.primary, { signal });
      await instrumentWorks(device, { signal, assert, log });

      const { a, b } = await arrange(device, { signal, assert, log });

      const image = flash(device);
      log(`flash.bin is ${image.length} bytes`);

      /* Where the residue used to be: bytes 171..255 of A's P||Q, the low 85
       * bytes of Q. Reported by name so a regression is recognised as THIS
       * defect returning rather than as some new one. */
      const predicted = a.pq.subarray(171, 256);
      const at = image.indexOf(predicted);
      log(`the old residue window (85 bytes at key offset 171) is ` +
        `${at >= 0 ? `PRESENT at flash 0x${at.toString(16)}` : 'absent'}`);

      /* Measured independently of that window, so a residue that moved is still
       * caught: the longest run of A's plaintext anywhere in the image. */
      const run = longestRun(image, a.pq);
      log(`longest contiguous run of A's P||Q in flash: ${run.len} bytes` +
        (run.at >= 0
          ? `, key offset ${run.offsetInKey}, flash offset 0x${run.at.toString(16)}, ` +
            `${run.at % MAX_RSA_KEY_SIZE} bytes into a ${MAX_RSA_KEY_SIZE}-byte slot stride`
          : ''));

      /*
       * THE LENGTH IS THE FINDING, NOT THE BOOLEAN, and that is why the bound is
       * 8 rather than 0. longestRun() gives up below 8 bytes, and an 8-byte
       * coincidence in a 128 KiB image is ordinary; what is not ordinary is a
       * run long enough to be key material. Known low bits of one factor is the
       * Coppersmith setting and half the bits is enough - 64 of Q's 128 bytes
       * would already factor the modulus - so any run this instrument can see at
       * all is reported as a regression rather than quietly tolerated.
       */
      assert.absent(run.len === 0,
        `${run.len} contiguous bytes of the 2048-bit key's P||Q are on the medium ` +
        `(key offset ${run.offsetInKey}) - the slot tail is carrying plaintext again, ` +
        'which means the memset before okcore_aes_gcm_encrypt() in rsa_priv_flash() ' +
        'is gone or the chunk clamp is letting the global fill past keysize');

      /* And B, the key that was actually being stored, is not in the clear
       * either - which is what says a hit above would be a tail-of-the-buffer
       * defect rather than the slot encryption being broken outright. */
      const bRun = longestRun(image, b.pq);
      log(`longest run of B's own P||Q: ${bRun.len} bytes`);
      assert.absent(bRun.len === 0,
        `the key being STORED is itself in the clear (${bRun.len} bytes) - that is a ` +
        'different and larger defect than the tail this file is about');
    });

  it('OKGETPUBKEY, OKSIGN and OKDECRYPT are bounded by the slot\'s declared type, so the tail is not reachable over the vendor interface',
    async ({ device, assert, signal, log }) => {
      /*
       * SURFACE: vendor - and this is the half that decides the severity.
       *
       * Every reader of an RSA slot is bounded by the type byte in EEPROM:
       * `okcore_flashget_RSA()` reads exactly `type * 128` bytes, and the three
       * messages that use a key all go through it. The backup path is bounded the
       * same way and by the same expression - `memcpy(large_temp + off + 3,
       * rsa_private_key, (type * 128))` (okcore.cpp, the RSA loop in `backup()`).
       * READ rather than measured, and said plainly as such; what is measured
       * here is the vendor interface, which is the surface a client has.
       *
       * The one way to make the device read further into slot B would be to
       * declare a bigger type for it - and that cannot be done without a write
       * that overwrites the residue first, because `rsa_priv_flash()` only
       * reaches `okeeprom_eeset_rsakey()` inside the branch that fires when the
       * accumulated offset has passed the new key's size. So the tail cannot be
       * promoted into readability. That is asserted below rather than argued.
       */
      /* This test ends on an absence in the flash IMAGE as well as one in the
       * vendor answer, so it needs the image instrument proved too - the vendor
       * controls below do not cover flash.bin. */
      await device.ensureUnlocked(PINS.primary, { signal });
      await instrumentWorks(device, { signal, assert, log });

      const { a, b } = await arrange(device, { signal, assert, log });

      /* Slot B is type 1, so its answer is 128 bytes and no more. */
      const answer = await modulus(device, SLOT_B, MAX_RSA_KEY_SIZE, { signal });
      const bounded = answer.bytes.subarray(0, 128);
      log(`slot B answered ${answer.reports.length} reports`);

      assert.equal(answer.reports.length, 2,
        `a 1024-bit modulus is 2 reports; ${answer.reports.length} means the device sent ` +
        'more than the declared type, which would be the tail coming out');

      /*
       * THE CONTROL FOR THIS TEST is that the answer is B's own modulus. An
       * absence of A's bytes in an answer that is empty, or truncated, or from
       * the wrong slot, would be an absence of everything - and would pass.
       */
      assert.control('slot B answered with its own 1024-bit modulus, so the search ' +
        'below is running over a real answer',
        Buffer.compare(bounded, b.n) === 0);
      assert.control('longestRun() locates a byte string that IS present in that answer',
        longestRun(Buffer.concat(answer.reports), b.n).len >= 8);

      const leaked = longestRun(Buffer.concat(answer.reports), a.pq);
      log(`longest run of A's P||Q in slot B's answer: ${leaked.len} bytes`);
      assert.absent(leaked.len === 0,
        `slot B's public-key answer carries ${leaked.len} contiguous bytes of the OTHER ` +
        'key\'s private material - the tail IS reachable over the vendor interface, which ' +
        'is far more serious than a raw-flash finding');

      /*
       * AND PROMOTING THE SLOT DOES NOT EXPOSE ANYTHING EITHER. While the leak
       * was live this block asserted that a larger type OVERWRITES the residue
       * (`after < before`), which was the argument that the tail could not be
       * promoted into readability. With the tail zeroed there is no residue to
       * overwrite, so the same concern is now stated directly: nothing of A is
       * in the image before the promotion and nothing is in it after.
       */
      const before = longestRun(flash(device), a.pq).len;
      const c = keypair(2048);
      await pqc.readyForKeygen(device, { signal });
      await store(device, { slot: SLOT_B, typeByte: 2 | FEATURE_DECRYPT, pq: c.pq },
        { signal, assert });
      await device.restart({ signal });
      await device.ensureUnlocked(PINS.primary, { signal });

      const image = flash(device);
      const after = longestRun(image, a.pq).len;
      log(`A's residue: ${before} bytes before slot B was promoted to 2048-bit, ` +
        `${after} after`);
      /* No control is registered here: `|| true` would be a control that cannot
       * fail, which is worse than none. The two that fired above are this test's
       * instrument proof and they cover the same search. */
      assert.absent(before === 0 && after === 0,
        `promoting slot B to a larger type left ${after} contiguous bytes of A's private ` +
        'material in flash (there were ' + `${before}` + ' before) - a slot whose declared ' +
        'type can be raised over live residue is the case that makes the tail readable');
    });
});
