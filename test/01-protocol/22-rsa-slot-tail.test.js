/*
 * The RSA slot tail: a smaller key stored after a larger one is READ must not
 * leave the larger one's plaintext in flash.
 *
 * This file measured a real defect and now pins its fix. The mechanism below is
 * kept in full because the fix is one `memset` and the only way to judge that
 * one line is to understand what it is for - and because the same shape (a
 * plaintext key global that outlives its consumer) is still present for
 * `ecc_private_key` and was deliberately left for a separate change.
 *
 * It measures two things SEPARATELY, because they were different severities and
 * conflating them would have overstated the finding:
 *
 *   1. Is the previous key's plaintext present in flash at all?
 *   2. Is any of it reachable through a normal device operation, rather than
 *      only by reading raw flash?
 *
 * THE MECHANISM, so the measurement can be checked against a prediction rather
 * than fished for. Three sites in `rsa_priv_flash()` and
 * `okcore_flashget_RSA()` (okcore.cpp):
 *
 *   a. `okcore_flashget_RSA()` decrypts a stored key IN PLACE into the
 *      `rsa_private_key` global - so after any READ of an RSA slot, that global
 *      holds `type * 128` bytes of somebody's private key in the clear. STILL
 *      TRUE; the fix does not change it.
 *   b. `rsa_priv_flash()` accumulates a new key into the SAME global, and only
 *      as far as the new key goes: the chunk guard for a 1024-bit key stops at
 *      offset 114, so bytes past 171 were never written. Since the clamp it
 *      stops at 128, so bytes past 128 are never written.
 *   c. It then encrypts only `keysize` bytes - `okcore_aes_gcm_encrypt(...,
 *      keysize)` - and copies **all MAX_RSA_KEY_SIZE (512)** bytes of the global
 *      into the flash sector. Everything past `keysize` goes to flash exactly as
 *      it sits in RAM. STILL TRUE, and it is why the fix has to be a `memset`
 *      of `keysize..MAX_RSA_KEY_SIZE` immediately before that encrypt rather
 *      than a narrower copy.
 *
 * WHAT THIS USED TO MEASURE, for a 2048-bit key read and then a 1024-bit key
 * stored - the prediction the file was written against:
 *
 *   flash slot-B region, offset 0..127     E(B), the new key, encrypted
 *   flash slot-B region, offset 128..170   the third chunk's report padding
 *   flash slot-B region, offset 171..255   *** key A's PLAINTEXT, bytes 171..255
 *   flash slot-B region, offset 256..511   whatever the global held before
 *
 * A's P||Q is P at 0..127 and Q at 128..255, so bytes 171..255 were the LOW 85
 * bytes of A's 128-byte Q. That number decided how bad it was: known low bits of
 * one factor is the Coppersmith setting, and 85 of 128 bytes is far past the
 * half-the-bits threshold that attack needs.
 *
 * WHAT IT MEASURES NOW. The same image, expected as E(B) then zeros, and the
 * longest run of A's plaintext anywhere in it expected to be 0 rather than 85.
 * The tests assert ZERO and not "shorter than 32", because the clamp alone
 * would have REMOVED the padding at 128..170 and widened the residue from 85
 * bytes to 384 - a partial fix here is worse than the defect, so a shortened
 * residue must not read as a pass.
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
 * the two questions - test 1 says whether the bytes are there, and only
 * something with raw flash access could see them. The second test is on the
 * vendor surface and says the device itself will not hand them over.
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

    const at = flash(device).indexOf(Buffer.from(marker, 'latin1'));
    log(`instrument control: the label probe is at flash offset ` +
      `${at >= 0 ? `0x${at.toString(16)}` : 'NOT FOUND'}`);
    assert.ok(at >= 0,
      'a slot label written by the device is not in flash.bin, so this file cannot ' +
      'see the medium at all and no absence it reports means anything');
  }

  it('a 1024-bit key stored after a 2048-bit key is READ leaves NO plaintext in flash.bin',
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

      /* The prediction is bytes 171..255 of A's P||Q - the low 85 bytes of Q. */
      const predicted = a.pq.subarray(171, 256);
      const at = image.indexOf(predicted);
      log(`predicted ${predicted.length}-byte residue at flash offset ` +
        `${at >= 0 ? `0x${at.toString(16)}` : 'NOT FOUND'}`);

      /* Measured independently of the prediction, so a wrong prediction reports
       * the truth rather than a miss: the longest run of A's plaintext anywhere
       * in the image, and where in the key it starts. */
      const run = longestRun(image, a.pq);
      log(`longest contiguous run of A's P||Q in flash: ${run.len} bytes, ` +
        `key offset ${run.offsetInKey}, flash offset ` +
        `${run.at >= 0 ? `0x${run.at.toString(16)}` : 'n/a'}`);

      /* A's own slot holds it ENCRYPTED, so a hit is not simply "the key is in
       * its own slot in the clear" - and B's slot is 512 bytes further on. */
      if (run.at >= 0) {
        log(`that run sits ${run.at % MAX_RSA_KEY_SIZE} bytes into a ` +
          `${MAX_RSA_KEY_SIZE}-byte slot stride`);
      }

      /*
       * ZERO, and not merely "shorter than it was".
       *
       * rsa_priv_flash() now zeroes keysize..MAX_RSA_KEY_SIZE before the
       * encrypt, so no byte of A reaches the medium at all. While the defect
       * was live this asserted `run.len >= 64`, on the grounds that known low
       * bits of one factor is the Coppersmith setting and half of Q is enough
       * to factor the modulus - so a partial fix that merely SHORTENED the
       * residue still had to read as a finding rather than as a pass.
       *
       * That reasoning inverts exactly. Anything above zero means the tail is
       * not being cleared, and a shortened residue is still a leak, so the
       * threshold here is not 64 or 32 but none at all.
       */
      assert.equal(run.len, 0,
        `${run.len} contiguous plaintext bytes of the older 2048-bit key are ` +
        'still on the medium, so the slot tail is not being zeroed before the ' +
        'encrypt');
      assert.equal(at, -1,
        'the predicted 85-byte residue at key offset 171 is still in flash.bin');
      log('VERDICT: no plaintext of the 2048-bit key is on the medium');

      /* And B, the key that was actually being stored, is NOT in the clear -
       * which is what says this is a tail-of-the-buffer defect rather than the
       * slot encryption being broken outright. */
      const bRun = longestRun(image, b.pq);
      log(`longest run of B's own P||Q: ${bRun.len} bytes`);
      assert.ok(bRun.len < 32,
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
      const { a } = await arrange(device, { signal, assert, log });

      /* Slot B is type 1, so its answer is 128 bytes and no more. */
      const answer = await modulus(device, SLOT_B, MAX_RSA_KEY_SIZE, { signal });
      const bounded = answer.bytes.subarray(0, 128);
      log(`slot B answered ${answer.reports.length} reports`);

      assert.equal(answer.reports.length, 2,
        `a 1024-bit modulus is 2 reports; ${answer.reports.length} means the device sent ` +
        'more than the declared type, which would be the tail coming out');

      const leaked = longestRun(Buffer.concat(answer.reports), a.pq);
      log(`longest run of A's P||Q in slot B's answer: ${leaked.len} bytes`);
      assert.ok(leaked.len < 32,
        `slot B's public-key answer carries ${leaked.len} contiguous bytes of the OTHER ` +
        'key\'s private material - the tail IS reachable over the vendor interface, which ' +
        'makes this far more serious than a raw-flash finding');

      /* Not zeros either: the bounded answer is B's real modulus, so the bound
       * is a bound and not a failure to answer. */
      assert.notEqual(bounded.toString('hex'), '00'.repeat(128),
        'slot B answered nothing at all, so the assertion above proves nothing');

      /*
       * And promoting the slot to a bigger type does not bring a residue back:
       * this stores a 2048-bit key into slot B and shows the image is still
       * clean afterwards.
       *
       * While the defect was live this measured `before` and `after` and
       * asserted the residue SHRANK, because promotion was the one path that
       * could have made the tail readable. With the tail zeroed there is
       * nothing left to shrink, so what is left to check is that the larger
       * write does not reintroduce one - the type-2 accumulate runs a fresh
       * pass through the clamped branch.
       */
      const before = longestRun(flash(device), a.pq).len;
      const c = keypair(2048);
      await pqc.readyForKeygen(device, { signal });
      await store(device, { slot: SLOT_B, typeByte: 2 | FEATURE_DECRYPT, pq: c.pq },
        { signal, assert });
      await device.restart({ signal });
      await device.ensureUnlocked(PINS.primary, { signal });

      const after = longestRun(flash(device), a.pq).len;
      log(`A's residue was ${before} bytes before slot B was promoted to 2048-bit, ` +
        `${after} after`);
      assert.equal(after, 0,
        `promoting the slot to a larger type put ${after} contiguous bytes of the ` +
        'older key back on the medium');
    });
});
