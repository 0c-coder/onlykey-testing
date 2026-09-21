# Finding: an RSA slot's unused tail carries the previous key's plaintext to flash

**Status:** **FIXED.** Measured on the emulator, reproducible, against
`libraries@83353cf`; closed by `libraries@b6ca21c` on branch `rsa-fix`
(`bm-ok/0c-coder-libraries`), which is pending upstream. Longest run of the
older key's plaintext anywhere in `flash.bin`: **0 bytes**, where it was 85.
**Severity:** confidentiality of key material **at rest**. Not remotely
reachable - see "What it is NOT", which is as load-bearing as the rest.
**Reproducer:** `onlykey-testing`, `01-protocol/22-rsa-slot-tail.test.js`,
which measures both halves separately and fails if either changes. It asserted
the defect until the fix landed and asserts its absence now; the file keeps the
mechanism write-up because the fix is one `memset` and that line cannot be
judged without it.

## Summary

Storing an RSA key writes **512 bytes** to the slot's flash region but encrypts
only as many as the new key occupies. The rest of that 512 bytes is whatever
happened to be left in the `rsa_private_key` global - and reading any RSA slot
leaves *that slot's private key, in the clear*, in exactly that global.

So: read a 2048-bit key, then store a 1024-bit key, and **85 contiguous plaintext
bytes of the 2048-bit key's prime Q are written to flash**, unencrypted, inside
the 1024-bit key's slot.

Measured, not inferred:

```
longest contiguous run of key A's P||Q in flash: 85 bytes, key offset 171
that run sits 171 bytes into a 512-byte slot stride
longest run of key B's own P||Q (the key being stored): 0 bytes
```

Key offset 171 is inside Q (P is bytes 0..127, Q is 128..255), so the residue is
**the low 85 bytes of the 128-byte prime Q**. That is well past the half-the-bits
threshold at which Coppersmith's method recovers a factor from partial knowledge,
so an attacker who can read the flash region can factor the modulus. Key B being
absent from the clear text confirms this is a tail-of-buffer defect and *not* the
slot encryption failing.

## The three lines that do it

All in `libraries/onlykey/okcore.cpp`.

**1. Reading a slot leaves plaintext in a global.** `okcore_flashget_RSA()`
decrypts in place:

```c
okcore_flashget_common((uint8_t *)rsa_private_key, (unsigned long *)adr, (type * 128));
okcore_aes_gcm_decrypt(rsa_private_key, slot, features, profilekey, (type * 128));
```

After this, `rsa_private_key[0 .. type*128-1]` is a private key in the clear.
`OKGETPUBKEY`, `OKSIGN` and `OKDECRYPT` all call it, so any use of an RSA slot
does this.

**2. Storing a smaller key only overwrites as far as it goes.**
`rsa_priv_flash()` accumulates into the same global, and its chunk guard stops
early for a smaller key - for `keysize == 128` the guard is
`packet_buffer_offset <= 114`, so nothing past offset 171 is ever written:

```c
else if ((buffer[6] & 0x0F) == 1)   //Expect 128 Bytes
{
    keysize = 128;
    if (buffer[0] != 0xBA && packet_buffer_offset <= 114)
    {
        memcpy(rsa_private_key + packet_buffer_offset, buffer + 7, 57);
        packet_buffer_offset = packet_buffer_offset + 57;
    }
}
```

**3. It then encrypts `keysize` bytes and writes `MAX_RSA_KEY_SIZE`.** This is
the defect:

```c
okcore_aes_gcm_encrypt(rsa_private_key, buffer[5], buffer[6], profilekey, keysize);   /* 128 */
okcore_flashget_common(tptr, (unsigned long *)adr, 2048);
for (int z = 0; z < MAX_RSA_KEY_SIZE; z++)                                           /* 512 */
{
    temp[z + ((buffer[5] * MAX_RSA_KEY_SIZE) - MAX_RSA_KEY_SIZE)] = rsa_private_key[z];
}
flashEraseSector((unsigned long *)adr);
okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
```

`keysize` bytes are protected; bytes `keysize .. 511` go to flash exactly as they
sat in RAM.

## Resulting layout, for a 1024-bit key stored after a 2048-bit key was read

| slot region offset | content |
|---|---|
| 0..127 | the new key, AES-GCM encrypted - correct |
| 128..170 | zero padding from the third 57-byte report |
| **171..255** | **the previous key's plaintext, bytes 171..255 - the low 85 bytes of its Q** |
| 256..511 | whatever the global held before |

## Preconditions, which bound it

- **Both operations must happen within one boot.** The residue lives in RAM.
  A reboot re-runs `setup()`, the C++ globals are reconstructed, and
  `rsa_private_key` comes back zeroed - so a read in one boot and a write in the
  next leaks nothing. (This produced a false negative in the first version of the
  test, which is why it is stated.)
- **The write must be for a smaller key than the read.** Same-size or larger
  overwrites the residue.
- Entering config mode does **not** reboot - the long-press-6 branch sets
  `configmode = true`, clears `unlocked` and returns - so "read a slot, then enter
  config mode and store a smaller key" is a single-boot sequence a client can
  perform. That is the realistic path: a configuration tool that reads slots to
  display them and then writes one.

## What it is NOT - measured, and it limits the severity

**The residue is not reachable through the device's own interfaces.** Every
reader of an RSA slot is bounded by the slot's declared type:

- `okcore_flashget_RSA()` reads exactly `type * 128` bytes, and `OKGETPUBKEY`,
  `OKSIGN` and `OKDECRYPT` all go through it. Measured: after arranging the leak,
  the 1024-bit slot answers `OKGETPUBKEY` in **2 reports** (128 bytes, its
  declared size) and those bytes contain **0 bytes** of the other key's material.
- The **backup** path is bounded by the same expression -
  `memcpy(large_temp + off + 3, rsa_private_key, (type * 128))` in `backup()`'s
  RSA loop. *This one is read from the source, not measured, and is stated as
  such.*
- The tail **cannot be promoted into readability.** Making the device read
  further would mean declaring a larger type for the slot, and
  `rsa_priv_flash()` only reaches `okeeprom_eeset_rsakey()` inside the branch
  that fires once the accumulated offset has passed the new key's size - i.e.
  only after a full-size write, which overwrites the residue first. Measured:
  85 bytes before promoting the slot to 2048-bit, **0 bytes after**.

So the exposure is to an attacker who can read flash directly - a physical
attacker with readout access, a firmware bug that dumps flash, or anyone handling
an image of the storage. On a Teensy 3.x that is what FSEC readout protection
exists to prevent. It is a defence-in-depth failure rather than a remote one.

## One thing to know before dumping a real key's flash

**OnlyKey's flash is not a flat byte image.** `okcore_flashset_common()` packs
each four bytes into one longword *big-endian* and writes it with
`flashProgramWord()`:

```c
unsigned long data = (uint8_t) * (ptr + z + 3) | ((uint8_t) * (ptr + z + 2) << 8)
                   | ((uint8_t) * (ptr + z + 1) << 16) | ((uint8_t) * (ptr + z) << 24);
```

On a little-endian core that puts `ptr[z]` at the *highest* address of the word,
so **every aligned 4-byte group is byte-reversed** relative to the logical bytes.
`okcore_flashget_common()` mirrors the unpack, so the device is self-consistent
and only an out-of-band reader sees it. Anyone reproducing this against a flash
dump must un-reverse each 4-byte word first, or every search comes back empty and
reads as "no leak". Verified against a slot label, which is stored in the clear:
`oktprobe00961683` was written and `borpkto00169386`-style word-reversed bytes
were on the medium; un-reversing gives the label back exactly.

## The fix, as applied

`libraries@b6ca21c`, branch `rsa-fix`. The unused tail is zeroed immediately
before the encrypt, so nothing beyond the new key's own material can be
written:

```c
memset(rsa_private_key + keysize, 0, MAX_RSA_KEY_SIZE - keysize);
okcore_aes_gcm_encrypt(rsa_private_key, buffer[5], buffer[6], profilekey, keysize);
```

**It ships in the same commit as the 4096-bit clamp, and it has to.** What
bounded this residue to 85 bytes was the other defect's padding: a 1024-bit
key's third report copied a literal 57 bytes from offset 114, so 128..170
reached flash as that report's zero padding and the older key's plaintext
started at 171. Clamping that copy removes the padding, which would widen the
residue from 85 bytes to the full 384. Clamping without zeroing is a larger leak
than either defect alone, so neither half can be committed on its own. See
`FINDING-rsa4096-overflow.md`.

Wiping `rsa_private_key` after every `okcore_flashget_RSA()` consumer is finished
with it would also close it, and is the stronger form - the global holding a
plaintext private key between operations is the underlying condition, and the
same pattern exists for `ecc_private_key`, which this finding has not examined.
**That was deliberately left out of the fix**: it touches every consumer rather
than one function, and a security change a maintainer has to audit is worth
keeping to the smallest diff that closes the defect.

Note the same 512-byte copy is what makes an **RSA wipe** leave the slot's key
type in EEPROM (`rsa_priv_flash()` returns from its `wipe` branch before
`okeeprom_eeset_rsakey()`), so a wiped RSA slot still reports a key and publishes
a modulus computed from decrypted zeros. That is a separate finding, pinned by
`01-protocol/19-rsa-keys.test.js`.

## Reproducing

```sh
sudo sysctl -w vm.mmap_min_addr=4096
node bin/okt.js run test/01-protocol/22-rsa-slot-tail.test.js
```

Two tests: the first measures that no residue is present, the second measures
that the vendor interface would not hand one over if there were. Both carry a control - the first proves the
flash image is current and correctly un-swapped before believing any absence, and
the second proves the bounded answer is a real answer rather than silence.
