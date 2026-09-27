# Finding: loading a 4096-bit RSA key writes one byte past `rsa_private_key`

**Status: FIXED.** `libraries:merge/user-input-modes-pqc` clamps the ninth copy
to `MAX_RSA_KEY_SIZE - packet_buffer_offset`. Verified on the emulator
2026-09-22: a 4096-bit key loads, the device survives, and the modulus read back
out of flash after a reboot equals `p*q` byte for byte - so the clamp is
lossless as well as safe (8 x 57 + a clamped 56 = exactly 512; the dropped byte
is the host's padding in the ninth report).

The regression test moved with the fix. `01-protocol/25-rsa4096-overflow.test.js`
asserted the device CRASHES and so went red the day the clamp landed; it is
replaced by `01-protocol/25-rsa4096-load.test.js`, which asserts the key loads
INTACT. That file's modulus check is the one that matters and it was proved
against a deliberately narrowed clamp (`room - 1`): the load still reported
`Successfully set RSA Key`, the device still survived, and only the modulus
comparison caught it - `differs at byte 254 of 512`. A survival-only test would
have passed.

`23-rsa-tunnel`'s 4096 case is ungated and `OKT_EXPECT_RSA4096_FIX` is gone -
but ungating alone did not make it pass, and what it uncovered is worth its own
line: every test in that file was failing on transit v2, not on the key size.
The kit's tunnel client was still speaking the old length-preserving box, so the
firmware discarded each request whole and the host waited out a 30-second
timeout with nothing to attribute it to. `lib/device/transit.js` now seals and
opens `[counter(4)][ciphertext][tag(16)]`, request chunks are 171 bytes
(245 - 20 framing, rounded down to a multiple of 57) and the file is green. The
framing also moved the boundary the file was written for, in its favour: a
512-byte RSA-4096 signature is staged as 532 and served in TWO chunks, so
RSA-4096 is now the smallest classic response that exercises the multi-chunk
path the alpha report pointed at, with RSA-2048 (276 framed) as the one-chunk
control beside it.

Both files stay gated `emulated`, because a key running firmware WITHOUT the
clamp is still a key this drives an out-of-bounds write at, with no
`_FORTIFY_SOURCE` to catch it.

**Originally:** measured on the emulator, deterministic, `libraries@83353cf`.
**Severity:** out-of-bounds WRITE, reachable from a normal client
(`onlykey-cli loadkey` with any 4096-bit RSA key). Higher than the slot-tail
finding, which is read-only exposure at rest.
**Found by:** driving the RSA-4096 response boundary in `onlykey-testing`. The
emulator did the work here: `_FORTIFY_SOURCE` turns a silent one-byte corruption
into a loud abort, so this is a defect a physical key would not have surfaced.

## Summary

`rsa_priv_flash()` accumulates a key in fixed 57-byte `memcpy`s whose length is a
literal, never clamped to what remains in the destination. The guard threshold
varies per key type but the copy length does not, so the largest type runs one
byte off the end:

| type | key size | last offset passing the guard | ends at | |
|---|---|---|---|---|
| 1 | 1024 | 114 | 171 | safe |
| 2 | 2048 | 228 | 285 | safe |
| 3 | 3072 | 342 | 399 | safe |
| **4** | **4096** | **456** | **513** | **1 byte past a 512-byte array** |

Observed on the ninth chunk:

```
Slot =  2
Type =  68                              (4 | FEATURE_SIGN)
*** buffer overflow detected ***: terminated
```

## The buffer and the expression

`libraries/onlykey/okcore.cpp`, `rsa_priv_flash()`, the type-4 branch:

```c
else if ((buffer[6] & 0x0F) == 4)
{ //Expect 512 Bytes
    keysize = 512;
    if (buffer[0] != 0xBA && packet_buffer_offset <= 456)
    {
        memcpy(rsa_private_key + packet_buffer_offset, buffer + 7, 57);
        packet_buffer_offset = packet_buffer_offset + 57;
    }
}
```

The destination is `uint8_t rsa_private_key[MAX_RSA_KEY_SIZE]` -
`MAX_RSA_KEY_SIZE` is 512 (`okcore.h:210`), defined at `okcrypto.cpp:149`. The
offsets that satisfy `<= 456` are 0, 57, 114, 171, 228, 285, 342, 399, 456 - nine
of them - and the ninth copies 57 bytes to `rsa_private_key + 456`, touching
indices 456 through 512 inclusive. Index 512 is out of bounds.

## What triggers it - measured, both directions

- **Nine chunks at type 4: aborts.** Every time.
- **Eight chunks at type 4: device alive, no abort.** So the trigger is precisely
  the ninth copy, not the type byte alone.
- **The bytes do not have to be a key.** The eight-chunk probe sent
  `crypto.randomBytes(512)`, and the abort case is equally indifferent:
  `rsa_priv_flash()` never inspects the material. Nothing is validated until
  `okcore_flashget_RSA()` + `rsa_getpub()` at USE time, long after the write.
- **Only type 4.** Types 1-3 end at 171/285/399, all inside the array. A nibble
  above 4 that is not `KEYTYPE_PQC_PGP` is rejected with "Error invalid RSA type"
  before any copy. `KEYTYPE_PQC_PGP` (5) has its own branch bounded by
  `PQC_PGP_BLOB_LEN`; it writes past the 160-byte blob but stays well inside the
  512-byte array, so no fortify trip and no out-of-bounds write.

## Eight chunks are safe; the ninth is the trigger

Stated plainly because it is what makes the defect easy to confirm and easy to
fix, and because it rules out the type byte on its own:

| | |
|---|---|
| eight chunks at type 4 | **device alive, no abort.** Offsets 0..399, the eighth copy ending at 456 - still inside the array. The load does not complete and the device says nothing. |
| the ninth chunk | **aborts, every time.** Offset 456, copy ends at 513. |

The bytes need not be a key: the eight-chunk probe sent
`crypto.randomBytes(512)`, and `rsa_priv_flash()` never inspects the material -
nothing is validated until `okcore_flashget_RSA()`/`rsa_getpub()` at use time,
long after the write. So the trigger is exactly "type nibble 4, ninth copy".

## Reachable from the SHIPPED CLI - confirmed, and intermittently

Driven through `onlykey-cli` itself rather than the kit's own sender, with a real
4096-bit key generated by node:crypto:

```sh
onlykey-cli setkey RSA1 4 s <1024 hex chars of P||Q>
```

`setkey()` maps that to `key_type = 4 | 64 = 68`, takes the
`key_type & 0xf == 4` branch and issues its nine sends. **Two runs of the exact
same command behaved differently:**

| run | outcome |
|---|---|
| 1 | CLI exits **0**, prints only a newline - the device never answers, nothing is stored, and no error is reported anywhere. The load silently did nothing. |
| 2 | `*** buffer overflow detected ***: terminated` - the firmware aborts, mid-load. |

Nothing changed between them but the test's own logging, so this is
non-deterministic. The likely reason is pacing: `setkey()` issues its nine
`send_message()` calls back to back with no delay between them (the kit's own
sender paces 150ms and reaches the ninth chunk every time), so whether all nine
arrive depends on the receive path keeping up. Either outcome is a defect on the
shipped path:

- **it crashes the firmware**, or
- **it silently fails to load a key and exits 0**, which is the same
  "exit code is not coverage" shape as `setpqc` reporting success for a load the
  device refused.

So this is not reachable only from a hand-built client. `onlykey-cli loadkey` with
any 4096-bit PGP key goes through the same `setkey()`, since
`_load_single_key()` derives the type from the key's own size
(`rsa_type = key_size // 128`).

This is not a hand-built-client-only defect. python-onlykey's `setkey()`
(`client.py`) sends exactly nine chunks when `key_type & 0xf == 4`:

```python
elif key_type & 0xf == 4: # RSA 4096
    self.send_message(msg=Message.OKSETPRIV, slot_id=slot_number, payload=format(key_type, 'x')+value[:114])
    ... nine sends ...
    self.send_message(msg=Message.OKSETPRIV, slot_id=slot_number, payload=format(key_type, 'x')+value[912:1024])
```

and `_load_single_key()` picks the type from the key itself -
`rsa_type = key_size // 128`, which is 4 for any 4096-bit key. So
`onlykey-cli loadkey <4096-bit PGP key>` reaches it, as does any client following
the same framing (the OnlyKey App's RSA path is the other one to check).
Preconditions are only what `OKSETPRIV` always needs: unlocked and in config
mode.

**The value written differs by caller, and that is the part worth noting.** A
normal client's ninth chunk carries key bytes 456..511 - 56 bytes - so the 57th
byte copied is the report's own zero padding and the out-of-bounds byte is
`0x00`. A client that fills all 57 bytes of that final report controls the value
written past the array.

## What it lands on - `rsa_publicN[0]`, with no padding

Read out of the built object rather than guessed from declaration order
(`nm -S` on the emulator addon):

```
00000000000c97c0  0x020  B  ecc_private_key
00000000000c97e0  0x041  B  ecc_public_key
00000000000c9840  0x200  B  rsa_private_key     spans …9840 … …9a3f
00000000000c9a40  0x200  B  rsa_publicN         begins at …9a40
```

`rsa_private_key` ends at `0xc9a40` and `rsa_publicN` starts exactly there, so
**the stray byte lands on `rsa_publicN[0]`** - the most significant byte of the
modulus buffer - with no padding to absorb it.

**And that is why this has never been noticed on hardware.** `rsa_publicN` is a
scratch buffer: `rsa_getpub()` recomputes N from P·Q and writes all `type*128`
bytes of it on *every* `okcore_flashget_RSA()`, and `okcrypto_getrsapubkey()`
only ever transmits it after that call has run. So the corrupted byte is
overwritten before anything can read it. The write is still out of bounds and
still undefined behaviour, but on an unfortified build its observable effect is
most likely nil.

So the severity splits by build, and the honest statement is:

| build | effect |
|---|---|
| anything with `_FORTIFY_SOURCE` (the emulator) | **fatal** - `memcpy` has a known destination size, glibc aborts, and a 4096-bit key cannot be loaded at all |
| Teensy / unfortified | one byte into a buffer that is fully recomputed before use - probably inert |

**One caveat that cannot be closed from here:** that layout is the x86 emulator's.
Nothing but the linker puts `rsa_publicN` after `rsa_private_key`, and the ARM
build's ordering is its own question - the Teensy build's map file would settle
it. If something live sits there instead of a scratch buffer, the severity goes
back up.

## Suggested fix

Clamp the copy to what remains, in all five branches rather than only type 4 -
the other four are safe by arithmetic that a future key size would break again:

```c
int n = keysize - packet_buffer_offset;
if (n > 57) n = 57;
if (n > 0) memcpy(rsa_private_key + packet_buffer_offset, buffer + 7, n);
```

The guard `packet_buffer_offset <= 456` can then be `< keysize`, which says what
it means: keep going while there is room.

## Reproducing

```sh
sudo sysctl -w vm.mmap_min_addr=4096
node bin/okt.js run test/01-protocol/23-rsa-tunnel.test.js --test 4096
```

The run aborts with exit code 5 and `*** buffer overflow detected ***` in the
device host's stderr, attached to the failing test. Note the exit code: SIGABRT
is currently classified as "the device host died for a reason that is not the
firmware's fault", which is wrong for a fortify trip - tracked separately in the
kit's TODO.
