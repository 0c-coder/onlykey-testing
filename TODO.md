# TODO

The work list. [PLAN.md](PLAN.md) is the source of truth for *why* and carries
the reasoning behind every row here; [README.md](README.md) is how to use what
exists. This file is the order to do things in, and what each one needs.

**READ THE TABLE, NOT THE HEADINGS.** The headings below are numbered in the
order they were written and each was written when its section was empty, so
several still read as though their section is untouched. The table is what is
open. And the two numbering schemes are not the same thing: a heading here is
`§n`, the kit's own test directories are `test/0n-...`, and they do not line up -
**TODO's §2 is the kit's section 1**, TODO's §1 is the kit's section 2. Each row
below names its heading in words for that reason.

**THE ORDER IS ASSIGNED, NOT DERIVED.** It used to be "what is unblocked and what
unblocks the most", and that rule put the app last because it has no ancestor.
The maintainer has assigned it first as of 2026-08-06, which overrides the rule
rather than contradicting it - so do not reorder this table back on the strength
of the old reasoning.

| | what | why it is next |
|---|---|---|
| 1 | **section 4, the OnlyKey APP** (§5, "Section 4 - the OnlyKey app") | **ASSIGNED, AND DONE - 28 tests green as of 2026-08-06 14:44Z**, up from 15. **Every tab is driven bar the two that must not be**: the session plus Slots, Keys, Backup, Setup, Preferences and Advanced. **The Firmware tab is excluded** because it reaches `OKFWUPDATE` - and note `16-app-setup` records that the SAME DOOR is on the Setup tab (`LoadFirmware` -> Step11), so the exclusion is not confined to the tab it is named after. **Tools is deliberately NOT a test file** - it is a launcher of external links with no device behaviour, so pinning its hrefs was maintenance without a subject; what mattered is [FINDING-app-tools-origin.md](FINDING-app-tools-origin.md). **What is left is ONE tab: Setup** (`init-panel`), plus the **restore half** of Backup (measured, unsettled - see the premises table). **The Firmware tab is deliberately excluded**, because it reaches `OKFWUPDATE`, and Preferences' `fullWipeModeBtn` is excluded for the same class of reason - both have their PRESENCE asserted so that an absence would be noticed without either being armed. Two findings came out of the new tabs: the Yubico form discards a hex Public ID in total silence (`hexToModhex` throws inside the click handler and nothing catches it), and the Tools tab's four `/app/*` links point at an origin the firmware does not stage. **Advanced also closed a real coverage gap nothing else could reach** - `set_slot()` case 10 (`YUBIAUTH`), one of only two cases with no coverage anywhere, since `onlykey-cli` exposes no route to it |
| 2 | ~~HMAC challenge-response~~ **DONE 2026-08-06** | `01-protocol/24-hmac-sha1-challenge`, 3 tests in 23s, `--isolate` 3/3 and `--reverse` green. The Yubikey-style HMAC-SHA1 the old kit could not reach, over the keyboard interface's control transfers - a THIRD command channel beside the vendor interface and the tunnel. The device's HMAC is checked against node:crypto over the same key and challenge, and both `hmac_challengemode` paths are driven. **The security-relevant half is now MEASURED rather than read** and written up as [FINDING-hmac-press-free-on-write.md](FINDING-hmac-press-free-on-write.md): writing a key through this path leaves the slot press-free, and the test answers a challenge with no press at all. See the file header for six protocol traps |
| 3 | `13-pgp-pqc` (§4, "Section 3 - the pages that are left") | the only page left, and the one item here that needs a browser in front of a human. Page debugging, not coverage |
| — | **section 5, SECURITY** (§6) | PLANNED, after the sweep, by decision. Its two harness prerequisites - a recorded crash rather than an aborted run, and a positive control for every negative assertion - land BEFORE any test in it |
| — | the International Travel Edition (§3) | DEFERRED until the kit is complete, by decision - a second BUILD, diffed against this one |

**No COVERAGE row is open outside that table** - which is what this paragraph
used to say as "nothing else is open", and a cold reader who took that literally
would close the file with ten kit-side items still unticked. Section 2 is
complete, 37 of 37 subcommands. Section 1 has one row left and it is
`OKFWUPDATE`, which is gated `emulated` and driven only to its interlocks on
purpose - it is not work waiting to be done. Section 3 is complete but for
`13-pgp-pqc`.

**What IS still open below the table, and none of it is coverage:**

| where | what |
|---|---|
| Kit-side items | the exit-4 device-host **orphan leak**; **SIGABRT** classified as exit 5 when it is a firmware crash; a **run-max during a boot** reported as 5 rather than 3; the shape of the **RSA-4096 regression test**; **per-section budgets** instead of `RUN_MAX` |
| The venv | whether to pin **solo / python-fido2** back into step |
| Not tests | **hosted CI**, parked deliberately; whether to track **`package-lock.json`**; the backup TYPESPEED saving; folding the flasher's pacing upstream |
| §6 | the two **harness prerequisites** for section 5, which land before any test in it |

Everything else below the table is ticked, a finding, or debt that is recorded
rather than scheduled.

One rule from the old ordering is worth keeping because it corrects a myth that
cost an hour whenever it resurfaced: **the large-response path went early** even
though it was unglamorous. Everything returning more than 64 bytes had been
testing it accidentally and would have blamed its own feature. This file used to
say "`OKGETRESPONSE` goes early"; there is no such mechanism - see PLAN's plane 1
and the premises table below.

**What landed on 2026-08-05/06, kept because each row records what it cost
rather than that it happened.** Six files in one session, which is why several
headings below still describe a world that ended that night:

| file | tests | what it settled |
|---|---|---|
| `01-protocol/19-rsa-keys` | 7 in 104s | RSA, the seventh key kind outside the six-value `KEYTYPE_*` enum. Every key kind the firmware stores now has coverage |
| `01-protocol/20-second-profile` | 3 in 39s | the first time either kit entered the second profile. It sees profile 1's slot data, deliberately |
| `01-protocol/21-self-destruct` | 2 in 63s | gated `full-wipe`. The secret does not come back even after re-provisioning with the same PINs |
| `01-protocol/22-rsa-slot-tail` | 2 | gated `storage-files`. [FINDING-rsa-slot-tail.md](FINDING-rsa-slot-tail.md) |
| `01-protocol/23-rsa-tunnel` | 2 + 1 gated off | classic RSA over the WebAuthn transport. [FINDING-rsa4096-overflow.md](FINDING-rsa4096-overflow.md) |
| `03-gui/08-pgp-encrypt-decrypt` | 6 in 135s | the encrypt/decrypt pages' LIBRARY tier, all five `_$mode()` modes |
| `03-gui/14-gui-encrypt-decrypt` | 6, 107s with its session | the same five through the PAGES, in nw.js over the USB gadget |
| `02-cli/16-cli-key-files` | 3 in 35s | `loadpqc` / `loadkey` on their accepting paths. Section 2 finished |

**And what landed on 2026-08-06, all section 4** - the first time any kit has
driven the OnlyKey App against a device rather than a mocked `chrome.hid`:

| file | tests | what it settled |
|---|---|---|
| `04-app/10-session` + `19-stop` | 7 in 7s | the App runs under the kit's own nw.js 0.114 with `chrome.hid` working, shares the gadget with the kit's device host, and stops without leaking |
| `04-app/11-app-slot-config` | 4 | a label and a PASSWORD written through the App's form, the password read back by PRESSING THE BUTTON. Two defects: [FINDING-app-slot-button-dead-window.md](FINDING-app-slot-button-dead-window.md) |
| `04-app/12-app-keys` | 2 | a PGP RSA key loaded through the Keys tab, both slots' moduli checked against openpgp.js's own `n`, and the signing/decryption slot convention agreed with `onlykey-cli` |
| `04-app/13-app-backup` | 2 | a backup the DEVICE typed, accepted by the App's own verifier - two independent readers of one artefact neither of them wrote |

So **both PINs this kit provisioned on every run and had never entered are now
entered**, the International Travel Edition is a deferred second BUILD rather
than a test, and four findings are written up for upstream - the two above plus
[FINDING-cli-exit-codes.md](FINDING-cli-exit-codes.md) and the RUN_MAX/exit-code
pair under "Kit-side items".

**`18-gui-encrypt-decrypt` used to share a row with `13-pgp-pqc` and that was
the mistake worth remembering**, because merging two items blocked on different
things made the unblocked one look blocked for weeks. It needed a browser and a
human only in its second half; its first half needed neither and nothing had
tried. Both halves are now done and only `13-pgp-pqc` is left.

**When a file lands, update its section's `last run` in [PLAN.md](PLAN.md)'s
counts table.** The emulated and hardware columns carry separate dates because
they drift apart, and a count with no date reads as current when it is not. The
emulated column WAS a whole-tree sweep as of 2026-08-06 02:16Z (353 passed,
1489s) whose per-section rows all came from that one run and summed exactly -
**and it no longer sums**, because section 4's row is a later measurement of its
own (15 passed, 04:13Z) and the tree has not run end to end since. PLAN says so in
place rather than leaving the arithmetic to mislead. The hardware column is
2026-08-05 16:24Z and has seen none of the files in either table above. Section 3 is the one most exposed to drift, since its browser tier
depends on nw.js and the onlykey.github.io checkout rather than on anything this
repo pins.

**And watch the run budget when a file lands.** `RUN_MAX` is 30 minutes; the tree
was 1489s (83%) before section 4 existed, and section 4 measures 121s on its own,
so a whole-tree run is now roughly **1610s - about 89% of the cap**, and unmeasured
as a whole. That is not a lot of room, and the last time it ran
out nobody noticed for hours, because a per-file cost is invisible against a
per-run cap. See the row under "Kit-side items".

Trap that does NOT apply here, worth knowing because the old kit's notes are
full of it: slot collisions between files. `onlykey-alpha-testing` lost whole
runs to one file overwriting another's key material (its report records two in a
single day, RSA1 and RSA4), and its answer was to hand out slots. This kit boots
every file from a fresh fixture image, so files may reuse slots freely. Do not
inherit the workaround.

---

## 1. Section 2 - the `onlykey-cli` endpoint sweep (DONE)

**The carried-over rows are done.** Every row of PLAN's table that belongs to
this section now has a replacement, and per the maintainer there are no further
tests to PORT here. What section 2 is for from now on is the thing it is named
after: **the Python CLI, endpoint by endpoint**. `onlykey-cli` exposes 37
subcommands, and **all 37 are now driven** - the sweep is finished. The last row
in this section, `loadpqc` / `loadkey` on their accepting paths, landed as
`02-cli/16-cli-key-files` and is ticked below. **Nothing is open in section 2.**

The ticked rows are kept because each carries what it cost to establish, which
is the part a future reader needs.

- [x] **`11-derived-xwing-cli`** (TC-16/17) → `02-cli/07-derived-xwing`, 7 tests
      in 9s. No button press and no `derivedkeymode` setup: the raw-HID branch
      has no `CRYPTO_AUTH` gate and bit 3 is checked only on the tunnelled path
      in `fido2/ok_extension.cpp`. Both facts are asserted rather than assumed -
      the tests count the device's own priming marker and require it not to
      move, so a firmware change that started demanding a confirmation reads as
      a sentence instead of a timeout.
- [x] **`06-lib-agent-ssh`** (TC-13) → `02-cli/08-lib-agent-ssh`, 7 tests in 7s.
      Three oracles on one key - lib-agent over hidapi, the kit over the
      in-process vendor interface, and node:crypto deriving the public half from
      the seed the firmware prints. "No device state changed" is asserted, not
      described: zero button challenges and zero flash sector erases across the
      file. Note the number - the row is named for the OLD kit's file; this
      kit's next free number was 08.
- [x] **`07-lib-agent-gpg`** (TC-13) → `02-cli/09-lib-agent-gpg`, 9 tests in 6s.
      The first lib-agent test that SIGNS - twice, each behind its own button
      challenge - so the first that needs `lib/pqc.js`. Both derived keys
      (ed25519 to sign, curve25519 to decrypt) checked against the kit's own,
      and the digits lib-agent prints checked against the packet the device says
      it received, which is what proves the multi-report send arrived intact.
      Three traps it turned up are in PLAN: `init` needs the venv on **PATH**,
      it leaves a **daemon running**, and **`gpgconf --kill all` hangs** on it.
- [x] **`age_file.js` against the real `age` binary** → `02-cli/15-age-file-interop`,
      4 tests in 8s, `--isolate` 4/4 and `--reverse` green. BOTH directions, not
      just the one this row asked for: real `age` writes and `age_file.js` reads
      it, and `age_file.js` writes and real `age` reads it. A reader and a writer
      can be wrong in opposite ways and still pass one direction each.

      Cheap because the device half goes over RAW HID rather than the tunnel -
      the derived X-Wing branch has no `CRYPTO_AUTH` gate and does not check
      `derivedkeymode`, so no button, no config mode, no setup. It is also the
      first time the KIT sends the derived pair itself: `OKGETPUBKEY` slot 128
      with `KEYTYPE_XWING`, and `OKDECRYPT` slot 128 as TWO reports with the
      continuation marker in `buffer[6]` - the framing that used to be broken.

      The kit's recipient is asserted equal to the plugin's for the same label,
      so a later failure cannot be a silent key mismatch wearing a format
      failure's clothes.

      Failure KINDS separated on a real container, which `04-age-file` could not
      do: a corrupted sealed file key fails as an AEAD tag inside `openFileKey`
      and never reaches the MAC check, because the MAC cannot be computed until
      the file key is recovered. Only editing the MAC line itself reaches it.
      The first version of this test had that backwards.

**The sweep, which is now the section's main work.**

`onlykey-cli` exposes **37** subcommands. Before this, section 2 had run exactly
ONE of them - `setpqc`, and only as a way of loading a key for something else to
test. Everything else in the section drives `age-plugin-onlykey`, `onlykey-agent`,
`onlykey-gpg` or python-onlykey's library directly, so the CLI itself - the thing
a person actually types - was almost entirely untested.

Five files, split by what an endpoint COSTS rather than by help-text order.
**An endpoint is not covered by exiting 0**: several of these print a help line
and exit 0 when they dislike their arguments, so what the command did has to be
visible from a second place - the kit's own vendor interface reading back what
the CLI wrote, or the device's console saying what it received.

**A COMMAND THAT BLOCKS ON STDIN TRIPS THE WATCHDOG, NOT ITS OWN TIMEOUT.** The
run's inactivity budget is 30s and a blocked CLI produces no device output, so a
per-command `timeoutMs` above that aborts the whole run with a watchdog message
instead of failing the test that caused it. Section 2's commands are capped at
12s and fed stdin, so an unanticipated prompt surfaces as a wrong answer rather
than a hang. Found by a 45s timeout on `credential` killing a run at 31s.

**`--isolate` AND `--reverse` ARE BOTH GATES FOR EVERY NEW FILE.** A file does
not land until `okt run <file> --isolate` and `okt run <file> --reverse` are
both green. They catch opposite faults and neither substitutes for the other:

| fault | fails when | caught by |
|---|---|---|
| the test DEPENDS on an earlier one | run alone | `--isolate` |
| the test is BROKEN BY an earlier one | something runs before it | `--reverse` |

Four times in this sweep a test was made wrong by what ran before it, and
`--isolate` caught none of them - three were caught by the natural order and one
by `--reverse` on its first use (`13-cli-lifecycle`'s `password`, which cannot
type while a predecessor has left config mode on). `--reverse` costs one
ordinary run, not a boot per test. A single endpoint has to be
debuggable on its own with `okt run <file> --test <name>`, which only works if
no test depends on what an earlier one did - so each test brings the device to
the state it needs itself, through `device.ensureUnlocked()`, the idempotent
form of `unlock()` (which cannot be called twice: it PRESSES the PIN digits, and
on an unlocked device those are slot presses).

**Every `it()` name must contain the literal endpoint it covers**, so that
`--test getlabels` selects exactly one test. That is what makes the gate worth
having rather than merely true.

**Every test says which surface it asserts on.** A production key ships without
SEREMU, so any assertion that reads the debug console cannot run in a future
production walk, while the keyboard, vendor and FIDO surfaces can - see
[PRODUCTION.md](PRODUCTION.md). Where an assertion can be made on a
client-visible surface without weakening it, make it there. Where the console is
genuinely the only oracle - counting button challenges, flash erase counts,
which SLOT a write went to - use it and say so. The words, so the split is
greppable rather than discovered later:

```
/* SURFACE: vendor - survives into a production walk. */
/* SURFACE: console - does NOT survive a production walk, and is used here
 * because <the reason nothing client-visible can answer this>. */
```

Existing files that fail the gate are **debt, tracked below, retrofitted
opportunistically** - the sweep is worth more than a clean isolation record. See
"Isolation debt" under Not tests.

- [x] **`10-cli-reads`** - `version` `fwversion` `getlabels` `getkeylabels`
      `ping` `rng`. 7 tests in 10s, first run green. The version is checked
      against what section 1's own unlock reported, the labels against a slot
      this kit wrote over the vendor interface, the RNG against a second call.
      Two findings worth carrying forward: **the CLI is not one program** -
      `ping` and `rng` hand off to `solo.cli.key()` and reach the device over
      FIDO, so they fail in a different language than the rest - and
      `getlabels` picks its slot layout with `okversion[19] == 'c'`, a fixed
      INDEX into the model string, which lands on the hardware-variant
      character only for a version string of exactly this length.
- [x] **`11-cli-settings`** - 13 endpoints, 13 tests in 53s, `--isolate` 13/13.
      `2ndprofilemode` `backupkeymode` `derivedkeymode` `hmackeymode`
      `storedkeymode` `idletimeout` `keylayout` `keytypespeed` `ledbrightness`
      `lockbutton` `sysadminmode` `touchsense` `wipemode`.

      **Entirely on the vendor surface bar one assertion**, because the firmware
      acknowledges every one of these BY NAME - "Successfully set keyboard
      layout" is a different string from "Successfully set typespeed" - so the
      acknowledgement identifies the field without a debug line. The refusals
      are equally specific, and "Error not in config mode" IS the security
      property arriving where an attacker would see it.

      `backuppassphrase` moved to `13-cli-lifecycle`: it reads stdin with
      prompt_toolkit and goes out as OKSETPRIV, so it is neither argv-driven nor
      a setslot.

      Three findings. **`onlykey-cli` exits 0 when the device refuses** - all
      seven refusals here return 0 with an error on stdout, which is this
      section's "exit code is not coverage" rule demonstrated rather than
      asserted. **Config mode is sticky and has no exit but a reboot**, and
      `wipemode`/`backupkeymode` do not merely need it, they SUCCEED inside it -
      so a predecessor entering config mode inverts their assertion rather than
      erroring. **--isolate does not catch that class**: those tests pass alone,
      they are broken by a predecessor rather than dependent on one. Establishing
      the state you assert about is the rule that covers both directions.
- [x] **`12-cli-slots`** - 8 endpoints, 8 tests in 89s, `--isolate` 8/8. Also
      closes most of section 1's "slot fields beyond LABEL and PASSWORD" row
      below: 13 of the CLI's 17 `setslot` field types are now written and each
      acknowledged in its own words. The remaining four - `password`, `gkey`,
      `totpkey` - read stdin with prompt_toolkit and moved to `13-cli-lifecycle`.

      Entirely on the vendor surface, console needed for nothing. The strongest
      assertion stores RFC 8032's published seed with `setkey` and reads the
      PUBLIC key back with OKGETPUBKEY, checking it against node:crypto - an
      acknowledgement says a write was accepted, this says the right bytes
      arrived.

      **`setpqc` reports success for a load the device refused** - three
      "Error not in config mode" replies, and the CLI prints "Loaded composite
      PQC PGP key (160 bytes) into RSA1" and exits 0 without reading them. A
      client fault, not a firmware one; the load path itself is fine, as
      05-composite-load shows from inside config mode.

      Two more surprises, both pinned as they ship: **OKWIPEPRIV says "Error
      device locked" on an unlocked device** that is merely not in config mode,
      where its neighbour OKSETPRIV says "Error not in config mode"; and
      **OKGETPUBKEY is REFUSED in config mode**, printing to the console with no
      vendor reply at all, so a client that writes a key and reads it back in one
      session sees the read time out with nothing to explain it.
- [x] **`loadpqc` / `loadkey` accepting paths** → `02-cli/16-cli-key-files`,
      3 tests in 35s, `--isolate` 3/3 and `--reverse` green. **Section 2 is now
      complete**: every one of the 37 subcommands is driven, and both of the two
      that take a FILE are driven on the path that does the work rather than only
      on the one that rejects.

      The files are generated by the WEB APP's own vendored openpgp fork, which
      makes each test a two-client agreement rather than a round trip: the
      browser's library writes a key file, python-onlykey's Node/OpenPGP.js
      bridge reads it, and they have to mean the same thing by it. A checked-in
      fixture key would have tested that the bridge still reads a file from 2026.

      **The two commands are not symmetrical and neither is the evidence.**
      `loadpqc` has NO readback - `okcrypto_getpubkey()` has no
      `KEYTYPE_PQC_PGP` branch - so the only evidence is the device USING the
      key, and the test has it sign and verifies against the Ed25519 public half
      derived from the blob the file carries. `loadkey` writes RSA, so both
      moduli are read back over the vendor interface.

      **The best assertion here is about a convention nobody states.**
      `loadkey`'s auto mode puts the signing key in slot 2 and the encryption
      subkey in slot 1 - measured, "Loading RSA 2048 key to slot 2... / Loading
      RSA 2048 key to slot 1..." - which is exactly the pair `onlykey-pgp.js`'s
      `slotid()` hardcodes. So a key a person loads with the CLI lands where the
      encrypt and decrypt pages look for it, and `03-gui/08` and `03-gui/14`
      would find it. Nothing in either codebase says so; now something checks it.

      Third test drives the refusal that needs a REAL file: `loadkey` parses a
      composite key successfully and then rejects it by name, telling you to use
      `loadpqc`. That is a different branch from "cannot open the file", and the
      failure it prevents is 160 bytes of seeds landing in an RSA slot as P‖Q.

      One trap, and it is the one README warns about: `unlock()` cannot be called
      on an unlocked device, so a test that inherits one times out thirty seconds
      later waiting for an `UNLOCKED` that will not come again. Two of these
      tests now use `pqc.readyForKeygen()`, which reboots first.
- [x] **`13-cli-lifecycle`** - 7 endpoints, 7 tests in 67s, `--isolate` 7/7.
      `settime` `password` `totpkey` `gkey` `backuppassphrase` `restore` `init`.

      **Regrouped**: `set-pin` `change-pin` `reset` `wink` moved to
      `14-cli-fido`. None of them is an OnlyKey command - cli.py hands all four
      to `solo.cli.key()`, so they reach the device over FIDO, and `set-pin`
      sets the FIDO2 CLIENT PIN rather than the device PIN its name suggests.
      The five-file split is unchanged; only which file they live in.

      prompt_toolkit drives from a pipe - it warns and redraws oddly in captured
      output, but the value arrives intact, so `input:` on `cli.run()` is enough
      and no pty is needed.

      Best assertion in the sweep is here and is on the KEYBOARD surface: a
      password written by the command line is read back by pressing the button
      and decoding what the device types. Every other test in the sweep checks
      that a write was ACCEPTED; this checks the secret that comes out is the
      one that went in.

      **`init` is silent on a set-up device until config mode, then re-arms the
      PIN machine** - and prints exactly the same script either way, exiting 0.
      One of those two outcomes is a key an Enter-and-six-presses away from a
      replaced PIN, and nothing in the output says which just happened.

      `backuppassphrase` is length-checked host-side (>= 25 characters) before
      anything reaches the wire, which is the right shape - a weak backup
      passphrase is what would make an exported backup worth stealing.

      `gkey` and `totpkey` are indistinguishable on any client surface: one
      base32-decodes and the other does not, and the device acknowledges both
      with "Successfully set 2FA Key". Telling them apart needs a TOTP code
      checked against a host computation, which is the deferred challenge-mode
      work in PLAN's loose ends.
- [x] **`14-cli-fido`** - 6 endpoints, 6 tests in 22s, `--isolate` 6/6.
      `wink` `credential` `set-pin` `change-pin` `reset` `loadfirmware`.

      **The sweep is complete: 37 of 37 subcommands are now driven.**

      Nothing here flashes firmware and nothing resets the authenticator. Both
      are driven exactly as far as their confirmation prompts, which is the part
      worth testing: the assertion is that NEITHER interface carries anything
      while the guard holds.

      **`credential`, `set-pin` and `change-pin` are broken by a host dependency**
      - `AttributeError: 'Fido2Client' object has no attribute 'client_pin'`,
      solo calling an API the installed python-fido2 no longer exposes. The
      device answers; the client cannot use the answer. `set-pin` then EXITS 0
      while printing the error, so a script checking exit codes is told a PIN
      was set when none was. Worth deciding whether to pin the venv's `solo` and
      `fido2` back into step - see the row under Not tests.

## Premises worth checking before picking a row up

`OKGETRESPONSE` cost an hour whenever it came up because the row asserted a
firmware mechanism that does not exist, and nothing in the row said whether
anybody had looked. So: **rows that rest on a claim about the firmware say
whether the claim has been verified.**

Checked while correcting that one:

| claim | status |
|---|---|
| `OKGETRESPONSE` returns large payloads | **FALSE** - no handler, no references |
| `OKPING` is a live message | **FALSE** - no handler, no references |
| `OKHMAC` / `OKWEBAUTHN` are live messages | **FALSE** - internal tags only |
| "eighteen live message types" | **wrong** - fourteen are dispatched |
| CTAP2 implements MakeCredential, GetAssertion, GetInfo, ClientPIN, Reset, GetNextAssertion, Cancel, CredMgmt | verified, all in `fido2/ctap.cpp` |
| `hmac-secret` and `credProtect` are advertised | verified, in `ctap.cpp` / `ctap_parse.cpp` |
| the derived branches have no `CRYPTO_AUTH` gate | verified, and asserted by `07-derived-xwing` and `15-age-file-interop` |
| 28 slot fields under `OKSETSLOT` | **WRONG twice** - `set_slot()` dispatches **29** cases, and only **16** are per-slot; the other 13 are device-wide settings. 28 is the size of python's `MessageField` enum, which is where the number came from |
| `OKFWUPDATE` can leave a key needing `okt flash` | **WRONG, and worse than stated** - it locks the bootloader and permanently converts a developer key into a production key. Maintainer's understanding, deliberately NOT verified experimentally |

Checked while writing `19-rsa-keys`, all in `libraries/onlykey`:

| claim | status |
|---|---|
| python-onlykey frames RSA-2048 as five `OKSETPRIV` chunks | verified, `client.py:563` - five slices of 114 hex characters, nine for RSA-4096 |
| `onlykey-pgp.js` needs RSA slot 1 to decrypt and slot 2 to sign | verified, `slotid()` returns `slot == OKSIGN ? 2 : 1` and adds 100 only when `is_ecc` |
| `okcrypto_rsasign()` / `okcrypto_rsadecrypt()` had never had a byte sent at them | verified - `13-large-response` writes RSA slot 1, but as `KEYTYPE_PQC_PGP`, which `okcrypto_sign()` routes to `okpqc_sign()` before the RSA branch |
| an RSA slot holds a private key | **NO** - it holds **P‖Q and nothing else**. `rsa_getpub()` multiplies the halves for N and `rsa_sign()`/`rsa_decrypt()` recompute D, DP, DQ and QP every time, **with E hardcoded to `0x10001`**. A key whose exponent is not 65537 stores fine and then signs with a D it does not have |
| RSA `type` is a key type like the ECC ones | **NO** - it is the modulus size in 128-byte units (1..4 for 1024..4096), sharing one byte with the feature flags: low nibble size, bit 5 decrypt, bit 6 sign |
| the single-press `stored_key_challenge_mode` covers only ECC slots | **NO, it covers RSA too** - `done_process_packets()` loads it when the slot is `< 5` OR 101..116, and `< 5` **is** the RSA slot range. 14-stored-keys' byte-1 trick works here unchanged |
| `OKGETPUBKEY` takes any field on an RSA slot | **NO** - `okcrypto_getpubkey()` takes the RSA branch on `buffer[5] < 5 && !buffer[6]`. Any other field falls through to the ECC branch and reads a slot that does not exist |
| the key-load and operation chunk framings are the same | **NO, and this is the trap.** The KEY going in carries the **type byte** in `buffer[6]` on all five reports and `rsa_priv_flash()` copies a fixed 57 bytes from each, counting its own way to 256 with a global offset. The OPERATION payload carries the **continuation marker** - `0xFF` while more follows, the final chunk's length on the last. Swapping them gives a 255-byte packet or "Error invalid RSA type" |
| `OKSIGN` takes any digest on an RSA slot | **NO** - exactly 28, 32, 48 or 64 bytes, and the length PICKS THE HASH: `rsa_sign()` maps them onto SHA-224/256/384/512. And it is refused AFTER the confirmation, so the press is spent on a request the device was always going to refuse |
| the second profile cannot see profile 1's slot data | **FALSE** - both profiles unwrap the same stored master profile key, so an AES-GCM decrypt succeeds across the boundary and the firmware prints the plaintext doing it. Deliberate ("Using new method, PIN changes supported"), and NOT a failed boundary: plausible deniability is the travel BUILD's property, not the second profile's. Pinned by `20-second-profile` |
| `NONENCRYPTEDPROFILE` is a runtime mode of the second profile | **NO, it is primarily a BUILD** - the `#else` of `#ifdef STD_VERSION` in `setup()` (OnlyKey.ino:259-263), the International Travel Edition, which exists because some countries do not permit encrypted devices. A legal constraint, not a security feature. Everything this kit has assumes `STD_VERSION`; see README |
| "RSA is the one key type of six with no coverage" | **LOOSE, and this file's own opening said it.** `okcore.h`'s `KEYTYPE_*` values are 1..6 and **all six are ECC** - ed25519, P256, secp256k1, curve25519, ML-KEM-768, X-Wing - and all six were already covered by `14-stored-keys`. RSA is a **seventh key kind outside that enum**, with its own EEPROM accessor (`okeeprom_eeget_rsakey` rather than `..._ecckey`), its own flash sector, and a "type" that means modulus size rather than algorithm. The gap was real; the arithmetic describing it was not |

Checked while writing `03-gui/08-pgp-encrypt-decrypt`, all in
`onlykey.github.io/src/onlykey-fido2`. **These are about the shipped web client,
not the firmware** - the first client-side entries this table has carried, and
they belong here for the same reason: each was a claim something else rested on.

| claim | status |
|---|---|
| the classic PGP pages need a section-2 step to get a key onto the device | **FALSE, and now measured** - a classic RSA key goes in over the vendor interface with `OKSETPRIV`. The file loads both slots itself and never spawns a process |
| `slotid()`'s two hardcoded slots can be filled from ONE PGP key | verified - a PGP key is a primary that signs plus a subkey that encrypts, so the primary's P‖Q goes to slot 2 and the subkey's to slot 1. Both moduli read back equal to openpgp.js's own `n` |
| an RSA slot cares which factor is P and which is Q | **NO** - and the two key sources this kit uses disagree, so it was worth measuring rather than assuming. openpgp.js emits **p < q** every time (RFC 4880's convention, where `u = p⁻¹ mod q`); node:crypto's JWK export emits **p > q** every time (PKCS#1's, where `qi = q⁻¹ mod p`). Measured 5/5 each way. `19-rsa-keys` and `23-rsa-tunnel` load node's order and `08-pgp-encrypt-decrypt` loads openpgp's, and both sign and decrypt correctly - which follows from `rsa_sign()` recomputing D, DP, DQ and QP from whatever it was given |
| `startEncryption`'s empty-argument guards protect the caller | **FALSE** - both test `to_pgpkeys.value == ""` / `from_signer.value == ""` while both pages pass STRINGS, so `.value` is `undefined` and neither guard can fire. `startDecryption`'s equivalents test the string and are fine. The empty input reaches `keyStore.loadPublic()`, which emits an error and **returns without resolving**, so the call never comes back and the output box never fills. Pinned by the second test, written to fail when it is fixed |
| kbpgp hands the device a digest it can hash | verified, and the length is the whole contract: `pad_and_sign()` defaults to SHA512, so the device receives **64 bytes** and `rsa_sign()` maps that onto SHA-512. The device picks the hash from the LENGTH, so a kbpgp that changed hasher would silently change the signature's algorithm too |
| the library's challenge digits are the device's | verified, and asserted rather than assumed - `get_pin()` takes bytes 0, 15 and 31 of SHA256 mod 6 plus 1, and the digits the page shows a user are required to equal the ones derived from the packet the device says it hashed. Measured `4,3,2` on the first run |
| a PGP decrypt crosses the keyhandle boundary | verified - `auth_decrypt` sends `ct.slice(12)`, which for RSA-2048 is the whole 256-byte modulus-long ciphertext, so `u2fSignBuffer` frames it as 228 + 28. The device accumulated all 256, which is the client-side half of what `23-rsa-tunnel` proved firmware-side |
| `usevirtru` is safe to pass as `false` | **NO** - `usevirtru != null` is TRUE for `false`, so `false` arms a Virtru branch that plugin.js's own `pgp()` never arms (it forwards an absent argument). `03-gui/07-pgp-keys` passes `false`; it only escapes because it never runs a file path. Pass nothing |
| `_poll_delay` is chosen from the key's size | **NO, from the key id COUNT** - `loadPublicSignerID` sets 1 if a third key id exists and 8 otherwise, commented "Assuming RSA 4096 or 3072". An ordinary primary-plus-subkey RSA-2048 key has two, so every signature waits 8 seconds for no reason. Costs time, nothing else |

Checked while writing `03-gui/14-gui-encrypt-decrypt` - the BROWSER tier. The
first is a defect in **this kit**, not in anything under test:

| claim | status |
|---|---|
| `page.close()` closes the window | **FALSE, and it was the kit's own bug** - it was `this.ws.close()` alone, which drops the debugger socket and leaves the tab running, loaded and still retrying. `11-password-generator`'s "closes its window" test has always CLAIMED the opposite in its comment ("a window left open holds a device handle"), and nothing noticed because **no file had ever opened a second page in one session**. Fixed: `close()` now shuts the target over the browser endpoint. See the next row for how it presented |
| a leaked tab is a slow leak | **NO - it breaks the NEXT page immediately.** Chromium allows **one WebAuthn request at a time per BROWSER**, not per tab, so a page closed while its startup OKCONNECT is outstanding makes the next page's handshake fail inside Chromium with `OperationError: A request is already pending.` The page swallows it, the output box never fills, and what a test sees is a device that was never contacted. Measured: the pending wait was `/Received Message/` and the run died on the inactivity watchdog with the real cause only in the page's console |
| every app page talks to the device as it loads | verified, and it sharpens what "Encrypt Only needs no device" means - true of the OPERATION, false of the PAGE. `14`'s version of that test asserts on confirmations PRIMED rather than on device silence, and says so; `08`'s headless version really does reach no device |
| `#header_messages` reports the handshake | verified - onlykey-api.js writes "Secure Connection Established" with the firmware version into it, which is the only page-visible signal that startup finished. `14` waits for it before doing anything, which is what makes closing a page safe |

Checked 2026-08-06 by a cold reader before picking up row 1, all in
`onlykey/OnlyKey-App` and `emulator/lib`. **These are about the OnlyKey APP and
the emulator's gadget, not the firmware** - every one was a claim §5's row rested
on, and the first changes what that row costs:

| claim | status |
|---|---|
| `chromeHid._sent` lets a test read what the App put on the wire without patching | **FALSE against a real device.** `send()` (`OnlyKeyComm.js:112-125`) pushes to `_sent` only when `connectionId === "mockConnection"`; the real branch calls `chrome.hid.send` and records nothing, so against the emulator `_sent` stays empty. Not the same shape as `__pgpPqcTestHooks`, which publishes the LIVE transport. Still patchable - `chromeHid` is a `const` binding holding a MUTABLE object, so an injected script can wrap `.send`/`.receive` - but that is patching, and the row assumed it was free |
| the App finds the device by VID/PID | **INCOMPLETE - there are THREE gates.** `onDeviceAdded()` (`OnlyKeyComm.js:1243-1251`) also requires `collections[0].usagePage == 65451` (`0xFFAB`) and `serialNumber == "1000000000"`. All three match the emulator by reading both sides (`emulator/lib/hid-descriptors.js:19-23`), so the conclusion survives and is now three-for-three instead of one-for-one. **READ ON BOTH SIDES, NOT MEASURED** |
| a device the App does not recognise is simply not found | **NO** - the `else if` fallback is `supportedDevice && serialNumber != "1000000000"`, the pre-Beta-8 path, which connects to **whatever interface enumerated first with no usagePage check**. On the gadget that is four interfaces behind one VID/PID, so a serial mismatch would present as the App speaking vendor protocol at the keyboard or FIDO interface rather than as an absence |
| ...and that fallback is worth a test that provokes it | **NO, and this was MY OWN claim four hours earlier in the same session** - corrected before it shipped, which is the premises table working on its author. `usb_init_serialnumber()` (`OnlyKey-Firmware/usb_desc.c:1032`) **hardcodes `num = 1000000000`**; the Teensy code that would derive a per-device serial from flash is commented out directly above it. So **every device on this firmware presents that serial**, the strict branch always wins, and the fallback is unreachable without lying to the App. The emulator's `SERIAL_NUMBER` is faithful imitation rather than a lucky guess. Latent branch, not a live risk - and the cost of provoking it is in §5 |
| the gadget's VID/PID live in `lib/gadget.js` | **WRONG FILE** - that is the KIT's own file and a consumer of the values. The source is `emulator/lib/hid-descriptors.js`. Same numbers, so nothing downstream changes; worth correcting because a reader chasing the gadget's identity into the kit finds a copy and believes it |
| `OnlyKey-App/build/` is checked in, and the question is whether it is current | **NEITHER** - `build/` is **gitignored** (`.gitignore:5`). What is on this workstation is a local artifact from clone time, and it IS current (it differs from `app/` only by an appended sourcemap comment). So a fresh checkout has no `build/` and `gulp build` is unconditional - a CI fact, not a convenience |
| the slot buttons are dead / the App is stuck | **NO to both - `getAttribute('open')` was the wrong instrument, and it cost three iterations.** `showModal()` sets the `open` attribute to the **EMPTY STRING**, so `!!el.getAttribute('open')` is false for a dialog that is wide open. The dialog had been opening all along. The App's own selenium test compares `getAttribute('open')` to `'true'` and is right only because **WebDriver normalises boolean attributes**; anything reading the raw DOM must use the `open` PROPERTY. A rule ported out of a selenium suite is not automatically true outside it |
| the App binds its slot buttons when it shows them | **NO - there is a ~1.2s window in which they are visible and dead.** `initSlotConfigForm()` does the `addEventListener` and is reached only from `handleGetLabels()`, so the binding waits for the first OKGETLABELS reply while the panel is revealed from the unlocked state. Measured 1163ms, with a click issued from inside the page in the same frame the button was first laid out - and with a positive control (a click after binding opens the dialog). A real user reaches it by clicking a slot as soon as it appears. [FINDING-app-slot-button-dead-window.md](FINDING-app-slot-button-dead-window.md) |
| the App sets NEXTKEY3 to Return without being asked (its own FIXME) | **NOT REPRODUCIBLE against a device.** Configuring a password through the UI and pressing types the password and nothing after it. Control in the same test: writing NEXTKEY3 by hand over the vendor interface makes the same press type `"\n"`, so the absence is real rather than a decoder that drops Returns. `04-app/11` asserts the measured behaviour and fails if a Return ever appears |
| "Successfully set RSA Key" means the key is durable | **THE QUESTION WAS WRONG. SETTLED 2026-08-06: it is a defect in THIS KIT'S TEST, not in the firmware and not in the emulator.** The ack loop in `04-app/12-app-keys` captured `device.mark()` ONCE and reused it for both iterations. `waitHid` re-scans from its `since` and returns the FIRST match without consuming it or advancing the mark, so both iterations returned the SAME report - the loop harvested two acks from one ack on the wire and walked on while the App was still writing its second slot. The 6s settle was buying the App time to finish, which is why removing it failed deterministically and why no durability theory ever fit. Demonstrated with a positive control, not argued: the loop collects 2 acks from 1 report, and the identical wait with a fresh mark correctly times out. **Three things independently rule out the durability story**: the ack is emitted LAST in `rsa_priv_flash()`; `okemu_eeprom_write()` is an immediate per-byte `pwrite` (`emulator/src/ok_hal.cpp:589`) and flash is `MAP_SHARED`, so nothing durable dies with the SIGKILL a restart is; and `lib/pgp-rsa.js`'s `loadSlots()` does the identical two-slot-write-then-immediate-restart with **no settle at all**, driven six times by `03-gui/08` under `--isolate`, never losing a slot - because it takes a FRESH mark per slot, which is the bug's exact inverse. Loop fixed, and **the 6s settle is now REMOVED, measured rather than reasoned**: three consecutive runs green with no settle at all, the same standard the 6s was established by. The retrospective proof is in the run logs either side of the fix - before it both acks were logged at the SAME MILLISECOND (12:06:26.045), being one report returned twice; after it they are ~610ms apart |
| ...and the way to settle it is to dump `eeprom.bin` before and after | **NO - that experiment had only ONE LIVE BRANCH and could never have discriminated anything.** It was proposed to separate "never written" from "written and lost". Per-byte `pwrite` makes "written and lost" impossible by construction, so the answer was always going to be "never written", and reading that as a result would have confirmed a mechanism that was not operating. A test whose two outcomes are not both reachable is not a test |
| the App can restore a backup, and driving it is a matter of attaching a file | **UNSETTLED, and deliberately not asserted.** With a device-written backup attached to `#restoreSelectFile` over CDP's `DOM.setFileInputFiles`, the App displays "Restoring from backup please wait..." with an empty error box and then **nothing reaches the device** - zero vendor replies and no reboot across 45s, the device still answering `unlocked`. Two readings this could not separate: the App's restore stalls before transmitting (a real defect in a path carrying a whole device's secrets), or a debugger-injected `File` is not one this nw.js's FileReader will read (a harness artefact saying nothing about the App). **What settles it in one run:** wrap `submitRestoreData()` from the page - a top-level function, wrappable the way `initSlotConfigForm` was in `04-app/11` - and see whether it is called and with how many bytes. `#restoreSelectFile` is ALSO a duplicate id (app.html lines 305 and 1040), which cost one iteration on its own |
| the App ships a harness, so there is something to adopt | **TRUE, but it does not RUN as shipped.** `test/` holds FOUR files, not the three tabled in §5: the fourth is `serial.js`, which requires `node-hid` - **not a dependency of that repo** - and `chalk`. Mocha's default glob is `test/*.js`, so `npm test` dies at that require; past it, `serial.js`'s 1 ms `setInterval` would stop mocha exiting, and `driver.js` launches nw.js at module scope rather than in a hook. Adopting means repairing three defects in somebody else's repo first |

`OKFWUPDATE` is the exception to "check it": it is not to be verified
experimentally, and the gate is mechanical instead - see its row below.

The slot-field count was checked and is corrected below.

Checked 2026-08-06 by running sections 0 and 1 against the PHYSICAL KEY, which is
what most of these needed. Four were documentation claims nobody had re-measured;
the last two are the kind this table exists for, because both were absences that
turned out to be broken instruments.

| claim | status |
|---|---|
| the hardware adapter is "a declared seam with a stub behind it" (README) | **FALSE, and contradicted by PLAN's own hardware column for two days.** `lib/device/hardware.js` is 453 lines, carries measurements taken against a key, and runs **147 passed / 0 failed / 19 skipped in 837s**. README's bullet is corrected and now says what the run exercises and what it does not |
| PLAN's "the hardware column has seen none of the five" | **UNDERCOUNT - it is NINE files, not five.** The hardware sweep ended 16:24Z on 2026-08-05; `15-hmac-secret` (16:54Z), `16-credprotect`, `17-resident-keys` and `18-clientpin-credmgmt` (17:20Z) all landed after it and were never named. Found by measuring first-commit dates from git rather than reading the list. All nine have now run on the key |
| "Both adapters green" (PLAN's opening line) | **A HEADER THAT HAD STOPPED BEING A MEASUREMENT.** It carried no date while every row beneath it did, and by 2026-08-06 the hardware half was a day stale over a tree nine files larger. Now dated |
| `22-rsa-slot-tail` and `23-rsa-tunnel` "pass quietly" on a key because they lean on emulator-only affordances | **NEITHER, and they are not the same case.** `22` already requires `storage-files` and SKIPPED on the key, both tests, with the reason printed - the gate was right and had simply never been observed firing. `23` requires only `crypto`, **RAN, and both tests passed** - classic RSA over the WebAuthn transport against physical hardware for the first time. Gating it would have destroyed real coverage. What DID need tightening was its 4096 test: held only by `OKT_EXPECT_RSA4096_FIX=yes`, an env var with no hardware guard, so setting it on a hardware run would aim a known out-of-bounds WRITE at a real key with no `_FORTIFY_SOURCE` to catch it. Now gated `emulated` first |
| a flaky hardware test means flaky firmware | **NO - it was THIS KIT leaking file handles.** `_open()` was not idempotent: a re-enumerating key races udev, so a reopen a few ms early fails `EACCES` *part way through the loop*, leaving already-opened handles live while the caller retries and opens a second set over the top. The orphan keeps its `data` listener, so SEREMU arrives TWICE and the console accumulator - the only oracle several section-1 tests have - fills with interleaved duplicates. `23-rsa-tunnel` read a 32-byte digest as 54. **The open ORDER decided whether a denial mattered**: SEREMU is opened first, so its 30 denials per run were harmless, while VENDOR's 2-4 were the only ones that could leak. Fixed two ways - a pre-flight `fs.access` on every required node, and an all-or-nothing open that unwinds what it opened |
| ...and a clean run after the fix proves it | **WEAKER THAN THE REAL EVIDENCE, which is that the race fired HARDER in the passing run.** VENDOR denials went 2 (failing run) -> 4 (passing run) with total churn flat at 105 -> 107; both previously-failing tests came back green. "The fix made the run green" invites the flake reading; "the fault fired twice as often and the run passed anyway" rules it out. Then a third run with the pre-flight logged 42 access rejections and **zero** cases of a required interface failing after something was opened |
| run `20260806-122122`'s zero interface errors show the leak was not involved in `10-backup-restore`'s failure | **NO - THAT ZERO IS AN ABSENT LOGGER, NOT AN ABSENT FAULT**, and this is the fourth entry in the table above it. The runner only began subscribing to `interface-error` at 12:30:34Z; that run started at 12:21:22Z. Nothing was listening, so nothing could be recorded. A correlation table built across those runs is blind in its early rows rather than clean in them. `10-backup-restore`'s 90s generation timeout is **still open and retroactively untestable** - only a recurrence with the instrumentation present can settle it |

## 2. Section 1 - the protocol surface, now mostly touched

Highest leverage in the kit, and not for the reason this heading used to give.
It said "the only device section CI can run, so every test that lands here runs
on every push once stage 2 is enabled" - hosted CI is parked (see Not tests), so
that is not true today. The reason that survives is better: **section 1 is the
only place a test is worth double.** Section 2 can never run against a physical
key (`client-access`) and section 3's headless tier drives the emulator by
design, so section 1 is the hardware-capable surface - everything here was run
against a real key on 2026-08-05.

Plane 1, the vendor interface - 9 of 18 messages covered, plus two with a single
branch each:

- [x] **The multi-report response path** → `01-protocol/13-large-response`,
      3 tests in 45s, `--isolate` 3/3 and `--reverse` green. NOT
      `OKGETRESPONSE`, which does not exist - see the premises table above.

      Both sizes driven and both whole: **1184 bytes / 19 reports** (ML-KEM-768
      public key, generated on the device so it is the only source of the
      answer) and **3309 / 52** (ML-DSA-65 signature, the longest response the
      device produces). Report COUNT is asserted as well as byte count - they
      say different things, and a device answering the same payload in a
      different number of reports is a change worth knowing about.

      Also the answer to "what does an unhandled vendor message id do": it is
      handed to `recv_fido_msg()` and comes back as a **CTAPHID error frame**
      `FF FF FF FF BF 00 01 0B` on the vendor interface. Not silence - the test
      expected silence and was wrong, which is the better outcome, since silence
      would have been consistent with the report being dropped.

      First file to send `OKSETPRIV` and `OKSIGN` by hand rather than through
      onlykey-cli or the web app's library.
- [x] **`OKGETPUBKEY` / `OKSIGN` / `OKDECRYPT`** across the six key types →
      `01-protocol/14-stored-keys`, 6 tests in 90s, `--isolate` 6/6 and
      `--reverse` green. Section 1, so the whole file is hardware-capable.

      Every type checked against something that is not the device: ed25519,
      nist256p1 and secp256k1 pubkeys and signatures against node:crypto,
      curve25519 against node:crypto's X25519, and the two PQC types against
      @noble's encapsulation. Signatures are also checked NOT to verify over a
      different message.

      **This clears the challenge-mode blocker** - see the row below.

      Two findings. A PQC keygen has a different completion signal from a stored
      key: handing one over answers "Successfully set ECC Key", GENERATING one
      answers with the PUBLIC KEY itself (1184 / 1216 bytes) and no text at all.
      And the key the keygen returns is asserted equal to the key read back out
      of flash after a reboot, so generation, storage and retrieval agree.
- [x] ~~**`OKPING`, `OKHMAC`, `OKWEBAUTHN`**~~ - **not testable, not defects.**
      `OKPING` has no handler and no reference anywhere. `OKHMAC` and
      `OKWEBAUTHN` are internal tags (`packet_buffer_details[0] = OKWEBAUTHN`),
      never received. Three planned tests that dissolve on inspection; see
      PLAN's plane 1 for the check.
- [x] **`OKSETPRIV` / `OKWIPEPRIV`** beyond the backup-passphrase slot - done
      without ever being a row of its own. `14-stored-keys` sends OKSETPRIV into
      an ECC slot for all six key types, `13-large-response` sends it into an RSA
      slot as a 160-byte composite blob over three chunks, and `12-cli-slots`
      drives both through `setkey`/`wipekey`. What is NOT covered is an actual
      RSA key, which is the row below.
- [x] **Slot fields** - counted properly, and mostly done. `set_slot()` has **29**
      cases: **16 per-slot** fields and **13 device-wide settings** that merely
      arrive through the same message. "28" was python's `MessageField` enum
      size, not a firmware fact.

      All 13 device settings are covered by `02-cli/11-cli-settings`. Of the 16
      per-slot fields, `02-cli/12-cli-slots` and `13-cli-lifecycle` write 14 -
      label, username, url, the three delays, the five next-key characters, the
      2FA type, the TOTP key and the password. Two are left: **case 10**
      (`YUBIAUTH`, whose EEPROM accessor is named `public_DEPRICATED`) and
      **case 29**, which has no name in any client's enum.

      Also found: cases 5, 8, 9, 10 and 29 carry cross-guards - "Error MFA
      already enabled on this slot" and its mirror - but only when
      `Duo_config[0]==1`, meaning no device PIN is set. On a provisioned key they
      never fire, which is why a slot can hold both a password and a TOTP key in
      `13-cli-lifecycle`.
- [ ] **`OKFWUPDATE` - EMULATED-ONLY, MECHANICALLY GATED, AND NOT DRIVEN PAST
      ITS INTERLOCKS.** On a physical key this needs the special bootloader, and
      running it **locks the bootloader and permanently converts a developer key
      into a production key**. That is not "needs a reflash" - the key is gone as
      a dev key. Anything that sends this message, or drives a client that could,
      carries `requires: ['emulated']` so the hardware adapter cannot reach it
      and says why it skipped. `02-cli/14-cli-fido` already does.

      **What emulation cannot cover, by design rather than by omission:** FSEC
      lives in an anonymous mapping rebuilt on every boot, so there are no lock
      bits and the bootloader-lock path is not reachable on the emulator at all.
      What is testable is the framing, the interlocks and the refusals. Test
      those. The destructive behaviour stays untested.

Plane 2, CTAP2 proper - the ceremony works; the extensions do not exist:

- [x] **`hmac-secret`** → `01-protocol/15-hmac-secret`, 6 tests in 11s,
      `--isolate` 6/6 and `--reverse` green. Entirely on the FIDO surface -
      user presence arrives as KEEPALIVE(UP_NEEDED), which is client-visible -
      so the whole file survives into a production walk.

      The properties tested are the ones the feature exists for: 32 bytes back,
      the SAME 32 for the same salt (a password manager wraps a vault key with
      them, so unreproducible means the vault is gone), a DIFFERENT secret per
      salt, and a DIFFERENT secret per credential (or one site's credential
      unwraps another's vault). Plus the negative: a credential that did not ask
      for the extension must not come back carrying it.

      `getKeyAgreement` works with **no PIN set** - `clientPin` is false and it
      still answers, because the exchange is about keeping the salt confidential
      rather than authenticating anybody. If it did not, the extension would be
      advertised and unusable.

      **The `okcore.cpp:7645` note was wrong** - see PLAN. Two unrelated
      features that share the word HMAC.
- [x] **`credProtect`** → `01-protocol/16-credprotect`, 4 tests. Ungated - no PIN
      is needed to set any level, so it runs against a key with nothing to opt
      into. All three levels echoed as themselves; level 4 is accepted but
      echoed as NOTHING rather than stored; a credential that asked for nothing
      comes back with nothing; and a level-3 credential is refused with
      NO_CREDENTIALS on a device that cannot verify a user, which is the one
      thing level 3 is for.
- [x] **Resident keys** → `01-protocol/17-resident-keys`, 4 tests. Ungated.
      Discoverable with an empty allowList, the user handle comes back,
      non-resident credentials are correctly INVISIBLE to an empty allowList
      (or any site could enumerate the key), two users at one rpId report
      `numberOfCredentials: 2` and `GET_NEXT_ASSERTION` walks them, and a bare
      GET_NEXT_ASSERTION is refused. Every test uses its own rpId - resident
      credentials persist for the whole file, so a shared one would let an
      earlier test answer a later one's question.
- [x] **`credMgmt`, `CLIENT_PIN`, `RESET`** → `01-protocol/18-clientpin-credmgmt`,
      5 tests, gated on **`fido-reset`**.

      **The chain was verified before the file was written**, since three rows
      here have dissolved on inspection: `clientPin: false` means SUPPORTED BUT
      NOT SET - the option would be absent if PINs were unsupported - so
      credMgmt is reachable behind `setPin` -> `getPinToken` -> pinUvAuthParam,
      and both `0x0A` and the `0x41` FIDO_2_1_PRE alias answer.

      Two firmware behaviours worth knowing, both found by `--reverse`:
      a client PIN **cannot be unset**, only reset away; and the bad-pinAuth
      budget is **3 per BOOT**, which `ctap_reset()` does NOT restore - only a
      reboot or a successful auth does. So a second bad attempt escalates from
      PIN_AUTH_INVALID to PIN_AUTH_BLOCKED. Every test therefore reboots AND
      resets before it starts.

And the two carried-over rows that came over only partly:

- [ ] **HMAC - and this row is misnamed, which changes what is left to do.**
      It has read as "HMAC settings", the half of old `08-backup-hmac` that
      `10-backup-restore` did not take. **The settings half is already done.**
      Read the old file's own scope note: what it covered was the `hmackeymode`
      toggle and nothing else, and it said the actual challenge-response feature
      "is a keyboard/OTP HID interface python-onlykey doesn't implement a client
      for at all". `hmackeymode` is one of the 13 device settings
      `02-cli/11-cli-settings` drives, so the carried-over half landed without
      anybody noticing.

      **What is genuinely uncovered is the feature itself**: the Yubikey-style
      HMAC-SHA1 challenge-response, which the old kit could not reach and THIS
      kit can - the same "the emulator makes the keyboard interface an event
      rather than a privileged device node" argument that made backup and restore
      testable. It is a proper section-1 test with an independent oracle:
      node:crypto's HMAC-SHA1 over the same key and challenge.

      The firmware side, established:

      - `okcrypto_hmacsha1()` (okcrypto.cpp:850) needs `CRYPTO_AUTH == 4`, so a
        button confirmation. It is the THREE-DIGIT challenge, not the single
        press: the press handler's clause is `(CRYPTO_AUTH == 3 &&
        packet_buffer_details[0] == OKHMAC && isfade)`, and
        `done_process_packets()` only loads `stored_key_challenge_mode` for slots
        `< 5` or 101..116 - the HMAC key slots are 129 and 130, so neither range
        applies.
      - The key is **20 bytes** (`Sha1.initHmac(ecc_private_key, 20)`), and
        `keyboard_buffer[64]` selects the slot - but **THERE ARE TWO SEPARATE
        BRANCHES AND THEY USE DIFFERENT VALUES.** This row said `0x30`/`0x38`,
        was "corrected" to `1`/`3` on 2026-08-06, and that correction was WRONG:
        both pairs are real and they do different things. Corrected again, with
        the branch each belongs to, because a value without its branch is what
        caused the mistake:

        | `keyboard_buffer[64]` | branch | what it does |
        |---|---|---|
        | `1`, or `3`..`27` | `okcore.cpp:7657` | **WRITES** a key. `1` -> `RESERVED_KEY_HMACSHA1_1`, `3` -> `_2` (`:7681`), higher values are per-slot. Needs `keyboard_buffer[45] == 5 or 0` and `keyboard_buffer[46] == 0x60 or 0x40` |
        | `0x30`, `0x38`, or `1`..`12` | the challenge branch (`~:7860`) | **CHALLENGES**. `0x30` is Yklib HMAC slot 1, `0x38` is slot 2, and `1`..`12` reads a per-slot HMAC key |

        So the ORIGINAL row was right about the challenge, which is what this
        row is for. **The key write splits the 20 bytes**, which is its own
        trap: `recv_buffer+7 <- keyboard_buffer+22` (16 bytes) and
        `recv_buffer+23 <- keyboard_buffer+16` (4 bytes), commented "HMAC key
        split for some reason" in the source.
      - **The waiting-for-a-press path is chosen by `hmac_challengemode`**, read
        from EEPROM at the top of the challenge branch: `0` means physical
        presence is required, `1` means it is not. When presence is not
        required the firmware sets `CRYPTO_AUTH = 4` and calls
        `okcrypto_hmacsha1()` inline; otherwise it sets `CRYPTO_AUTH = 3` and
        `packet_buffer_details[0] = OKHMAC` and waits. **Both paths are worth
        driving** and neither ever has been.
      - **`check_crc()` is CRC-16/MCRF4XX over bytes 0..63 ONLY**, little-endian
        at `[65..66]`. The slot selector at `[64]` is NOT covered by it.
      - **The 70-byte buffer is filled seven bytes per SET_REPORT**, marker
        `0x80..0x89` in byte 7 - and **the copy happens inside GET_REPORT**, so
        every frame must be followed by one or nothing lands.
      - **The last frame only QUEUES the work.** `setBuffer[8] = 1` is consumed
        by `OnlyKey.ino:477`, gated on `!isfade || configmode` - so an unlock's
        LED fade delays it. Measured 2504ms. Sending a second buffer before the
        first is consumed overwrites `keyboard_buffer`.
      - **Do NOT poll GET_REPORT to detect that consumption.** After the last
        frame `setBuffer[7]` is still `0x89`, so each extra GET_REPORT re-enters
        the hand-off branch and rewrites `getBuffer[7]` - the poll destroys the
        `0xaf` it is waiting for. Measured: it returns 0x00 forever.
      - **Acknowledgement strings are NOT on the console as text.**
        `byteprint()` renders "Successfully set ECC Key" as
        `53 75 63 63 ...`, so a regex for the readable string never matches and
        times out looking like a device that did not answer. "Sending transport
        response data" is plain text and works.
      - The answer is FOUR GET_REPORTs, `getBuffer[8]` walking `0x40..0x43`,
        with the 20-byte HMAC split across `kb[0..6]`, `[8..14]`, `[16..21]`,
        CRC-16/X-25 at `[22]`/`[24]` and a constant `0x4B` at `[28]`.
      - Challenge length is inferred, not declared: all-`0x20` in bytes 57..63
        means 32 (KeePassXC's empty buffer), otherwise it scans back from 63 for
        the last non-zero and never goes below 16. **Any challenge under 16 bytes
        is treated as 16**, and the source says so - which is where a response
        differs from a real Yubikey's.
      - The answer is packed with `0xC0`/`0xC1`/`0xC2`/`0xC3` markers and a
        **CRC-16/X-25** (the code computes CRC-16/MCRF4XX and XORs `0xFFFF` to
        convert, with a comment about the mismatch).

      **The seam that is missing is in the KIT, not the firmware or the
      emulator.** This channel is HID control transfers on the keyboard interface
      - `SET_REPORT` 0x0921 and `GET_REPORT` 0x01a1 - and the emulator already
      ports both (`emulator/core-override/okemu_usb.cpp`, which carries the whole
      Yubikey state machine including the multi-report `0xC0`..`0xC3` read and the
      waiting-for-a-press path), AND the addon already exports them:
      `kbdSetReport(buffer)` and `kbdGetReport()` (`emulator/src/addon.cpp:215`).
      What does not exist is a verb for them in the kit's IPC - nothing in
      `emulator/lib/protocol.js` or `ipc-host.js` carries a set/get-report frame -
      so `device.send(IFACE.KEYBOARD, …)` cannot reach it, because an interrupt
      OUT report is not a control transfer.

      So the work is: add the two verbs to the IPC and the device host, expose
      them on the Device API, then write the test. Estimate is small and it is all
      in this project's own code rather than under `onlykey/`.

      **AND IT UNBLOCKS TWO ROWS, NOT ONE**, which is most of the argument for
      doing it. The same seam is the prerequisite for §6's keyboard-interface
      security row - `process_setreport()` is reached by the same control
      transfers, and it is a THIRD command channel that bypasses the vendor
      dispatcher's config-mode gate entirely. So this plumbing buys a feature test
      and an attack surface at once, and neither can start without it.
- [x] **RSA key handling** - the other half of old `12-non-pqc-regression` →
      `01-protocol/19-rsa-keys`, 7 tests in 104s, first run green, `--isolate`
      7/7 and `--reverse` green. **Every key kind the firmware stores now has
      coverage** - the six ECC `KEYTYPE_*` values by `14-stored-keys` and RSA,
      which is not one of them, by this file. `18-gui-encrypt-decrypt`'s
      prerequisite is met: RSA slot 1 holds a decrypt key and slot 2 a sign key,
      the pair `onlykey-pgp.js`'s `slotid()` hardcodes.

      Every answer checked against something that is not the device. The
      modulus against OpenSSL's own N for the same key AND against P * Q
      multiplied out in BigInt; the signature verified by node:crypto against a
      public key built from **the modulus the device published**, not from the
      host's key object; the plaintext sealed by node:crypto to that same
      published modulus, so a device decrypting with the wrong key returns noise.

      Almost entirely on the vendor surface - every answer and every refusal
      arrives where a client can see it. The console is read for "Encrypted
      Buffer" only, for press timing, plus two secondary "nothing was primed"
      counts.

      The premises it corrected are in the table above and are worth reading
      before touching RSA again: the slot holds **P‖Q with E hardcoded to
      65537**, `type` is the **modulus size in 128-byte units** sharing a byte
      with the feature flags, the two chunk framings mean **different things in
      `buffer[6]`**, and the single-press challenge mode **covers RSA slots**
      because `done_process_packets()` tests `slot < 5`.

      **Two findings, one pinned as a test.** `OKSIGN` on a decrypt-only slot
      and `OKDECRYPT` on a sign-only slot are refused BY NAME and **without
      priming a confirmation**, which is the security property arriving where a
      client sees it. And the pinned one: see the OKWIPEPRIV row below.
- [x] **`OKWIPEPRIV` on an RSA slot does not clear the slot's key type** -
      pinned as it ships by `19-rsa-keys`'s last test, which is written so that
      **it fails the day this is fixed**. `rsa_priv_flash()` handles `wipe` first
      and returns before it ever reaches `okeeprom_eeset_rsakey()`, so the flash
      region is zeroed and the type byte survives in EEPROM. The ECC path has the
      opposite shape - `ecc_priv_flash()` writes the type byte unconditionally on
      the way in, so an ECC wipe records type 0 and the slot really does read as
      empty afterwards.

      What a client sees: a wiped RSA slot does NOT answer "Error no RSA Private
      Key set in this slot" the way a never-written one does.
      `okcore_flashget_RSA()` believes the stale type, decrypts 256 zero bytes
      into P and Q, multiplies them and publishes the result - so the slot goes
      on reporting a 2048-bit key that is not a key. Measured: `6cd48841…`
      where the real modulus had been.
- [x] **The RSA slot tail - SETTLED BY MEASUREMENT, and it holds.** Was a DECIDE
      row found by reading; now `01-protocol/22-rsa-slot-tail`, 2 tests, gated on
      `storage-files`. **The write-up to send upstream is
      [FINDING-rsa-slot-tail.md](FINDING-rsa-slot-tail.md).**

      **Question 1, is the plaintext there: YES.** 85 contiguous plaintext bytes
      of a 2048-bit key's P‖Q, at key offset 171 - which is inside Q, so it is
      the low 85 bytes of the 128-byte prime. Well past the half-the-bits
      threshold where Coppersmith recovers a factor. It sits 171 bytes into the
      512-byte slot stride, exactly where the code predicts, and the key being
      STORED is not in the clear (0 bytes) - so it is a tail-of-buffer defect
      rather than the slot encryption failing.

      **Question 2, is it reachable through a normal device operation: NO**, and
      that is what bounds the severity. Every reader is capped at the slot's
      declared `type * 128`: the 1024-bit slot answers OKGETPUBKEY in 2 reports
      carrying 0 bytes of the other key, and the tail cannot be promoted into
      readability because declaring a larger type requires a full-size write that
      overwrites it first - measured, 85 bytes before, 0 after. The backup path is
      bounded by the same expression, which is READ from the source rather than
      measured and is labelled as such in the write-up.

      **Two false negatives before the real answer**, both worth carrying forward
      because either would have closed this row wrongly:

      1. `pqc.readyForKeygen()` RESTARTS, and a reboot re-runs `setup()` and
         zeroes the global, so the first run measured nothing at all. Entering
         config mode by long press does NOT reboot, so the read and the write can
         share a boot - and the residue living in RAM is what bounds the finding
         to a single boot.
      2. **`flash.bin` is word-reversed** - see README. The search found nothing
         because it was looking for logical byte order. A label-based control now
         proves the instrument before any absence is believed, which is the only
         reason this was caught rather than reported as "read wrong".

      Not examined: `ecc_private_key` has the same shape - a global holding a
      plaintext private key between operations - and nothing here has looked at
      it. The write-up says so.

## 3. The PINs provisioned every run and never tested

`PINS.secondary` and `PINS.selfDestruct` appear once each, both as *negative*
assertions in `07-unlock`.

- [x] **Second profile** → `01-protocol/20-second-profile`, 3 tests in 39s,
      `--isolate` 3/3 and `--reverse` green. The first time either kit has
      entered the second profile at all.

      Entirely on the KEYBOARD surface for every claim about what the device
      holds, which is the strongest oracle here and survives a production walk:
      what a slot contains is proven by reading what the device TYPES, not by an
      acknowledgement that a write was accepted. `ensureUnlocked()` is unusable
      in this file and the reason generalises - an unlocked device says nothing
      about WHICH PROFILE it is unlocked into, so every test restarts and enters
      its own PIN.

      **Two of the three things this row asked for are true and the third is
      not.** It is a different profile and it has different slot data:
      `gen_press()` adds 12 (and `gen_hold()` 12 + 6), so the second profile's
      buttons address slots 13..24 and can NEVER address 1..12. But it does see
      profile 1's - see the premise below and the row after this one.
- [x] **The second profile does not have its own key** - measured, and the row
      above asked to confirm the opposite. Both profiles unwrap the SAME stored
      32-byte master profile key, deliberately: the comment at the branch says
      "Using new method, PIN changes supported", and a wrapped master is what
      lets a PIN change without re-deriving everything. The backwards-compatible
      path beside it (`Curve25519::eval(profilekey, KEK, p1hash)`) is the one
      that gives profile 2 a key of its own, and it only runs when no stored
      profile key is found.

      The firmware printed the evidence itself, on the first run of the file
      while the assertion was still the other way round:

      ```
      INPUT KEY         85 E7 A9 F7 …      the key profile 2 read with
      SLOT              13
      ENCRYPTED STATE   E6 C2 DD 70 …      sealed while in profile 1
      DECRYPTED STATE   70 72 6F 66 69 …   "profileONEsecret1"
      ```

      An AES-GCM decrypt that succeeds across the boundary can only mean one key.
      **This is a documented property, not a failed boundary** - plausible
      deniability belongs to the travel BUILD (see README's `STD_VERSION` note
      and the row below), so the second profile's separation being by slot
      numbering is what it is supposed to be. Pinned as it ships, and the test
      fails if the profiles are ever given separate keys.

      Two things bound it anyway, worth knowing before anyone reads it as more
      than it is: a second-profile press can never reach slots 1..12, and no
      client message reads a password back out - so reaching across needs a slot
      both profiles can address, which is what the test arranges deliberately.
- [x] **Self-destruct** → `01-protocol/21-self-destruct`, 2 tests in 63s, gated
      on **`full-wipe`** - the existing capability, reused rather than duplicated,
      because its reason string already says the exact cost: `factorydefault()`
      erases the firmware hash and forces the bootloader, so a physical key needs
      reflashing. Free on the emulator, false on hardware unless somebody sets
      `OKT_ALLOW_FULL_WIPE=yes`. **Do not weaken it.**

      The device answers `UNLOCKED, NO PIN SET` afterwards, which `status()` maps
      to `uninitialized`, and the primary PIN that worked a moment earlier
      unlocks nothing.

      The second test is the one that means something to a person - not "the
      device says it is blank" but "the secret does not come back". It stores a
      password, types it back, self-destructs, RE-PROVISIONS with the same three
      PINs, and presses again. Unrecoverable for two reasons and only one of them
      is the erase: re-provisioning generates a NEW random profile key, so the
      same PINs on the same device cannot read what the old key sealed.

      **Both tests needed a control the first version lacked.** After the wipe the
      slot types nothing at all - and "nothing" is equally what three presses
      discarded mid-fade produce, and what a dead keyboard interface produces. So
      the file writes a different secret into the same slot afterwards and reads
      it back, which is what makes the silence attributable to the wipe.

      Note the ORDER of the three PIN checks is what makes this testable:
      `sdhashevaluate()` is an `else` after both profile evaluations, so it can
      only fire on a PIN that is neither profile's. That is also why
      `lib/config.js` insists the three test PINs are distinct - a repeat would
      be swallowed earlier and this file would wipe nothing while passing.
- [ ] **The International Travel Edition - DEFERRED until the kit is complete**,
      and cheap when it comes. `STD_VERSION` is a `#define` in the sources rather
      than a build flag, so the travel edition is a comment-out and a rebuild.
      **Two lines, not one**, which is the trap: `libraries/onlykey/onlykey.h:84`
      and `OnlyKey-Firmware/OnlyKey/OnlyKey.ino:82` both define it, and doing one
      gives a half-travel build where the units that include `onlykey.h` take one
      side of every guard and the sketch takes the other.

      **File it beside `usb_desc.h`'s commented-out production block** - both are
      hand-edited source variants the build cannot distinguish, so both need the
      same care and neither shows up in a build log.

      **The approach is a DIFF of the same suite across both builds, not a new
      suite.** 76 guard directives (measured; see README for the command) and what
      matters is which behaviours change, which a second suite would assert
      separately and therefore never compare. Everything the kit has - both
      fixtures, every state module, every test - assumes `STD_VERSION` today, so
      anything reached only when `profilemode == NONENCRYPTEDPROFILE` is untested
      by construction. Saying so is the point of this row; it is not a gap to
      close now.

## 4. Section 3 - the pages that are left

Every feature these call is already proven at the library level, so a failure
here means the PAGE. That is the whole reason the tiers are split.

Two things that are not optional for any of them, both already measured:

- **Serve from `localhost`, never `127.0.0.1`.** WebAuthn refuses an IP as an
  rpId, the pages swallow the error, and the only symptom is an output box that
  never fills. The RPID is also folded into the derivation, so any cross-check
  must ask the kit for the same rpId the browser will use.
- **Device up and unlocked before any page opens.** A page whose startup
  `OKCONNECT` times out makes Chromium raise a NATIVE WebAuthn dialog that no
  CDP command can dismiss, and the session is wedged until restarted. The
  landing page in `tools/nwjs` makes no device call, which is what makes it safe
  to start on.

- [x] **THE `ctap_end_get_assertion()` PREDICTION - RESOLVED 2026-08-06, and it
      is vacuous for classic RSA.** It sat here unticked and outside the open-work
      table, which is neither closed nor scheduled - **the exact shape of the
      `18-gui-encrypt-decrypt` mistake**, where an item nobody could see was open
      stayed open for weeks. Resolved rather than tabled, because the reasoning
      below plus one measurement that already exists settles it:

      - **The largest classic RSA response is exactly one chunk.** `chunk_len =
        remaining > 512 ? 512 : remaining` and a classic response is `type * 128`,
        so RSA-4096's 512 bytes is served whole. The condition the prediction
        names - "any response served in more than one chunk" - is **unreachable
        for classic RSA**, so the sentence is vacuous rather than wrong.
      - **The RSA-2048 case is MEASURED and it works.** `01-protocol/23-rsa-tunnel`
        drives OKSIGN and OKDECRYPT over this transport against a 2048-bit key,
        and `03-gui/08`/`14` then drive the same path through the shipped library
        and the pages. That was this row's "RSA-2048 second, because it is what
        the pages actually use", and it landed without anybody connecting it back.
      - **The 512-byte boundary case is BLOCKED, on a defect already tracked.**
        It is the one input where reading the code is least trustworthy, and it
        cannot be driven: loading an RSA-4096 key aborts the firmware on a
        one-byte overflow before any response is served
        ([FINDING-rsa4096-overflow.md](FINDING-rsa4096-overflow.md)). So the
        residue of this row is not a row of its own - it is a case that unblocks
        when that overflow is fixed, and `23-rsa-tunnel`'s
        `OKT_EXPECT_RSA4096_FIX=yes` gate is where it is already waiting.

      Original analysis follows, kept because the chunk arithmetic is what the
      resolution rests on. **READ, NOT MEASURED** where it says so.

      The mechanism splits by response size because a response that fits ONE
      chunk completes inside `send_stored_response()`, which sets
      `pending_operation = CTAP2_ERR_DATA_WIPE` before returning, so the old gate
      passed. A partial chunk set nothing, the gate read the clobbered global, and
      sizing fell to the 72-byte default while the cursor advanced a full 512 -
      hence 71 bytes per 512 and "one byte in seven".

      **The chunk is 512 bytes** (`MAX_LARGE_RESP_CHUNK`, ok_extension.cpp:116),
      not a 64-byte HID report - and that is the number the prediction turns on.
      A classic RSA response is `type * 128`, and `store_FIDO_response()` does
      not grow it (`large_resp_buffer_offset = len`; the encrypt path is
      in place):

      | key | response | chunks |
      |---|---|---|
      | RSA-1024 | 128 B | 1 |
      | RSA-2048 | 256 B | 1 |
      | RSA-3072 | 384 B | 1 |
      | RSA-4096 | **512 B** | **1** - `chunk_len = remaining > 512 ? 512 : remaining`, so 512 is served whole and the cursor reaches the offset in one pass |

      So on this reading **no classic RSA response can exceed one chunk**, the
      largest is exactly one full chunk, and the condition the prediction names
      is unreachable for classic RSA - which would make the sentence vacuous
      rather than wrong. It also means an RSA-2048 signature is NOT the
      multi-chunk case; five 64-byte REPORTS is the raw-HID framing that
      `19-rsa-keys` already drives and where it works.

      **What would settle it, and it has to be driven over the tunnel.** RSA-4096
      is the case worth the trouble, because 512 bytes is exactly the boundary:
      an off-by-one anywhere in the cursor or the `>` would split it, and that is
      the one input where reading the code is least trustworthy. RSA-2048 second,
      because it is what the pages actually use.

      The transport work that needs, since `lib/device/tunnel.js` does a single
      assertion and has no poll loop: `u2fSignBuffer()` in `onlykey-pgp.js` sends
      the request in **228-byte** chunks (`57 * 4`) with `cmd` = OKSIGN/OKDECRYPT,
      `opt1 = slotid()` (2 to sign, 1 to decrypt - the RSA slots), `opt2` = the
      final-packet flag and `opt3` = an incrementing packet number, and the
      payload is **AES-GCM encrypted with the OKCONNECT handshake secret**. So
      either the kit mirrors that encryption and adds a poll loop, or - cheaper
      and the precedent `03-xwing-derive` set - the shipped library sends it and
      the kit checks the answer.
- [x] **A section-2 prerequisite that has DISSOLVED, which makes the row below
      cheaper than PLAN says.** `03-gui/07-pgp-keys` is `device: false` and its
      header explains why the device-backed half is section 2's: it "needs a
      composite key loaded into a slot by `onlykey-cli setpqc`, which is not
      reachable over the browser's WebAuthn transport at all". True for a
      COMPOSITE key. **Not true for a classic RSA key**, which goes into an RSA
      slot with OKSETPRIV over the vendor interface - and `19-rsa-keys` does
      exactly that, from the kit, with no CLI at all. So the classic
      `startEncryption`/`startDecryption` half needs no section-2 step and can
      run in section 3's headless tier, or section 1. **Settled**: it went into
      section 3 as `08-pgp-encrypt-decrypt`, which loads both RSA slots itself and
      never spawns a process, and PLAN's build sheet is corrected.
- [x] **`18-gui-encrypt-decrypt`, THE HEADLESS TIER - DONE.**
      `03-gui/08-pgp-encrypt-decrypt`, 6 tests in 135s, `--isolate` 6/6 and
      `--reverse` green. All five of `_$mode()`'s modes driven through
      `onlykeyApi.pgp().api()`, with `navigator.credentials.get` pointed at
      `lib/device/ctap2.js` - no browser, no display, no CLI, no kernel HID node.

      **The oracle is openpgp.js from the other side of the same key.** The key is
      generated by openpgp.js and the device is given only its factors, so the
      library's output goes back to a library that has never spoken to the device:
      a signature it verifies is one a correspondent would verify, and a message
      it opens is one anybody could open. Self-consistency would have proved
      nothing here, since kbpgp wrote every message and would read its own
      mistakes back happily.

      **One PGP key fills both hardcoded slots**, which is the shape of the thing
      and is not obvious from `slotid()` alone: the primary signs (slot 2) and the
      subkey encrypts (slot 1), so `pgpRsaKey()` splits one generated key across
      them and each modulus is read back over the vendor interface before anything
      is asserted about an operation.

      Two findings, both client-side and both in the premises table above: the
      **`startEncryption` guards are unreachable and the mode hangs** rather than
      erroring - pinned by its own test, written to fail when it is fixed - and
      **`usevirtru` must be passed as nothing, not `false`**.

      A third that is only a cost: `_poll_delay` is picked from the key id COUNT
      rather than the key size, so every signature waits 8 seconds against a
      2048-bit key. That is most of why a device test here is ~30s.

      **The device half was not the variable, as predicted.** `23-rsa-tunnel` had
      already driven OKSIGN and OKDECRYPT over this transport; nothing in this
      file failed on the firmware side, first run.

      **What is LEFT is the browser tier**, and it carries the two constraints
      that are already measured and are not optional: serve from `localhost`,
      NEVER `127.0.0.1` (WebAuthn refuses an IP as an rpId, the pages swallow the
      error, and the only symptom is an output box that never fills - and the RPID
      is folded into the derivation, so a cross-check must ask the kit for the
      same rpId the browser will use); and the device must be up and unlocked
      BEFORE any page opens, or the startup OKCONNECT times out and Chromium
      raises a native WebAuthn dialog no CDP command can dismiss.

      **And one symptom now has two causes, which is worth knowing before
      debugging the page**: "the output box never fills" is what the rpId mistake
      looks like AND what an empty input box looks like, because of the unreachable
      guards above. Check the inputs before blaming WebAuthn.

      Original scope note follows.
- [x] **`18-gui-encrypt-decrypt`, the BROWSER half - DONE.**
      `03-gui/14-gui-encrypt-decrypt`, 6 tests, 107s with its session. All five
      modes through `/app/encrypt` and `/app/decrypt` in nw.js, with the device
      reached by Chromium's own WebAuthn over the USB gadget - the same pairing
      `11-password-generator` has, and the reason a failure here now means the
      PAGE.

      **Four things about the pages that are not guessable**, and two of them
      cost real time:

      1. **The recipients field is not the input it looks like.**
         `jquery.tokenizer.js` replaces `#pgpkeyurl` with a contenteditable span,
         hides the real one and writes `escape(value)` into it. That is what
         `startEncryption`'s `slice(0,11) == '-----BEGIN%'` branch is for - an
         armored key arrives URL-ESCAPED, which is also the only way one fits,
         since an `<input>` strips newlines from `.value`. Driving it means
         `jQuery("#pgpkeyurl").data("tokenizer").add(key)`, which is the call the
         widget itself makes on blur.
      2. **`window.$` does not exist** - app.js sets only `window.jQuery`, and the
         plugin system passes `$` around as a dependency.
      3. **The mode is read off the radio during `page.setup()`**, and each radio
         re-runs setup on `change`. There is no other way in: `page.okpgp` lives
         in the plugin's closure and is not published on `window` the way
         pgp-pqc's test hooks are.
      4. **Both pages write their result back into the SAME textarea** the input
         came from, so "it worked" is "the box CHANGED", not "the box is
         non-empty".

      Two findings, one in the kit and one about the pages - see the rows below
      and the premises table.
- [ ] **`13-pgp-pqc`** - LAST, by decision. Working copy is
      [wip/13-pgp-pqc.test.js](wip/13-pgp-pqc.test.js), which the runner does
      not glob. Everything beneath it is now proven headless by
      `02-cli/06-composite-ops`, so this is page debugging, not coverage. Start
      by instrumenting the page: it already publishes
      `window.__pgpPqcTestHooks` with the live `ok` transport, so wrapping
      `ok.composite_decrypt` over CDP records every device call, and the two
      halves are told apart by argument size alone - 32 bytes is `hooks.ecdh`,
      1088 is `hooks.mlkemDecaps`. See PLAN.md's pgp-pqc block for the rest.

## 5. Section 4 - the OnlyKey app. **ROW 1, ASSIGNED 2026-08-06**

**FIRST: there are TWO "apps" in this tree and they are different codebases.**
This is the trap for anybody arriving at this row, because section 3 is also
called "the app" in half the prose here.

| | section 3's | section 4's |
|---|---|---|
| checkout | `onlykey/onlykey.github.io` | `onlykey/OnlyKey-App` |
| what it is | a web app served by its own express server on port 3000, opened in nw.js | a PACKAGED nw.js app (`manifest_version: 2`, Chrome-App style), loaded from `build/` |
| how it reaches the device | WebAuthn (`navigator.credentials.get`) through the vendor tunnel | **`chrome.hid`** - the Chrome Apps HID API, `app/scripts/onlyKey/OnlyKeyComm.js` |
| nw.js | the kit's own 0.114.0-sdk | its own dependency, `nw ^0.71.1` |
| covered | 84 tests, both tiers | nothing |

Everything the kit knows about driving nw.js (`lib/gui.js`) was built for the
first and has never been pointed at the second.

- [ ] **Section 4, and it is NOT true that there is no ancestor** - that is what
      this row said until somebody looked, and the correction is most of what a
      first attempt needs. It is true of THIS kit and of `onlykey-alpha-testing`.
      **The App ships its own harness**, in `OnlyKey-App/test/`:

      | file | what it is |
      |---|---|
      | `driver.js` | selenium-webdriver pointed at **nw.js's bundled chromedriver**, with `nwapp=<repo>/build`. Builds the driver **at require time**, so loading it launches nw.js |
      | `startup-test.js` | mocha + chai: the disconnected dialog, the working dialog |
      | `configure-slot-test.js` | a whole slot-configuration flow, up to asserting the OKSETSLOT bytes |
      | `serial.js` | a node-hid SEREMU console reader. **Not a test**, and it is what stops the suite running - see below |

      **And it proves the UI against a MOCK, not a device**, which is precisely
      the gap this kit would fill. Its tests call `chromeHid.onDeviceAdded.
      mockDeviceAdded()`, push canned replies with `chromeHid.mockResponse([null,
      msg])`, and read what the app sent back out of `chromeHid._sent`. So the
      wiring is covered and the device never is - the mirror image of every other
      section here, where the device is covered and the page was not.

      **THE SUITE DOES NOT RUN AS SHIPPED, measured 2026-08-06**, and anything
      that proposes adopting it pays to fix that first. `test/serial.js` requires
      `node-hid` and `chalk`; **`node-hid` is not in `package.json` at all** and
      is not installed. Mocha's default spec glob is `test/*.js`, so `npm test`
      loads `serial.js` and dies at the require. Past that it would not terminate
      either - `serial.js` installs a 1 ms `setInterval` with nothing to clear it.
      And `driver.js` builds its driver at module scope rather than in a hook, so
      merely loading the files launches nw.js. Three defects, none of them deep,
      all of them somebody else's repo.

      Two consequences, and they point in opposite directions:

      1. **`chromeHid._sent` IS NOT AN INSTRUMENTATION SEAM AGAINST A REAL
         DEVICE** - this row claimed it was, and the claim is **FALSE**, measured
         2026-08-06. `send()` (`app/scripts/onlyKey/OnlyKeyComm.js:112-125`)
         pushes to `_sent` **only** when `connectionId === "mockConnection"`; the
         real branch calls `chrome.hid.send` and records nothing. Driven against
         the emulator, `_sent` stays empty forever. It is **not** the same shape
         as pgp-pqc's `window.__pgpPqcTestHooks`, which publishes the LIVE
         transport - this publishes only the mock's.

         What is true is weaker and still useful: `chromeHid` is a `const`
         BINDING holding a MUTABLE object, so an injected script can replace
         `chromeHid.send` and `chromeHid.receive` with recording wrappers. That
         is patching, and the cost of the row has to carry it rather than assume
         a seam that is already there.
      2. **A mock that answers is a mock that can drift.** Its canned
         `'UNLOCKEDv0.2-beta.3'` and hand-written slot list are a firmware
         version this kit does not run. Driving the same flows against the
         emulator is what would catch that, and is the reason to bother.

      **THE REACHABILITY QUESTION IS ANSWERED ON THREE GATES, NOT ONE**, which is
      the single most useful thing here - and the row named only the first.
      `onDeviceAdded()` (`OnlyKeyComm.js:1243-1251`) requires all of:

      | gate | the App wants | the emulator's gadget presents |
      |---|---|---|
      | VID/PID | `{7504, 24828}` = `0x1D50:0x60FC`, from `SUPPORTED_DEVICES` | `VENDOR_ID 0x1d50` / `PRODUCT_ID 0x60fc`, `emulator/lib/hid-descriptors.js:19-20` |
      | `collections[0].usagePage` | `65451` = **`0xFFAB`**, the vendor interface | `rawhidDesc(0xFFAB, 0x02)`, same file |
      | `serialNumber` | the literal **`"1000000000"`** | `SERIAL_NUMBER = '1000000000'`, same file |

      So the App can see the emulated device with no change to either side, and
      section 4 needs `client-access` the same way section 2 does. The other
      declared pair, `{5824, 1158}` = `0x16C0:0x0486`, is the Teensy raw-HID
      identity. **READ ON BOTH SIDES, NOT MEASURED** - nothing has yet launched
      the App against the gadget.

      **And note the fallback, because it fails as something else - but it is
      NOT PROVOKABLE, and that is the useful half.** The `else if` beside that
      test is `supportedDevice && device.serialNumber != "1000000000"` - the
      pre-Beta-8 path - which calls `connectDevice()` on **whatever interface
      enumerated first**, with no usagePage check at all. On the gadget that is
      four interfaces sharing one VID/PID, so a serial that stopped matching
      would present as the App talking vendor protocol at the keyboard or FIDO
      interface rather than as "device not found".

      **It cannot stop matching on this firmware.** `usb_init_serialnumber()`
      (`OnlyKey-Firmware/usb_desc.c:1032`) hardcodes `num = 1000000000` with the
      Teensy per-device derivation commented out above it, so every device on
      this firmware presents that serial and the strict branch always wins. Two
      ways to reach the fallback anyway, and **neither is worth a test**:

      | route | cost | what it would prove |
      |---|---|---|
      | re-create the gadget with a different serial | **root**, and a teardown/recreate - the serial is written into configfs once by `scripts/gadget-setup.sh`, not by `gadget-bridge.js`, so it is not a per-run parameter | that the App mis-selects an interface, on a bus configuration no device produces |
      | patch `chromeHid.getDevices` in the page | free | the same thing, against a synthetic input - which is what the App's own mocked tests already do, and the weaker evidence this section exists to replace |

      So: **recorded as a latent branch, not scheduled.** It becomes live the day
      the firmware starts deriving a real per-device serial - which is a change
      worth watching for, since it would silently move every Beta-8 device onto
      the unchecked path.

      **The gadget's identity is `emulator/lib/hid-descriptors.js`, not
      `lib/gadget.js`** - this row cited the latter, which is the KIT's own file
      and a consumer of those values rather than their source. Same numbers, so
      nothing downstream changes; the citation pointed at the wrong side of the
      fence.

      **THE GATING UNKNOWN IS ANSWERED: `chrome.hid` WORKS.** Measured
      2026-08-06, one launch of the REAL App with its REAL manifest under the
      kit's own nw - because "does nw expose chrome.hid to anybody" is a
      different question from "does it expose it to this app, with these
      permissions", and only the second one gates anything.

      | | |
      |---|---|
      | runtime | nw **0.114.0**, Chromium **151.0.7922.0** - the kit's own SDK build, not the App's declared `nw ^0.71.1` |
      | `chrome.hid` | **present in BOTH targets**, all nine methods: `getDevices` `connect` `disconnect` `send` `receive` `sendFeatureReport` `receiveFeatureReport` `onDeviceAdded` `onDeviceRemoved` |
      | `getDevices({}, cb)` | **actually called back** - `lastError` null, 0 devices, which is correct: nothing was on the bus. Presence is not function, so the call was made rather than the API merely inspected |
      | targets | `[app] app.html` and `[background_page] _generated_background_page.html`, both drivable over CDP |
      | `chromeHid` | reachable by name in the app window (`typeof` = `object`), which is where a wrapper would be installed. **Absent from the background page** - it is a `const` in the window's script, so instrumentation belongs on the app target |

      The App got as far as `OnlyKeyComm init()` and enumerated all three
      supported pairs on its own. **So both options were live and option A is
      not blocked** - and section 4 does not need the App's own nw.

      **One benign startup exception, characterised so nobody chases it.** The
      BACKGROUND page throws `TypeError: Cannot read properties of undefined
      (reading 'hasOwnProperty')` at `app.js:106` - `localStorage.hasOwnProperty
      ('autoLaunch')` in the `else if (typeof nw != 'undefined')` branch, where
      nw's node context has no `localStorage` unless it was given a file. The APP
      WINDOW is unaffected and inits cleanly, so it costs nothing but noise.
      **`--localstorage-file=<path>` does NOT fix it** - tried, the warning and
      the exception both survive - so do not spend a second attempt on that flag.

      **`npm install --ignore-scripts` in the App: DECIDED AND VERIFIED, do not
      re-litigate.** The App's `nw ^0.71.1` is a RUNTIME dependency, so a plain
      install downloads a ~150MB runtime the kit has no use for - it drives the
      App with its own nw, as the measurement above shows. Measured on a clean
      copy: **install 6s / 711 packages / 71MB total, with `node_modules/nw` at
      244K** - the package without its binary - and **`gulp build` then succeeds
      and produces byte-identical output** to a normal install's. So the flag
      costs nothing and saves the download. The three build packages (`gulp`,
      `gulp-sourcemaps`, `fs-jetpack`) are pure JS and need no install script.

      **WHERE IT GOT TO, 2026-08-06: SECTION 4 IS STANDING UP AND GREEN.**
      `04-app/10-session`, `11-app-slot-config` and `19-stop` - **11 tests, 23s,
      green twice.** The App is driven against the emulated device for the first
      time in any kit, and the two assertions that matter are the ones its own
      suite structurally cannot make:

      - a slot **LABEL** written through the App's form comes back from the
        device over this kit's own vendor interface, and
      - a **PASSWORD** written through the App's form is what the device TYPES
        when its button is pressed - the keyboard surface, so the secret that
        comes out is checked against the one that went in, not against an
        acknowledgement.

      Four things cost a run each and are now written down rather than repeated:

      | guess | measured |
      |---|---|
      | the App is reload-looping on a version it cannot classify | **NO.** Stamped the window and sampled it 8 times over 12s - the stamp survived every one. `version` is `v3.0.4-testc`, `lastChar` is `c`, so `setDeviceType()` classifies it `classic` correctly. (There IS a `window.location.reload()` in that function's `default:` branch, which is why this was the leading theory) |
      | the App never noticed the unlock | **NO.** `isInitialized: true, isLocked: false, deviceType: classic, connection: 2`, and a screenshot showed the Slots tab open with twelve `empty` slots |
      | the control is missing | **NO - it is TRIPLICATED.** `slot1aConfig` appears **three times** in app.html, and the only VISIBLE one carries no `data-slot-id` while the two that do are 0x0 in hidden panels. "First" and "the one with the data attribute" are both accidents of document order; click whichever is actually visible |
      | the dialog never opened | **IT ALWAYS DID.** `getAttribute('open')` returns the empty string for an open dialog - see the premises table. Three iterations were spent on a detection bug |

      **The tabs now driven: Slots, Keys, Backup.** `12-app-keys` loads a PGP
      RSA key through the Keys form and checks both slots' published moduli
      against openpgp.js's own `n` - a third client agreeing with `slotid()` and
      with `onlykey-cli loadkey` about which half goes where. `13-app-backup`
      captures a backup the DEVICE typed and has the App's own verifier accept
      it, which is two independent readers of one device-written artefact and
      the thing a mocked `chrome.hid` can never reach. **The restore half of
      that tab is not asserted** - see the premises table for what was measured
      and what would settle it.

      **And two real defects came out of it**, both in
      [FINDING-app-slot-button-dead-window.md](FINDING-app-slot-button-dead-window.md):
      the slot buttons are clickable ~1.2s before anything is bound to them, and
      the App's own NEXTKEY3 FIXME does not reproduce against a device. The first
      is why `openSlotDialog()` retries and logs its click count - the same shape
      as section 1's mid-fade press retry, and the run that landed this file took
      2 clicks on its first dialog and 1 on the rest.

      **And one section-wide constraint learned the hard way**: a page wait
      produces no device output, so any wait longer than the **30s inactivity
      budget** aborts the whole run with exit 3 and blames a watchdog rather than
      the test that hung. Section 2 caps its CLI commands at 12s for exactly this
      reason; the arithmetic is the same for anything waiting on a browser. Every
      wait in section 4 is under 20s.

      **THE FIRMWARE TAB IS DELIBERATELY NOT DRIVEN, and this is the record of
      that decision rather than an oversight.** The App has a Firmware tab
      (`#firmware-panel`, `submitFirmwareFile()`), and it reaches **`OKFWUPDATE`**
      - the one message in plane 1 that is gated `emulated` because on a physical
      key it **locks the bootloader and permanently converts a developer key into
      a production key**. Section 4 must not be the door that reaches it by
      accident, so no file here opens that tab, fills that form, or clicks that
      button. If a file ever does, it carries `requires: ['emulated']` like
      `02-cli/14-cli-fido`, and it is driven only as far as its interlocks - the
      same rule as everywhere else. The tab existing and being untouched is worth
      one line so nobody later reads its absence as "nothing there to test".

      What is NOT known, and should be established before writing tests:
      - **`build/` is GITIGNORED** (`.gitignore:5`), so the question this row
        used to ask - "is the checked-in `build/` current" - has no answer:
        there is no checked-in `build/`. What is on this workstation is a local
        artifact from clone time and it IS current (it differs from `app/` only
        by an appended sourcemap comment). So `gulp build` is an unconditional
        prerequisite on any fresh checkout, which is a CI fact rather than a
        developer-convenience one.

        **Measured 2026-08-06, and it is cheap: `gulp build` succeeds in 1.78s,
        exit 0, on Node 24.18.1** - `clean`, `transpile`, `copy`, `finalize`, one
        deprecation warning and no errors. So this costs a second per run rather
        than being a porting project, and the build is a plain file copy plus a
        sourcemap rather than a bundler that could drift. It does `clean` first,
        so `build/` is destroyed and regenerated every time - nothing may be
        edited there and expected to survive.
      - Whether to drive it over **CDP** the way `lib/gui.js` already does, or to
        adopt selenium as the App's own tests do. CDP keeps the kit
        dependency-free and reuses the session machinery; selenium is the path
        the App's authors took, but their tests do not currently run, so
        "and their tests would keep working" is not one of its advantages until
        somebody makes them work. Decide this first - it shapes every file
        after it.
      - ~~Whether a packaged app and the kit's own device host can hold the
        gadget at once.~~ **ANSWERED 2026-08-06: they can.** With the kit's
        device host holding the gadget, the App's own `chrome.hid.getDevices`
        **saw 4 devices** - the gadget's four interfaces - from inside
        `04-app/10-session`. Same split section 3 relies on: the kit's host owns
        `/dev/hidg*` (device side) and the App opens `/dev/hidraw*` (host side),
        so they are not competing for descriptors. `chrome.hid` changes nothing
        about that.
      - Whether the App has a landing state that touches no device.
        **Partly answered: it does not need one.** It has no device-free page -
        `app.html` enumerates as it loads - but with nothing on the bus it
        settles into the disconnected dialog and waits, which is a safe place to
        start from. More importantly the section-3 rule it was borrowed from does
        not apply here: "device up and unlocked BEFORE anything opens" exists
        because a timed-out startup OKCONNECT makes **Chromium raise a native
        WebAuthn dialog** no CDP command can dismiss. The App uses `chrome.hid`,
        not WebAuthn, so that wedge has no equivalent. **What is NOT measured is
        the device-up-but-LOCKED case**, which is the one worth checking before
        assuming the rule can be dropped.

## 6. Section 5 - security. SCAFFOLDED, AND BOTH PREREQUISITES ARE NOW BUILT

**As of 2026-08-06 this heading's old text - "PLANNED, NOT BUILT, AFTER THE
SWEEP" - is no longer true of the blocking half.** Both harness prerequisites
exist, `test/05-security/` exists with its own README carrying the admission
test and the rules, and `okt run 05-security --controls` is green. What is left
is writing tests, which is what the section was waiting for permission to do.

Recorded now while the reasoning is fresh; [PLAN.md](PLAN.md)'s stage 7 carries
the argument for every line here. **Nothing in this section is to be written
until the two harness rows below have landed** - a security test written without
them produces confident nonsense, which is worse than no test.

**The admission test, and it has to be this sharp or the section becomes a junk
drawer:**

> **Does this send something the device should REFUSE, or look for something it
> should not REVEAL?**

Every other section is organised by what a test NEEDS to run - that is why
section 1 runs on hardware and in CI and section 2 can do neither. Security is
organised by INTENT and cuts across all of it, so it cannot be filed by
transport. A test that lands here while actually asserting that something WORKS
belongs in its own section, and the rule above settles that without an argument.

**No deliberate security pass has ever been run against this firmware from this
kit.** Every finding so far arrived sideways, out of coverage work tripping over
something: the RSA slot tail while reading code for a coverage test, the RSA-4096
overflow while loading a key a feature needed, the `last_request_opt3` clobber
because a scripted caller was faster than any human. That is a reason to expect
the surface to repay looking, not a claim that it is unsound.

### The two harness prerequisites - both before any test in this section

- [x] **A dead device host must be a RECORDED RESULT, not the end of the run.**
      **BUILT 2026-08-06** as `device.expectFatal(fn)`. Arms the transport for
      ONE operation; a crash inside that window is captured as evidence - kind,
      signal, code, generation and the whole stderr tail, which is where the
      addon's `[okemu] FATAL:` line and backtrace live for a segfault and
      glibc's `*** buffer overflow detected ***` for an abort - and a fresh host
      comes up against the SAME storage dir. A crash outside the window still
      ends the run, it does not nest, and it REJECTS if the device survives.
      Proven by `01-protocol/25-rsa4096-overflow`, which captures the abort and
      then requires the run to CONTINUE, with a 2048-bit load through the same
      path as its positive control. Verified in a whole-section run: 173 passed
      in 755s with the crash in the middle of it.

      **It does NOT unblock `23-rsa-tunnel`'s 4096 case**, which is about
      response chunking and still needs the key to LOAD. What it retires is the
      kit's inability to test its own most serious finding.

- [x] ~~**A dead device host must be a RECORDED RESULT, not the end of the run.**~~
      For coverage, aborting is right: a device that died mid-suite invalidates
      everything after it. Here it is useless, because **"the device died" IS the
      finding**. `23-rsa-tunnel`'s 4096 case demonstrates both halves - it has to
      be gated off behind `OKT_EXPECT_RSA4096_FIX=yes` just to let the file land,
      and a test cannot observe the abort from the inside because the runner
      classifies a dead host as a run-level abort before any assertion runs. What
      is needed is a runner mode where a crash is captured with its evidence -
      the signal, the addon's `[okemu] FATAL:` line and backtrace, and the request
      that caused it - and the next case continues against a fresh host.
- [x] **NO NEGATIVE ASSERTION COUNTS UNLESS A POSITIVE CONTROL IN THE SAME TEST
      FIRES. A gate, like `--isolate` and `--reverse`.** **BUILT 2026-08-06.**
      `assert.control(what, cond)` records that an instrument was proven;
      `assert.absent(cond, msg)` REFUSES to pass until one has fired in the same
      test. `okt run <target> --controls` is the gate: a file declaring
      `negative: true` fails if any of its tests registered no control.

      **What it cannot do, stated so nobody over-trusts it:** a runner cannot
      look at `assert.equal(count, 0)` and know it is a claim about absence. So
      this does not FIND negative assertions - it gives them a form and checks
      that declared-negative files use it. The discipline stays the author's;
      the gate makes forgetting it visible, which is all a gate can do.

      Proven both ways: green on `05-security/00-controls`, and exit 1 on a
      deliberately naked test that asserts an absence with a plain assertion.

- [x] ~~**NO NEGATIVE ASSERTION COUNTS UNLESS A POSITIVE CONTROL IN THE SAME TEST
      FIRES. A gate, like `--isolate` and `--reverse`.**~~ A section built on "the
      device did not reveal X" is a section where a broken instrument reads as a
      pass, and this kit produced **three** of those in one day:

      | what read as absence | what it actually was |
      |---|---|
      | no plaintext in the RSA slot tail | `pqc.readyForKeygen()` RESTARTS, and a reboot zeroes the global holding the residue |
      | still none, second attempt | `flash.bin` is word-reversed - the search was looking for the wrong byte order |
      | silence from an unknown vendor message id | a CTAPHID error frame on the vendor interface; the test expected silence and was wrong |

      The first two would have closed a real finding as "nothing there".
      `01-protocol/22-rsa-slot-tail` is the pattern to generalise: it writes a
      known marker through a path that is NOT encrypted, finds it, and only then
      believes an absence elsewhere in the same dump. **Prove the instrument in
      the same test, or the absence means nothing.**

### Gating

- [ ] **Emulated-only by default, hardware behind an explicit opt-in** - the
      shape `fido-reset` and `full-wipe` already use, with the reason string
      naming the cost. Provoking malformed writes, oversized lengths and
      deliberate crashes against a physical key is a separate risk conversation,
      and the gate is where that gets recorded rather than assumed.

### What makes it cheap: the instruments already exist

Built for coverage, each also a security instrument. Nothing here needs new
transport work.

| instrument | what it gives |
|---|---|
| `lib/device/transit.js` | seals ARBITRARY bytes, so a request can be malformed AFTER encryption rather than before |
| `lib/device/ctap2.js` | CTAPHID directly - frames, channel ids, commands the firmware does not implement |
| `okmsg.build` | vendor messages framed by hand, so every field can be wrong on purpose |
| `flash.bin`, dumpable | reads storage out of band, which is how "should not reveal" is checked at all |

**And `_FORTIFY_SOURCE` is the part a physical key cannot offer**: the emulator
builds with it, so an overflow ABORTS where it happens instead of corrupting
whatever was next in memory. That is how the RSA-4096 one-byte overflow was
found, and it is the strongest single argument for doing this work here rather
than against a key. See EXPLAINER.

### Candidate rows, not exhaustive

- [ ] malformed and oversized length fields on every framed message
- [ ] out-of-order and forged continuation markers - `buffer[6]` means two
      different things in two chunked sends, which is a parser confusion waiting
      to be aimed
- [ ] `opt3` manipulation on the tunnel: the high-water mark is a DROP rule, so
      it is also a replay and truncation surface
- [ ] **the zero-IV keystream reuse question on the transit box.** Every message
      in a session is AES-256-GCM under the same key with a TWELVE-BYTE ZERO IV,
      tag discarded - one keystream XORed against every message in both
      directions. That is the firmware's design and mirroring it is the only way
      to talk to it; what nobody has done is assess whether it is exploitable in
      practice - what a passive observer of two messages recovers, and whether
      any message is attacker-chosen.
- [ ] unknown vendor ids reaching the CTAPHID stack, which the dispatcher's
      `default:` hands to `recv_fido_msg()` - a parser reached by a path its
      callers did not intend
- [ ] refusal paths asserted WITH controls: every "Error not in config mode" and
      "Error device locked" is a security property arriving where a client sees
      it, and each is worth one test proving the operation would otherwise have
      succeeded
- [ ] **THE KEYBOARD INTERFACE AS ATTACK SURFACE, and it is the biggest single
      row in this section.** `process_setreport()` (okcore.cpp:7638) is a THIRD
      command channel beside the vendor interface and the WebAuthn tunnel, and it
      is the least documented of the three. All of the following is **verified by
      reading the source**, not measured - nothing can measure it until the IPC
      verbs below exist.

      **What it accepts.** Slot selection from `keyboard_buffer[64]` - `1`, or
      `3..27` - and a write-or-wipe request at `keyboard_buffer[45]` (`5` or
      `0`). Beyond the HMAC-SHA1 challenge-response this is named for, the same
      handler sets **Yubico OTP keys**, writes **`addchar`** per slot, and
      changes **TYPESPEED device-wide** from `CFGFLAG_PACING_*` - a global
      setting written from the keyboard interface.

      **What guards it, stated precisely, because two of the three are easy to
      describe wrongly:**

      | guard | what it actually does |
      |---|---|
      | `initialized && !unlocked` → early return | **inert while locked**, confirmed. Note it does NOT fire on an UNINITIALIZED device - that case is caught instead by the dispatch condition's own `initialized && unlocked` |
      | `check_crc(keyboard_buffer)` | a well-formedness check on the report |
      | `CRYPTO_AUTH` | **an interlock, not an authorization.** The test is `if (!check_crc(...) \|\| CRYPTO_AUTH) return;` - it REFUSES while a crypto operation is pending. It is not a confirmation requirement, and reading it as one would mis-scope every test here |

      **THE PART WORTH THE WHOLE ROW: this path SYNTHESISES vendor messages and
      injects them past the vendor dispatcher's guards.** It fills `recv_buffer`
      with `OKSETPRIV` / `OKSETSLOT` / `OKWIPESLOT` and calls `set_private()` or
      `recvmsg(1)` **directly** - so it never passes `case OKSETPRIV:`
      (okcore.cpp:451), which is where `configmode == true` and the user-slot
      allow-list live. **Config mode does not gate this surface.** That is not an
      inference: the firmware's own comment at okcore.cpp:458-465 says HMAC
      (129/130) and derivation (128/132) "use other paths that call
      set_private() directly and bypass this dispatch".

      And one of the things it can write is **`hmac_challengemode`** - the flag
      that makes an HMAC slot require NO button press (`recv_buffer[7] = 1; //
      Authlite no button press required`). So a surface that bypasses config mode
      can also remove a user-presence requirement. Whether that composes into
      anything is exactly what this row is for.

      **WHY IT IS UNTESTED IS STRUCTURAL, NOT A JUDGEMENT.** The harness cannot
      reach it: this channel is HID control transfers (`SET_REPORT` 0x0921 /
      `GET_REPORT` 0x01a1), the emulator ports both and the addon exports
      `kbdSetReport`/`kbdGetReport`, and what does not exist is an IPC verb - so
      `device.send(IFACE.KEYBOARD, …)` cannot reach it, because an interrupt OUT
      report is not a control transfer. Nobody assessed this as low risk; nobody
      could assess it at all. **Same shape as the OnlyKey App being tested
      against a mock**: unexamined for a structural reason rather than a
      considered one, which is the pattern this section exists to break.

      **And it outlives the debug console.** A production key ships without
      SEREMU - that is PRODUCTION.md's whole argument - while the keyboard
      interface ships on every build, because it is the device's primary
      function. So this surface is present exactly where the console is not.

      **OPEN QUESTION, to answer when the section is built - UNVERIFIED, and it
      is the one that decides how much this matters:** does a local unprivileged
      process reach a keyboard interface more easily than it reaches `0xFFAB`,
      and does that differ per OS? The WEB path is closed - browsers refuse
      keyboard-usage devices in WebHID - so the browser cannot be the vector.
      The local one is the unknown, and it is an OS-permissions question rather
      than a firmware one, so it wants measuring on each platform rather than
      reasoning about.

      **Prerequisite: the two IPC verbs**, which is the same prerequisite the
      HMAC feature test has - see §2. One piece of plumbing unblocks a coverage
      row and a security row, which is most of the argument for doing it.

---

## The state the emulated fixtures were left in, 2026-08-05

Written down because it is nowhere else and a cold reader will assume otherwise.

- **Nothing was rebuilt and nothing is stale.** Every file this session ran booted
  from the cached `initialized` fixture (`c3525fff6ff3`) and none of them rebuilt
  it. The fingerprint covers the built firmware and the state module, so the cache
  is valid until one of those moves.
- **No test leaks state into another**, because each file gets a fresh copy of the
  image - which is why `19-rsa-keys`, `22-rsa-slot-tail`, `23-rsa-tunnel` and now
  `03-gui/08-pgp-encrypt-decrypt` all write RSA slots 1 and 2 freely and none of
  them cleans up. Do not add cleanup; it would be dead code. The last of those
  goes further and writes a fresh key **per test**, which is what buys it
  `--isolate`: the cost is a key load each time, and that was the trade.
- **`~/.cache/onlykey-testing/fixtures/` holds more than one `initialized-*`
  directory** - older fingerprints from previous firmware builds. Harmless, and not
  evidence of anything.
- **`21-self-destruct` factory-resets the device mid-file** and re-provisions with
  `initialized.apply()`; that is contained to its own run directory's copy.

## The state the physical key was left in

Recorded because it is nowhere else and the next hardware run inherits it.
Updated 2026-08-06 after sections 0 and 1 ran against the key
(`libraries@83353cf`), run `20260806-131421`. There is no fixture restore on
hardware, so whatever the last file did is what the next run finds.

**The key was WIPED AND RE-PROVISIONED during this run** - `03-wipe` and
`04-provisioning` do that every time on hardware - so the 2026-08-05 leftovers
recorded here previously (an X-Wing key in ECC1, a composite blob in RSA1) are
gone, and any conclusion resting on them is void. What persists now:

- **RSA1 and RSA2** hold `19-rsa-keys`' and `23-rsa-tunnel`'s RSA-2048 test keys,
  the later file overwriting the earlier. Real keys, generated per run.
- **ECC slots** hold `14-stored-keys`' six key types, the last written being
  X-Wing in slot 101.
- **`stored_key_challenge_mode` = 1**, still, and still the one that changes the
  key's security posture: every stored-key crypto operation takes ONE press of
  any button instead of a three-digit challenge. `14-stored-keys` sets it and
  does not restore it. It survives the wipe because the wipe runs BEFORE it.
- **A slot label and password from `10-backup-restore`'s restore**, which is the
  file's own point.

Undoing the challenge mode means entering config mode and writing slot field 22
back to `0` **as the byte, not the character** - see README, "Challenge modes".
Everything else is overwritten by whatever runs next.

Not left behind: no FIDO2 client PIN. `18-clientpin-credmgmt` sets one, but it
requires `fido-reset`, which is false on hardware unless somebody opts in - so
that file skipped all five of its tests and never touched the key. Confirmed in
this run's skip list rather than assumed.

**And note what a hardware run costs the key**, since nothing said so before:
about **30 reboots**, a full wipe, a re-provisioning, and a restore. That is
fine for a developer key and is worth knowing before pointing this at one that
matters.

## Order debt, the other direction - MEASURED

- [x] **`--reverse` across the tree**, one ordinary run per file, 2026-08-05.
      **55 files in scope, 30 pass, 25 fail.** Recorded as debt and NOT fixed,
      the same decision the isolate pass took: the coverage is worth more than a
      clean order record, and `--reverse` stays a gate for NEW files.

| section | files pass/total |
|---|---|
| `00-sanity` | **7/7** |
| `01-protocol` | 12/23 |
| `02-cli` | 7/16 |
| `03-gui` headless | 3/8 |
| `04-app` | 1/1 |

      Sanity is clean for the same reason it is clean under `--isolate`: those
      files are `device: false`, so there is no device state to spoil. The four
      session-scoped GUI files (`10-session`, `11`, `12`, `14`, `19-stop`) are
      **not in scope and are not debt** - `10-session` starts nw.js and the express server
      and `19-stop` stops them, so running any of them alone would orphan a
      browser and a server. Not run, rather than run and cleaned up after.

      **THE PATTERN IS ONE THING, and it is the mirror of the isolate pattern.**
      Look at which test is named in each failure: `cleans up after itself`,
      `has the restored label back`, `put the key where it said it did`, `signs
      with the key it was given`. These are FINAL tests being run FIRST. A file
      written as a narrative - establish, use, verify, tidy up - reverses into
      tidy-up-first, and the cleanup test is usually the one that fails because
      there is nothing yet to clean up. That is a different fault from the
      isolate one and it needs the same fix: establish the state you assert
      about.

      **The gate is working, and this is the evidence.** Every file written since
      `--reverse` became a gate passes it: `01-protocol/13`-`22` (ten files, all
      green), `02-cli/10`-`15` (six files, all green) and `03-gui/08` (green,
      landed after this sweep and therefore outside its 55). Every failure is in a
      file that predates the rule. Nothing that landed under the two-gate rule
      has failed either gate.

| file | reversed failure - the test that runs first and cannot |
|---|---|
| `01-protocol/02-restart` | keeps its storage across the reboot |
| `01-protocol/03-wipe` | no longer accepts the old PIN |
| `01-protocol/04-provisioning` | unlocks with the PIN it was just given |
| `01-protocol/05-snapshot` | boots LOCKED, always |
| `01-protocol/06-vendor-status` | does not read the vendor interface at all while locked |
| `01-protocol/07-unlock` | unlocks once the whole PIN has landed |
| `01-protocol/08-slot-keyboard` | wipes the slot without taking the firmware down |
| `01-protocol/09-fido-ctaphid` | answers a PING on any channel id, allocated or not |
| `01-protocol/10-backup-restore` | has the restored label back |
| `01-protocol/11-fido2-ceremony` | refuses an assertion for a credential it does not know |
| `01-protocol/12-webauthn-tunnel` | rejects a command it does not implement |
| `02-cli/00-venv` | reports a locked device as locked, the same way the kit does |
| `02-cli/01-pqc-keygen` | put the key where it said it did |
| `02-cli/03-pqc-decrypt` | cleans up after itself |
| `02-cli/04-pqc-no-device` | cleans up after itself |
| `02-cli/05-composite-load` | signs with the key it was given |
| `02-cli/06-composite-ops` | will not sign the same digest twice without a new confirmation |
| `02-cli/07-derived-xwing` | cleans up after itself |
| `02-cli/08-lib-agent-ssh` | hashes the user and the host, and nothing else |
| `02-cli/09-lib-agent-gpg` | cleans up after itself |
| `03-gui/00-fido2-lib` | reads the same firmware version the kit does |
| `03-gui/02-derive` | derives a shared secret against that public key |
| `03-gui/03-xwing-derive` | cannot be finished without the device |
| `03-gui/06-composite-key` | generates a different key every time |
| `03-gui/07-pgp-keys` | carries the mode the page sets |

      **Two of these are deliberate rather than lazy**, the same two the isolate
      pass excused: the lib-agent pair and the composite PGP files are built
      around ONE long operation with several assertions about it, and re-running
      `onlykey-gpg init` per assertion would test something different from what
      the file is for. `--reverse` reporting them is the flag working, not a
      defect to chase.

      **One thing the sweep proved about itself:** running the "cleans up after
      itself" tests first left NO orphans - no `onlykey-gpg-agent`, port 3000
      free - so those cleanups are safe to run against nothing, which is worth
      knowing before anyone reorders them.

## Isolation debt

Measured 2026-08-05 with `okt run <file> --isolate`:
**40 files, 232 tests - 17 files pass, 23 fail, 148/232 tests (64%) stand alone.**

**THAT SCOPE IS STALE, and adding to the numbers rather than re-deriving them was
the wrong fix - it read as current when it was not, which is the exact failure
this file warns about for the counts table.** The sweep covered the tree as it
stood when it ran: 13 files in `01-protocol` and 11 in `02-cli`. The reverse sweep
above counted **55 files in scope** on the same day, so **15 files are outside
this tally** - `01-protocol/13`-`22` and `02-cli/11`-`15`.

All 15 pass `--isolate` individually, because they landed under the two-gate rule
and could not have landed otherwise (the one row that does not record its result
is `02-cli/10-cli-reads`). So at FILE level today it is 32 of 55 rather than 17 of
40 - 33 of 56 counting `03-gui/08-pgp-encrypt-decrypt`, which landed after both
sweeps and passes both. The test-level percentage has NOT been re-derived and the
table below is the 40-file measurement - re-run the pass if the number matters,
rather than arithmetic on this one.

Retrofitted **opportunistically**, when a file is being worked on for another
reason. Not a project of its own: the sweep is worth more than a clean
isolation record. `--isolate` is a gate for NEW files only.

The pattern is the same everywhere: test 1 establishes something - an unlock, a
registered credential, a generated key, a written slot - and tests 2..n assert
about it. `device.ensureUnlocked()` fixes the unlock half cheaply; the rest
means each test redoing the establishing step, which is sometimes right and
sometimes changes what the file is testing.

| section | files pass/total | tests alone |
|---|---|---|
| `00-sanity` | **7/7** | 50/50 |
| `01-protocol` | 3/13 | 38/68 |
| `02-cli` | 4/11 | 33/64 |
| `03-gui` headless | 3/8 | 26/49 |
| `04-app` | 1/1 | 1/1 |

Sanity is clean because those files are `device: false` - there is no device
state to inherit. Files that fail, worst first:

| file | alone |
|---|---|
| `01-protocol/08-slot-keyboard` | 1/6 |
| `01-protocol/11-fido2-ceremony` | 1/6 |
| `01-protocol/12-webauthn-tunnel` | 1/6 |
| `02-cli/03-pqc-decrypt` | 1/6 |
| `02-cli/06-composite-ops` | 1/7 |
| `02-cli/07-derived-xwing` | 1/7 |
| `03-gui/03-xwing-derive` | 1/6 |
| `03-gui/07-pgp-keys` | 1/6 |
| `01-protocol/09-fido-ctaphid` | 2/4 |
| `01-protocol/02-restart` | 2/4 |
| `02-cli/04-pqc-no-device` | 2/5 |
| `02-cli/05-composite-load` | 2/4 |
| `02-cli/08-lib-agent-ssh` | 2/7 |
| `03-gui/00-fido2-lib` | 2/6 |
| `03-gui/02-derive` | 2/6 |
| `03-gui/06-composite-key` | 2/5 |
| `01-protocol/10-backup-restore` | 3/9 |
| `01-protocol/03-wipe` | 3/5 |
| `01-protocol/04-provisioning` | 3/4 |
| `01-protocol/07-unlock` | 3/4 |
| `02-cli/01-pqc-keygen` | 3/5 |
| `02-cli/09-lib-agent-gpg` | 5/9 |
| `01-protocol/01-debug-console` | 5/6 |

**`04-app/10-session` and `04-app/19-stop` are outside both gates for the same
structural reason, as of 2026-08-06** - and this is stated rather than left to be
inferred from their absence, which is how an untested file starts looking tested.
`10-session` builds the App and raises nw.js; `19-stop` takes it down. Under
`--isolate` each test would get its own device session and start its own App with
nothing to stop it; under `--reverse` the chrome.hid test would run before the
start test and fail on a session that does not exist yet. Neither is isolation
debt.

**And that extends to the whole section, which the first version of this
paragraph got wrong.** Every device-driving file in section 4 needs the session
`10-session` holds, exactly as `03-gui/14-gui-encrypt-decrypt` does, so the
section is outside both gates by construction rather than by debt. What is
required instead is the same discipline `14` keeps: **minimum coupling within
the file** - every test establishes the device state it asserts about and
attaches its own page, so that a failure names one test rather than the file.

**`03-gui/10-session`, `11`, `12`, `14`, `19-stop` are not in the tally and are
not debt.** They are structurally non-isolatable BY DESIGN: `10-session` starts
nw.js and the express server and `19-stop` stops them, which is the kit's
no-hooks rule working as intended. Running `--isolate` over them would start a
browser and a server with nothing to stop them and orphan both, so it was not run
rather than run and cleaned up after. `14-gui-encrypt-decrypt` joins them for the
same reason and keeps its coupling to the minimum the tier allows: one leading
test establishes the device and the keys, and every later test opens and closes
its OWN page.

Two files are deliberate rather than lazy even within the tally: the lib-agent
pair and the composite PGP files are built around ONE long operation with
several assertions about it. Re-running `onlykey-gpg init` per assertion would
test something different from what the file is for.

## Kit-side items from 2026-08-05, all small and all otherwise unrecorded

- [x] **THE WHOLE TREE OUTGREW `RUN_MAX`, AND HAD ALREADY DONE SO BEFORE THE FILE
      THAT REVEALED IT.** Raised to 30 minutes on 2026-08-05, with the
      measurements in `lib/config.js` beside the number so it reads as a ceiling
      rather than a guess.

      **The first version of this row blamed the wrong file, which is worth
      keeping because the correction is the finding.** It said
      `03-gui/08-pgp-encrypt-decrypt`'s 135s spent the 21s of headroom left by the
      879s sweep. Wrong: that sweep's section 1 was **367s for 96 tests**, and the
      five files that landed at 21:02Z took it to **707s for 112**. So the tree
      needed ~1217s the moment `19-rsa-keys`..`23-rsa-tunnel` landed - **over the
      cap by five minutes, hours before the new file existed.** Nobody saw it
      because nobody ran the whole tree afterwards, which PLAN's own counts note
      says in as many words ("Neither adapter has run the whole tree since").

      **A per-file cost is invisible against a per-RUN cap.** Each of those six
      files was measured, green and cheap on its own; nothing in the workflow adds
      them up, so the tree broke by accumulation with every individual step
      correct. That is the argument for the eventual shape:

      - [ ] **Make the budget per-SECTION rather than per-run.** DEFERRED by
            decision, not forgotten. A whole-run cap has to be resized every time
            the tree grows and goes stale silently in between, which is exactly
            what happened here; a per-section cap is bounded by the section's own
            content and a section that doubles is a thing somebody notices. Also
            the honest shape for `--isolate` and `--reverse`, which are per-file
            and have no run-level meaning at all.

      Measured per section (each from a run, not arithmetic): sanity <1s,
      `01-protocol` 707s, `02-cli` 435s, `03-gui` 211s, `04-app` ~2s - **~1356s,
      22.6 minutes**. 30 minutes is 1.33x that. Re-measure rather than doubling
      when it next binds, and note that INACTIVITY (30s, no-progress) is what
      actually catches a wedge - RUN_MAX only bounds a wedge that keeps talking.
- [ ] **A run-max that fires DURING A BOOT is reported as exit 5, not 3.**
      This one is a defect regardless of which way the first is settled, and the
      code says so itself. `deviceVerdict()` returns null when a watchdog has
      fired, with the comment "classifying that as an external kill would hide the
      watchdog behind exit 5" - and then the boot-failure path (`lib/runner.js`
      ~425) does exactly that:

      ```js
      const verdict = deviceVerdict(transport, watchdogs) || {
        code: EXIT.HOST_DIED,                       // <- 5, unconditionally
        reason: `the device host never finished booting: ${err.message}`,
      };
      ```

      So the sentinel carried the truth and the exit code contradicted it:

      ```
      OKT-END status=aborted code=5 ... reason="the device host never finished
      booting: cancelled while waiting for ...: run-max watchdog: the run exceeded
      its 900s maximum"
      ```

      **5 means "the run did not produce a verdict at all" and 3 means "a watchdog
      fired"**, and README says the whole point of the codes is telling those apart
      without reading anything. An agent that greps the code and not the reason
      concludes the host died.

      Same family as the SIGABRT row below and it wants the same treatment: fix the
      path and add the case to `00-sanity/05-exit-classification` together, so the
      oracle covers it rather than waiting for another 900-second run to prove it.
      **Deliberately not fixed in the commit that found it** - it changes the kit's
      verdict contract, which every other file's failure reporting rests on, and it
      belongs in its own change with its own coverage.
- [ ] **AN EXIT-4 ABORT LEAKS ITS DEVICE HOST, and the evidence is four orphans
      on this workstation right now.** `Reporter._installExitHandlers()`'s
      `bail()` (lib/report.js:184) writes the sentinel and then calls
      `process.exit(EXIT.RUNNER_ERROR)` directly - so the uncaught-exception and
      unhandled-rejection paths never reach `stopDevice()`. The child reparents
      to init and keeps running: the firmware thread spins, so each orphan costs
      about 9% of a core indefinitely.

      Measured 2026-08-06, four device hosts with `ppid=1`, two of them traceable
      to their runs by pid and both the SAME failure shape:

      | pid | run | sentinel |
      |---|---|---|
      | 752721 | `20260804-230114-752710` | `code=4 ... "unhandled rejection: TypeError: Cannot read properties of undefined (reading 'emit')"` |
      | 995541 | `20260805-214524-995530` | `code=4 ... "unhandled rejection: TypeError: onlykeyApi.getKey is not a function"` |

      The other two came from ad-hoc runs in another session's scratch directory
      that drove `lib/host/device-host.js` directly rather than through the
      runner, so they are the same leak reached by a different door.

      **`lib/gui.js` already solved this and the device host never got the same
      treatment**, which is the useful part: `installSafetyNet()` registers
      `process.on('exit', killEverything)` for the browser and the web server,
      added after "one aborted run left seven Chromium processes and an express
      server holding both ports, and the NEXT run then failed in startServer()
      with a port conflict a long way from the cause". The device host has no
      equivalent. Give it one - a process-group kill on `exit`, the same shape -
      rather than adding a `stopDevice()` to each bail path, because the
      scratch-run door proves the paths are not enumerable.

      **It is quieter than the browser version**, which is why it went unnoticed
      for two days: an orphaned device host holds no port and no device node, so
      nothing later fails because of it. It just burns a core and holds a
      `flash.bin` mapping. The only symptom is `ps`.
- [x] **SIGABRT is classified as "not the firmware's fault", and it is.** FIXED
      2026-08-06, with its oracle in the same change - three cases in
      `00-sanity/05-exit-classification`: the signal, glibc's own
      `*** buffer overflow detected ***` line (needed separately, because
      `okemu_restart.cpp` only handles SIGSEGV so NOTHING of ours prints on an
      abort), and the deliberate asymmetry that an abort during boot is NOT
      retried the way a segfault is - a fortify trip is deterministic, so
      retrying turns one clear failure into three slow ones. Sanity is 56.
      **The kit had been contradicting its own finding**: FINDING-rsa4096-overflow.md
      names the abort as the defect's signature while `classifyExit()` reported
      it as exit 5, "the run produced no verdict".

- [x] ~~**SIGABRT is classified as "not the firmware's fault", and it is.**~~
      `classifyExit()` maps SIGSEGV to a firmware crash (exit 2) but SIGABRT falls
      through to external/OOM (exit 5), which reads as "the run produced no
      verdict". A `_FORTIFY_SOURCE` abort IS a firmware crash and is exactly the
      class of bug the emulator exists to catch - it is how the RSA-4096 overflow
      surfaced. `00-sanity/05-exit-classification` covers eight outcomes and
      SIGABRT is not one of them, so add the case and the oracle together.
- [ ] **Decide the shape of the RSA-4096 regression test.** `23-rsa-tunnel`'s 4096
      test currently SKIPS unless `OKT_EXPECT_RSA4096_FIX=yes`, because ungated it
      aborts the device host and takes the whole file - and both its order gates -
      with it. That was chosen so the file could land at all, and it keeps the
      defect in every run's skip list with the finding named in the reason. The
      alternative is to let it run as a known-aborting reproducer and exclude the
      file from full-tree runs. Either is a one-line change; the maintainer's call.
      A test cannot observe this from the inside, because the runner classifies a
      dead host as a run-level abort before any assertion executes.
- [ ] **`@noble/ciphers` is now a declared optional dependency** and was
      previously present only TRANSITIVELY, which is the trap this file warns about
      - an oracle that can be absent is an oracle that silently stops running.
      `lib/device/transit.js` needs its `hsalsa`. Declared as `^2.2.0` (the version
      installed and measured against NaCl's published vector). If the lockfile
      question below is ever settled, this is another reason to settle it.

## The CLI never maps failure onto its exit code - ONE CLASS

- [ ] **Consolidated in [FINDING-cli-exit-codes.md](FINDING-cli-exit-codes.md),
      which is the version to send.** This had been recorded three times as three
      separate surprises - `setpqc` claiming success for a load the device
      refused, `set-pin` exiting 0 while printing a traceback, `setkey` storing
      nothing on the 4096 path - and they are three routes into one hole. A
      maintainer can fix a class and cannot fix three symptoms, so the scattered
      mentions elsewhere in this file now point here.

      Three routes, needing three different fixes:

      | | route | measured on |
      |---|---|---|
      | a | prints its own success string, never reads the reply | `setpqc` |
      | b | reads the reply, prints it verbatim, never tests it for `Error` - or for being EMPTY | seven settings commands, `setkey`, `init` |
      | c | catches a host-side exception, prints it, falls off the end | `credential`, `set-pin`, `change-pin` |

      **Twelve subcommands confirmed, roughly 25 of the 37 expected** - every
      command that WRITES, because they all bottom out in `setslot` or `setkey`.
      The six read commands are not expected to share it: a failed read is visible
      as missing output rather than as a false success. The write-up names which is
      which.

      Worth knowing before fixing: `02-cli/14-cli-fido` asserts the CURRENT
      behaviour deliberately, so a fix makes that file fail, which is the
      convention working rather than a regression.

## The venv's solo / python-fido2 mismatch

- [ ] **Decide whether to pin them back into step.** `credential`, `set-pin` and
      `change-pin` all fail inside `solo` with `'Fido2Client' object has no
      attribute 'client_pin'` - solo calls an API the installed python-fido2 has
      removed. `wink` works, so the transport and the device are fine; it is
      purely the PIN-token path. `02-cli/14-cli-fido` asserts the current
      behaviour, so whichever way this is resolved that file will need its
      assertions updated - deliberately, since a test whose subject is a known
      breakage should fail when the breakage is fixed.

## Not tests

Tracked here so they do not get lost, but they are not coverage.

- [ ] **Stage 2, CI - PARKED DELIBERATELY, not abandoned.** The workflow exists,
      is `workflow_dispatch` only, and has still never run on GitHub. Do not
      dispatch it and do not add push/PR triggers for now.

      **Why it is parked:** hosted CI is being re-envisioned once the
      local/developer-station side settles. A Raspberry Pi bridge could let a
      SELF-HOSTED runner reach a real device node - which would put sections 2,
      3 and 4 in reach of automation, and those are permanently impossible on a
      hosted runner. That is a different workflow with a different shape, not
      this one plus triggers, so building this one out further would be work
      thrown away.

      **What is already done and stays done.** Four defects were found by
      simulating every step against a clean tree and are fixed in the file
      (`1349aca`): the emulator repo name was wrong; `npm install` cannot work
      in `emulator/` because `"gypfile": true` runs node-gyp before
      `scripts/stage.js` generates the `sources.gypi` that `binding.gyp`
      includes; `npm run build` has no configure step; and the Teensy core -
      one of the FOUR trees `stage.js` requires - was never checked out at all.
      With those fixed the addon builds from a clean tree locally.

      **What is still unverified** is everything GitHub-specific: the runner
      image, the sysctl, the sparse checkout resolving, the artifact upload.

      **And note it cannot be dispatched from this workstation**, which is a
      practical fact rather than part of the decision: there is no `gh` binary,
      no `GH_TOKEN`/`GITHUB_TOKEN`, and no git credential helper. Dispatching
      means the Actions tab, or installing `gh` first. That is why the four
      defects were found by simulating the steps locally against a clean tree
      rather than by watching a run fail.

      Whatever replaces this must keep the two assertions the file already
      makes, since both fail in ways that do not look like themselves: the mmap
      rung (`vm.mmap_min_addr=4096`) and the `xwing-math` capability, BEFORE
      running anything. At the unprivileged default the device boots and answers
      HID and only segfaults once something encrypts; and a missing optional
      package skips a file with a reason and goes green, which is exactly how a
      test stops existing without anyone noticing.
- [ ] **Track `package-lock.json`?** Currently gitignored, with four declared
      optional dependencies - `node-hid` and three `@noble` packages, the last of
      which is cryptographic maths the suite checks itself against.
- [x] **Crypto vectors against derived and stored keys** - the challenge-mode
      configuration is worked out, and it is two facts:

      1. **`stored_key_challenge_mode` = 1 turns the three-digit challenge into a
         single press of ANY button.** `done_process_packets()` sets
         `CRYPTO_AUTH = 3` instead of computing the digits, and the press handler
         in `OnlyKey.ino` has a clause - `(stored_key_challenge_mode==1 && isfade
         && packet_buffer_details[0])` - that goes straight to `CRYPTO_AUTH = 4`
         without checking which button was pressed. `derived_key_challenge_mode`
         has the identical clause.
      2. **It must be sent as the BYTE 1, not the character `'1'`.** The clause
         tests `== 1` exactly. The string puts 0x31 in EEPROM, which is truthy
         enough for `done_process_packets()` to set `CRYPTO_AUTH = 3` - so the
         device primes and looks like it is waiting for one press - and then no
         press satisfies the clause and the operation answers "Error incorrect
         challenge". That is almost certainly why the row read as unworkable.

      Worth knowing: `03-gui/02-derive` sets the DERIVED mode with `String(8)` =
      0x38, and it works only because the tunnelled path tests
      `is_bit_set(mode, 3)` and 0x38 happens to have bit 3 set. Right by
      accident, and it would not survive being changed to another value.
- [ ] **Backup typing takes ~46s** at the default TYPESPEED. Setting a faster
      type speed before the backup would roughly halve the longest test.
- [ ] **Fold the flasher's pacing back** into
      `onlykey-usb-hid-passthrough/tools/halfkay_flash.py` if direct-attached
      flashing becomes routine there too. The kit has its own copy; the original
      still dies at block 4 without a proxy.

## In-process vendor capture reorders a long answer (2026-09-22)

`02-cli/15-age-file-interop` found it: the 1216-byte derived X-Wing recipient
(19 reports) comes back from `device.reportsSince(IFACE.VENDOR, …)` rotated -
reports 9..18, then 0..8 - identically every time, while `age-plugin-onlykey`
reading the kernel hidraw node gets it in order (and `02-cli/07` decrypts to
it). The firmware sends in order. Suspect the device-host's back-pressure when
nothing drains the gadget node. Until fixed, anything longer than ~9 reports
should be read through the node (15 now uses the plugin for the recipient).

## 04-app: run the App under nw.js 0.71, not 0.114 (2026-09-23)

Under the kit's nw.js 0.114 SDK, `10-session` passes but any test that waits
for the device fails with `{conn: null, init: false}`: the page stays at
`document.readyState === 'loading'` (every script has run - `dialogMgr`, the
last script's const, exists - but parsing never ends), `load` never fires,
so `init()` never runs. Same with upstream OnlyKey-App `b8918ce`.

Under nwjs-sdk-v0.71.1 - the line the App's own package.json pins
(`"nw": "^0.71.1"`) - it loads normally and `14` and `17` pass:

    OKT_NW_BINARY=/opt/ok/nw71/nwjs-sdk-v0.71.1-linux-x64/nw DISPLAY=:99 \
      node bin/okt.js run test/04-app/10-session.test.js ... test/04-app/19-stop.test.js

TODO: make lib/gui.js findNw() prefer an SDK matching the App's pinned nw
for section 4 (section 3 can stay on 0.114), and find out what 0.114 is
waiting on - the App will have to move off 0.71 eventually.

## FINDING: the first FIDO packet after unlock can be swallowed by vendor traffic (2026-09-23)

okcore.cpp, the `!useinterface` branch (an Android workaround): on the first
FIDO packet after unlock the firmware waits 100 ms, calls `RawHID.recv()`
once more, and if ANY report arrived meanwhile - on any interface - it
OVERWRITES the FIDO packet with it and sets `useinterface` to that report's
interface, so FIDO answers then go out on that interface. With the OnlyKey
App open, the App sends vendor traffic in reply to other vendor traffic; a
CTAPHID INIT sent right after a derived decapsulation was replaced by the
App's packet and never answered, in all 7 runs. Sent first, or 5 s later, it
was answered every time. The console shows the swallowed report parsed as
CTAPHID (`Recv packet` ... `length`, then no `adding a new cid`).

Pre-existing (not a v3.0.5 change). On hardware it means: App open + a FIDO
client's very first request after unlock can be lost; browsers retry INIT, so
it is probably invisible there, but anything that sends one INIT and waits
would hang. `17` now opens its CTAPHID channel before its vendor traffic.

## Rig: the gadget's UDC file must be writable by the kit's user

After a VM restart the gadget's UDC file in configfs came back owned by root
with mode 0644, so the device host could not unbind the gadget and
`02-cli/04-pqc-no-device` failed at "takes the device off the bus". With the
file owned by the kit's user it passes 5/5. The setup script should set that
on every boot.
