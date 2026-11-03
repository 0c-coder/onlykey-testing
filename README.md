# onlykey-testing

A test kit for OnlyKey firmware that runs against the emulator first and
physical hardware second. The test files are written once; an adapter decides
which device they reach.

The design and its reasoning are in [EXPLAINER.md](EXPLAINER.md). This file is
how to use what was built. What is left to build is [TODO.md](TODO.md), in the
order to do it; [PLAN.md](PLAN.md) is why each of those items exists.

**[FINDINGS.md](FINDINGS.md) is every defect this kit has found, and whether
anybody has been told.** None of them reported yet - which the table says out
loud, because a repo full of careful findings and no reporting status reads
exactly like a repo whose findings were all filed. (No count here on purpose:
this line said "six" for about six hours, and FINDINGS.md itself dropped its
count for the same reason.)

## Quick start

```sh
sudo sysctl -w vm.mmap_min_addr=4096     # once per boot, see "The rung" below
node bin/okt.js caps                     # what this host can reach, and why not
node bin/okt.js list                     # what would run
node bin/okt.js run 01-protocol          # run the protocol section
node bin/okt.js run 01-protocol/07-unlock.test.js   # or one file
echo $?                                  # the verdict
```

### Running one test

`--test` selects by substring against `"<suite name> <test name>"`, which is how
a single endpoint or a single behaviour gets debugged without its neighbours:

```sh
node bin/okt.js run test/02-cli/10-cli-reads.test.js --test rng
```

That only works if the test needs nothing an earlier test in its file did, and
that is a property of how the file was written rather than of the runner.
A test name should contain the literal thing it covers - the CLI sweep names
every `it()` after its endpoint - so `--test getlabels` selects exactly one.
Where one name contains another, `--test` also accepts `/regex/flags`:
`--test '/\bversion\b/'` selects `version` without also selecting `fwversion`.

`--isolate` checks it: each selected test runs in its own device session, and
anything that cannot stand alone is named.

```sh
node bin/okt.js run test/02-cli/10-cli-reads.test.js --isolate
```

It costs a fixture restore and a boot per test, so it is for after adding tests
rather than for ordinary runs. **Files in section 2's CLI sweep are expected to
pass it** - each brings the device to the state it needs itself, through
`device.ensureUnlocked()`, which is the idempotent form of `unlock()`. Files
built around one long operation with several assertions about it - the lib-agent
pair, the composite PGP files - deliberately are not, and `--isolate` reporting
them says exactly that rather than that something is broken.

`unlock()` cannot be called twice and the reason is worth knowing: it works by
PRESSING the PIN digits, so on an already-unlocked device those are slot
presses, the device types whatever the slots hold, and the call waits for an
`UNLOCKED` that will not come again. `ensureUnlocked()` reads the status first.

Standing alone is not the same as being unaffected by what ran before. A test
whose claim is "the device refuses this because config mode is off" passes in
isolation and inverts when a predecessor turns config mode on - and config mode
has no exit but a reboot. So there are two order faults, and they need different
instruments:

| fault | fails when | caught by |
|---|---|---|
| DEPENDS on an earlier test | run alone | `--isolate` |
| BROKEN BY an earlier test | something runs before it | `--reverse` |
| asserts an ABSENCE having proved nothing | never - it passes | `--controls` |

The third is section 5's gate and is a different kind of fault: the other two
make a test fail somewhere, while a broken instrument makes it PASS. A file that
declares `negative: true` must call `assert.control()` in every test, and
`assert.absent()` refuses to pass until one has fired. See
[test/05-security/README.md](test/05-security/README.md) for the six absences
that were really this kit's own instrument.

`--reverse` runs a file's tests back to front in one ordinary session, so it
costs one run rather than a boot per test:

```sh
node bin/okt.js run test/02-cli/13-cli-lifecycle.test.js --reverse
```

The two orders are complementary rather than redundant. If A leaves state that
spoils B then the natural order already fails; if B leaves state that spoils A,
only the reverse does. Reverse rather than shuffle so that a failure reproduces
by rerunning the same command.

Neither is a substitute for the rule: **establish the state you are asserting
about**, rather than inheriting it. Both flags only tell you where that was not
done.

### Which surface a test reads

A production key ships without SEREMU - it is a debugging interface, and on a
security key it is a key-extraction path - so an assertion that reads the debug
console cannot run in a future production walk, while the keyboard, vendor
(`0xFFAB`) and FIDO (`0xF1D0`) surfaces can. [PRODUCTION.md](PRODUCTION.md) has
the argument.

Prefer a client-visible surface wherever it does not weaken the assertion, and
mark every test with the one it uses, in these words:

```js
/* SURFACE: vendor - survives into a production walk. */
/* SURFACE: console - does NOT survive a production walk, and is used here
 * because nothing a client can see reports which SLOT a write went to. */
```

More is reachable on the vendor surface than it first looks. The firmware
acknowledges each settings write by name, so `02-cli/11-cli-settings` asserts 13
endpoints with one console read between them. Genuinely console-only: counting
button challenges, counting flash sector erases, and reading back a derived
private key.

Nothing has to be installed to run the kit. Everything in `package.json` is an
**optional** dependency, and a file that needs one skips itself with a stated
reason rather than failing:

```sh
npm install                  # both groups
npm install --ignore-scripts # the pure-JS ones only, skipping node-hid's build
```

- `node-hid` - the hardware adapter. Nothing emulated needs it.
- `@noble/ciphers` - `hsalsa`, for NaCl's `crypto_box_beforenm` in
  `lib/device/transit.js`. Nothing else in the kit needs it and node:crypto has no
  equivalent. Probed by `transit.probe()`, so a file that needs the tunnel skips
  with a reason rather than failing to load.
- `@noble/post-quantum`, `@noble/hashes`, `@noble/curves` - the X-Wing maths in
  `lib/age-pqc.js`. ML-KEM-768 has no `node:crypto` equivalent, so this is the
  one piece of arithmetic in the kit that cannot come from the standard library.
  Reported as the `xwing-math` capability.

The kit is CommonJS on the same Node that built the emulator addon - the device
host loads that addon directly, and a mismatched ABI is not a failure worth
debugging twice.

It finds the emulator at `../../emulator` relative to its own root, with
`OKEMU_ROOT` overriding. If neither resolves it says which paths it tried.

### The firmware sources, and which copy compiles

Three source areas compose in a fixed order, and a file present in more than one
is taken from the LAST:

| | staged | holds |
|---|---|---|
| 1 | `arduino-1.6.5-r5-teensy_127/arduino-1.6.5-r5/…/cores/teensy3` | the stock Teensy 3 core |
| 2 | `OnlyKey-Firmware/*.c *.h` copied **over** it | OnlyKey's USB stack, shadowing core files |
| 3 | `libraries/` | the vendored Arduino libraries |

`emulator/scripts/stage.js` mirrors `in-docker-build.sh`, so this precedence is
the shipped build's too - it is not an emulator quirk. Nothing under `onlykey/`
is ever written to; the tree is assembled into `emulator/.stage`.

**The trap: `usb_desc.h` exists in BOTH area 1 and area 2, and only OnlyKey's
compiles.** The core copy is 356 lines, OnlyKey's is 469 and is the one carrying
the `NUM_INTERFACE` / `SEREMU_INTERFACE` blocks. Editing the core copy looks
applied - the file changes, the build succeeds - and does nothing at all. That
matters directly for the production descriptor work in
[PRODUCTION.md](PRODUCTION.md), whose whole subject is a commented-out block in
`OnlyKey-Firmware/usb_desc.h`.

The same shadowing applies to every `.c`/`.h` OnlyKey ships. Before editing a
firmware source, check whether area 2 has its own copy.

### `STD_VERSION`: there are two firmwares, and the kit only knows one

`STD_VERSION` is not a build flag - it is a `#define` in the sources, and
**undefining it produces a different product**: the International Travel
Edition, which exists because some countries do not permit encrypted devices.
That is a legal constraint rather than a security feature, and the constant it
selects says so in its own comment:

```c
#define NONENCRYPTEDPROFILE 2 //International Travel Edition or Plausible Deniability
```

`setup()` assigns it at boot (`OnlyKey.ino:259-263`):

```c
#ifdef STD_VERSION
  profilemode = STDPROFILE1;
#else
  profilemode = NONENCRYPTEDPROFILE;
#endif
```

So **plausible deniability is the travel build's property, not the second
profile's.** `01-protocol/20-second-profile` is about the STD build, where the
second profile's separation is by slot numbering - which is what it is
documented to be, not a boundary that failed.

**It is defined in TWO places, and that is the trap** - the same shape as
`usb_desc.h` above, and for the same reason: both are hand-edited variants the
build cannot tell apart.

| | file | line |
|---|---|---|
| 1 | `libraries/onlykey/onlykey.h` | 84 |
| 2 | `OnlyKey-Firmware/OnlyKey/OnlyKey.ino` | 82 |

Both carry the comment "Define for STD edition firmare, undefine for IN TRVL
edition firmware". Comment out one and not the other and you get a half-travel
build: the translation units that include `onlykey.h` take one side of every
guard and the sketch takes the other. Worth re-measuring rather than trusting
this count, since the sources move:

```sh
grep -rhcE '#(ifdef|ifndef) *STD_VERSION' libraries/onlykey libraries/fido2 \
  OnlyKey-Firmware --include=*.cpp --include=*.h --include=*.ino
```

Measured 2026-08-05: **76 guard directives - 72 `#ifdef`, 4 `#ifndef` - across 8
files**, 49 of them in `okcore.cpp` alone.

**Everything in this kit assumes `STD_VERSION`.** Both fixtures, every state
module and every test. The travel edition has never been compiled or run here,
so any behaviour reached only when `profilemode == NONENCRYPTEDPROFILE` is
untested by construction rather than by omission - see TODO.

## The verdict

The exit code says what kind of problem it is without reading anything else:

| code | meaning |
|---|---|
| 0 | finished, everything passed |
| 1 | finished, at least one test failed - the only code that means the device behaved and the software did not |
| 2 | the firmware crashed |
| 3 | a watchdog fired: per-test deadline, no-progress inactivity, or run maximum |
| 4 | harness or runner error - the kit failed before it could judge anything |
| 5 | the device host died for a reason that is not the firmware's fault |

0-3 are verdicts about the device. **4 and 5 say the run did not produce a
verdict at all**, and that distinction is the whole point.

## What a run leaves behind

Every run gets its own directory under `runs/`, so nothing has to be piped or
tailed and two runs can coexist:

```
runs/<stamp>-<pid>/
  run.log             everything, timestamped
  status.json         rewritten live: section, file, test, elapsed, failures
  markers/            restart markers, one per generation
  files/<file>/       per-file device host: its storage, its markers
```

**`run.log` carries the device console ONLY inside a failure block.** A passing
run logs the runner's own lines and nothing the device said, so grepping it for
firmware output after a green test finds nothing - which reads exactly like "the
device never received anything" and is not. Read `device.log` from inside a test
instead (`device.log.count(re)`, `.tail(n)`). This produced a false negative that
nearly closed a real finding as read-wrong.

Poll `status.json` for progress. Read `run.log` afterwards. And every run ends
with exactly one sentinel line, emitted from the exit handler, the uncaught
exception handler and the unhandled rejection handler alike:

```
--- OKT-END status=finished code=0 tests=46p/0f/3s elapsed=99s reason="all tests passed" ---
```

**The absence of a sentinel means a hard crash.** That single fact, answerable
by one `grep OKT-END`, is what the old kit could never provide.

A failure block is self-contained - the pending wait, the recent device output,
the boot generation, and the device host's stderr if it died - so there is
nothing to go hunting for.

## The rung

One host setting decides how much of the device is reachable, and a run says
which one it got before it runs anything.

| `vm.mmap_min_addr` | what works |
|---|---|
| `0x0000` | everything, including `fw_hash()`. Needs `CAP_SYS_RAWIO`. Nobody should run this. |
| `0x1000` | **use this.** `certified_hw` (`0x5BB0`) is mapped so crypto works, and page zero stays unmapped so a genuine NULL dereference still faults. |
| `0x10000` | the unprivileged default. The device boots and answers HID, then segfaults the moment it encrypts anything - storing a PIN included. |

That last rung is the dangerous one: it looks like it is working right up until
the first test that stores a PIN. The runner reads the rung back and treats it
as a capability, so a run that lands there **skips the crypto files with a
stated reason** instead of reporting a pile of crashes.

## Section 4's App tier: how to drive the OnlyKey App

Everything here was learned by driving `OnlyKey-App` against the emulated
device, and none of it is guessable from its source. **It is a different
codebase from section 3** - that one is `apps.onlykey.io` (the web app) in a browser over
the WebAuthn tunnel; this is a packaged nw.js app reaching the device with
`chrome.hid`. `lib/app.js` is its session, `lib/gui.js` is section 3's, and they
share only the process plumbing.

### It is an application, not a URL

nw.js is handed the **build directory** and the app opens its own window, so
`AppSession.attach('app')` attaches to a window that already exists.
`Target.createTarget` - what `GuiSession.open()` does - would open a second,
empty window beside the real one and drive that.

**`build/` is gitignored**, so it is never in a fresh checkout and `gulp build`
is a prerequisite rather than a convenience. It is cheap (~1.8s; a file copy plus
sourcemaps, no bundler) so `10-session` rebuilds every run instead of guessing
whether an existing build is stale. `clean` runs first, so nothing may be edited
under `build/` and expected to survive. Getting gulp needs
`npm install --ignore-scripts` in the App checkout - **the flag is deliberate**,
since `nw` is a runtime dependency there and a plain install pulls a ~150MB
runtime the kit does not use.

### `page.close()` must NOT close the window - the opposite of section 3

There, a leaked tab holds an outstanding WebAuthn request and breaks the next
page's handshake. Here **the window IS the application**, and closing it ends the
session every later file depends on. So `attach()` deliberately does not give the
page a `targetId`, `close()` drops only the connection, and `19-stop` takes the
process group down.

### The App must re-find the device after every restart

Each test FILE gets its own device host, so between files - and after any
`device.restart()` - the device is unplugged and replugged as far as the App is
concerned. It recovers on `onDeviceAdded`, but not instantly, and a fixed wait
passes most runs and not all. Use **`session.waitForDevice(page, device, …)`**,
which polls the DEVICE between checks - `status()` is real traffic, so it proves
the device is alive *and* feeds the watchdog (see below). Two files were flaky on
exactly this before it lived in the session.

### Keep every page wait under the 30s inactivity budget

A page wait produces **no device output**, so a 60s one does not fail its own
test - it spends the run's no-progress budget and aborts the whole run with a
watchdog pointing at the device. Section 2 caps its CLI commands at 12s for the
same reason. Either keep waits under ~20s, or interleave real device calls.

### Controls are DUPLICATED, and only one of each is real

`slot1aConfig` appears **three times** in `app.html` and `restoreSelectFile`
**twice**. Neither "the first" nor "the one with `data-slot-id`" is a safe rule -
preferring the data attribute picked an element in a hidden panel and waited a
minute for a control that was never going to be laid out. **Click whichever
candidate is actually VISIBLE** (`getBoundingClientRect().width > 0`); a
zero-width control is not one a user could press. For file inputs, set the files
on **every** match and then read the counts back from the page - CDP's
`DOM.setFileInputFiles` reports success even when the element it was given is not
the one the App reads.

### A dialog's `open` ATTRIBUTE is the empty string

`showModal()` sets `open=""`, so `!!el.getAttribute('open')` is **false for a
dialog that is wide open**. Use the `open` **property**. The App's own selenium
test compares `getAttribute('open')` to `'true'` and is right only because
WebDriver normalises boolean attributes - a rule ported out of a selenium suite
is not automatically true outside it. This cost three debugging iterations.

### Slot buttons are clickable ~1.2s before anything is bound to them

`initSlotConfigForm()` does the `addEventListener`, and the only thing that calls
it during startup is **`handleGetLabels()`** - so the binding waits for the first
`OKGETLABELS` reply while the panel is revealed from the unlocked state. A click
in that window is silently discarded. It is a real defect
([FINDING-app-slot-button-dead-window.md](FINDING-app-slot-button-dead-window.md)),
and for a test the answer is to **click, check, click again**, exactly like
section 1's mid-fade press retry. Log the click count so a change in the size of
that window reads as a number rather than as a flake.

### Form fields are gated by their own checkboxes

`Wizard.setSlot()` walks a `fieldMap` whose KEYS are checkbox ids -
`chkSlotLabel`, `chkPassword` - and each field is written only `if (isChecked)`.
Filling a text input alone submits a form that agrees to send nothing, which is
indistinguishable from a device that ignored the write unless you know to look.

### The Firmware tab is off limits

It reaches `OKFWUPDATE`, which on a physical key **locks the bootloader and
permanently converts a developer key into a production key**. No file in section
4 opens that tab. If one ever does, it carries `requires: ['emulated']` and is
driven only to its interlocks.

## Seeing what a page is actually showing (authoring only)

When a browser-tier or app-tier test does not land where you expected, you can
look. **This is an authoring technique, not a kit feature - no committed test
may depend on it**, and captures are throwaway like probe files.

```sh
# the whole window, including native chrome, title bar and dialogs
python3 -c "from PIL import ImageGrab; ImageGrab.grab(xdisplay=':100').save('shot.png')"
```

Pillow speaks X11 directly, so nothing else needs installing. For page content
only, CDP's `Page.captureScreenshot` returns base64 in `result.data` - write
`Buffer.from(data, 'base64')` to a file, and pass `captureBeyondViewport: true`
for a tall page, which otherwise renders cropped.

Reach for it when an element is in the DOM but you are not sure it is VISIBLE,
or when a flow does not go where the code says it should. It settled two
questions in one run while `04-app/11` was being written: that the App had
reached its Slots tab with twelve empty slots rather than being stuck, and that
a control which existed at 0x0 was the wrong twin of a duplicated id.

## Writing a test file

One suite per file, flat, with metadata:

```js
const { describe, it } = require('../../lib/harness');

describe('unlock', { state: 'initialized', requires: ['crypto'] }, () => {
  it('unlocks with the primary PIN', async ({ device, assert, signal, skip, log }) => {
    const model = await device.unlock('1111111', { signal });
    assert.match(model, /^UNLOCKED/);
  });
});
```

Metadata:

- `state` - the device state this file needs (`blank`, `initialized`). The
  runner restores it before the file runs.
- `requires` - capability names. An unmet one skips the file **with the reason**
  rather than failing it.
- `timeoutMs` - per-test deadline for this file.

Every test receives one argument: `device`, `assert`, a `signal` that every wait
honours, `skip(reason)`, and `log`. There are no `before`/`after` hooks and there
will not be - a hook is an invisible step, and an invisible step is what makes a
wedge unattributable.

Pass `signal` to every device call. That is what makes a timeout actually cancel
the test instead of leaving it running while the runner moves on.

## The device API

```js
device.log                        the debug console as one accumulator
  .waitFor(re, {timeoutMs, signal})      matches retroactively
  .waitForCount(re, n, opts)             the firmware acks per BYTE
  .waitForAny({ok: re, err: re}, opts)   first to match, and which
  .count(re) / .clear() / .tail(n)       clearing is the CALLER's job

device.press(n, {hold})           hold: tap | hold | long | longest
device.pressLine([1,2,3])         one write - the firmware paces the replay
device.sendDebugLine('8')

device.send(iface, buf)           no report ID, no padding - adapters normalise
device.sendVendor({msg, slot, field, payload})
device.mark(iface) / device.waitHid(iface, {match, since, timeoutMs, signal})
device.keystrokes / device.waitKeystrokes(text, opts)

device.waitReady()                booted AND reading its input
device.waitResponsive()           just the second half
device.restart() / device.wipe({full})
device.waitForReboot({from})      for commands that reboot as their completion
device.status()                   {state: uninitialized|locked|unlocked, raw}
device.unlock(pin)
device.enterConfigMode(pin)       long-press 6, relock, unlock again
device.setTime()                  RAM-only, rebased every boot
device.generation / device.restarts / device.storageDir
```

### Driving a vendor command over the WebAuthn tunnel

`lib/device/tunnel.js` frames one and reads the answer out of an assertion, which
is enough for OKCONNECT and nothing else: `bridge_to_onlykey()` decrypts the whole
payload before it looks at the command, so an unencrypted request is dispatched as
noise. `lib/device/transit.js` is the other half.

```js
const transit = require('../../lib/device/transit');
if (!transit.probe().ok) skip(transit.probe().why);   // @noble/ciphers is optional

const ours = transit.keypair();
const reply = await tunnel.send(ctap, {
  cmd: okmsg.MSG.OKCONNECT, data: transit.connectPayload(ours.publicKey),
});
const key = transit.transitKey(reply.data.subarray(0, 32), ours.privateKey);
// then seal every request payload, and OPEN every response, with transit.box(key, …)
```

Five things about it that cost time to establish and are load-bearing:

- **`transit_key = SHA256(HSalsa20(X25519(sk, pk), 16 zero bytes))`** - NaCl's
  `crypto_box_beforenm`, not the raw X25519 point. That is the one piece
  node:crypto cannot do, hence `@noble/ciphers`' `hsalsa`. `transit.selfTest()`
  checks it against NaCl's published alice/bob vector; call it before trusting a
  device answer, because a wrong key produces 32 plausible bytes and a device that
  replies noise.
- **The box is plain AES-256-GCM keystream with a TWELVE-BYTE ZERO IV, tag
  discarded**, so it is length-preserving and its own inverse. Every message
  reuses one keystream; that is the firmware's design, and mirroring it is the
  only way to talk to it.
- **`okcrypto_split_sundae()` does NOT apply to transit**, though
  `okcrypto_aes_gcm_encrypt2()` looks like it does under `FACTORYKEYS` (which is
  defined). The function opens `if ((*certified_hw != 1 && *certified_hw != 3) ||
  s == false) return;` and the box passes `s = false` both ways.
- **The OKCONNECT payload is 43 bytes, not 32**: `set_time()` reads a big-endian
  epoch at `[5..8]`, the client public key sits at `[9..40]`, then a browser byte
  and an OS byte. Confirmed by the derive path reading `client_handle + 43`.
  `12-webauthn-tunnel` sends 32 bytes and therefore has the device read its pubkey
  partly out of bounds - harmless for that file's assertions, and the reason
  nothing had ever derived a transit key before `23-rsa-tunnel`.
- **Responses are SEALED on this transport and plaintext on the vendor one.**
  `okcrypto_rsasign()` passes `encrypt=1` for WEBAUTHN and `0` otherwise, so a
  tunnelled answer must be opened. Measured the hard way: a signature arrived with
  the right length and the right chunk count and would not verify.

Requests go in **228-byte** chunks (`u2fSignBuffer`'s `57 * 4`) with `opt1` = the
slot, `opt2` = the final-packet flag and `opt3` a STRICTLY INCREASING packet
number - `last_request_opt3` drops anything not greater than the last. Polling for
a chunked response is `cmd: 0xF3` (OKPING) with a further advancing `opt3`.

**And the origin check is not testable here.** `webcryptcheck()` opens with
`return 2; // Trust all origins for debug firmware` inside `#ifdef DEBUG`, before
any comparison - so on the emulator every rpId is trusted and no tunnel test
proves otherwise. That belongs to a production walk.

```

## Section 3's browser tier: the session, and how to drive a page

Everything here was learned by driving `/app/encrypt` and `/app/decrypt`, and
none of it is guessable from the web app's source.

### The session is started and stopped by visible test FILES

`10-session` starts the express server and nw.js; `19-stop` stops both and
asserts the ports came free. Nothing between them starts anything. The handle
lives in `lib/gui-session-holder.js`, which survives from file to file in the
MODULE CACHE - the runner clears the harness registry between files, so a
module-level variable in a test file would not.

**So a browser-tier file cannot be run on its own.** Run the section:

```sh
node bin/okt.js run 03-gui
```

or, to iterate on one file without paying for the whole section, name the
session files around it - one run, one session, three targets:

```sh
node bin/okt.js run test/03-gui/10-session.test.js \
                   test/03-gui/14-gui-encrypt-decrypt.test.js \
                   test/03-gui/19-stop.test.js
```

Running one browser file alone gets a clear error ("no GUI session is running")
rather than a hang. Running `--isolate` over one would start a browser and a
server with nothing to stop them, so **the browser-tier files are outside both
order gates by design** - `10-session`, `11`, `12`, `14`, `19-stop`. They are not
isolation debt and should not be added to it.

### `page.close()` closes the WINDOW - and it did not always

It used to close the debugger socket and leave the tab running. Nothing noticed
for weeks because no file had ever opened a SECOND page in one session, and
`11-password-generator`'s "closes its window" test asserts the opposite in its
own comment.

**It does not present as a leak. It breaks the next page.** Chromium allows one
WebAuthn request at a time **per browser**, not per tab, so an abandoned tab whose
startup OKCONNECT is still in flight makes the next page's handshake fail inside
Chromium with `OperationError: A request is already pending.` The page swallows
that, its output box never fills, and what the test sees is a device that was
never contacted - reported, eventually, by the inactivity watchdog pointing at the
device rather than at the browser. The only account of the real cause is the
page's own console, which is why `page.console` is kept and why a failure message
should print its tail.

So, for any file that opens more than one page:

- **wait for each page's handshake before doing anything with it.** Every app
  page starts an OKCONNECT as it LOADS; `#header_messages` gets "Secure
  Connection Established" with the firmware version when it lands. Waiting for
  that is both the fix and an assertion worth having.
- **close each page before opening the next**, in a `finally`.
- and note what this means for claims: in a browser, "this mode needs no device"
  is true of the OPERATION and false of the PAGE. Assert on what the device was
  asked to DO - a primed confirmation count - not on device silence.

### Driving the encrypt and decrypt pages specifically

Four mechanics, each of which cost time to find:

| | |
|---|---|
| `window.$` does not exist | `app.js` sets only `window.jQuery`; the plugin system passes `$` around as a dependency. Reaching for `$` is a TypeError that arrives as an unhelpful "page threw" |
| the recipients field is not an `<input>` | `jquery.tokenizer.js` replaces `#pgpkeyurl` with a contenteditable span, hides the real one, and writes `escape(value)` into it. Drive it with `jQuery("#pgpkeyurl").data("tokenizer").add(key)`, which is the call the widget itself makes on blur |
| ...and that escaping is load-bearing | it is why `startEncryption` has a `slice(0,11) == '-----BEGIN%'` branch. It is also the only way an armored key fits a field that strips newlines from `.value` |
| the mode comes from the radio, via `setup()` | each `#action` radio re-runs `page.setup()` on `change`, which re-reads `_$mode()`. Set `.checked` AND dispatch `change`. There is no other way in: `page.okpgp` lives in the plugin's closure and is not published on `window` the way `pgp-pqc`'s `__pgpPqcTestHooks` is |

And both pages write their result back into the **same** `#message` textarea the
input came from, so "it worked" is "the box CHANGED", not "the box is non-empty".

The two constraints that are not optional for any page in this app:

- **Serve from `localhost`, never `127.0.0.1`.** WebAuthn refuses an IP as an
  rpId, the pages swallow the error, and the only symptom is an output box that
  never fills. The RPID is also folded into DERIVED keys, so a cross-check must
  ask the kit for the same rpId the browser will use. (Stored-key operations -
  the RSA slots - are unaffected by which rpId is used.)
- **Device up and unlocked before any page opens.** A page whose startup
  OKCONNECT times out makes Chromium raise a NATIVE WebAuthn dialog that no CDP
  command can dismiss, and the session is wedged until restarted.

## Things the firmware does that will surprise you

All measured, all load-bearing, all commented at the point that depends on them:

- **A booted device is not a listening device.** The firmware drops debug-console
  input while it is busy - it has no queue for it - and it is busy for a while
  after boot and after unlock, both of which run LED fades. `waitReady()` and
  `unlock()` probe for responsiveness; `restart()` and `wipe()` resend up to
  three times, the same number the old kit used.
- **A press that lands mid-fade is discarded.** `payload()` reads the slot, prints
  "Additional Character", then `if (isfade) return;`.
- **A locked device does not read the vendor interface at all.** `recvmsg()` is
  only reached from `if (unlocked)`. The "Error device locked" branch in the
  source is unreachable on Classic/Color hardware - it is the DUO's. Status while
  locked comes from the once-a-second `INITIALIZED` broadcast.
- **A seven-digit PIN produces six digit acknowledgements.** The seventh digit
  completes the guess and takes the branch that evaluates it instead.
- **A rejected PIN does not clear the guess buffer** until ten keys have been
  entered, so the next attempt continues the old one. Reboot between attempts.
- **CTAPHID PING is answered on any channel id**, allocated or not.
- **A backup cannot be taken in config mode.** The backup branch requires
  `!isfade`, and config mode holds the LED animation forever. Configure the
  backup key in config mode, leave it, *then* hold button 1.
- **A restore reboots as its completion**, and probing across that reboot reads
  a stale ready flag - `locked` on the emulator where it is instant,
  `unreachable` on a key where re-enumeration takes real time. Same race, two
  faces. Use `waitForReboot()`.
- **`flash.bin` is not a flat byte image - every aligned 4-byte word is
  byte-reversed.** `okcore_flashset_common()` (okcore.cpp:3233) packs four bytes
  into one longword BIG-endian - `ptr[z]` becomes the most significant byte - and
  writes it with `flashProgramWord()`. On a little-endian core that lands `ptr[z]`
  at the highest address of the word. `okcore_flashget_common()` mirrors the
  unpack, so the device is perfectly self-consistent and **only an out-of-band
  reader sees it** - which means any test that searches `flash.bin` for a byte
  sequence must un-reverse each word first, or it finds nothing and reads that as
  an absence. It is firmware behaviour, not an emulator artifact, so a dump of a
  real key's flash needs the same treatment. `01-protocol/22-rsa-slot-tail` has
  the helper and a label-based control that proves the instrument before trusting
  any absence; measured by writing `oktprobe00961683` and finding it
  word-reversed at `0x3c820`.
- **An RSA slot holds P‖Q, and E is hardcoded to 65537.** There is no private
  exponent on the device: `rsa_getpub()` multiplies the halves for N and
  `rsa_sign()`/`rsa_decrypt()` recompute D, DP, DQ and QP every time. A key with
  any other public exponent stores happily and then signs with a D it does not
  have. Its "type" is the modulus size in 128-byte units, sharing one byte with
  the feature flags - low nibble size, bit 5 decrypt, bit 6 sign.
- **`buffer[6]` means two different things in two chunked sends.** Loading a KEY
  (`OKSETPRIV` -> `rsa_priv_flash()`) puts the TYPE BYTE there on every report and
  the firmware copies a fixed 57 bytes from each, counting its own way to the key
  size with a global offset. An operation PAYLOAD (`OKSIGN`/`OKDECRYPT` ->
  `process_packets()`) puts the CONTINUATION MARKER there - `0xFF` while more
  follows, the last chunk's own length at the end. Swap them and you get a
  255-byte packet, or "Error invalid RSA type".
- **A wiped RSA slot still reports a key.** `rsa_priv_flash()` returns from its
  `wipe` branch before writing the key type, so the type survives in EEPROM, and
  `OKGETPUBKEY` goes on publishing a modulus computed from 256 decrypted zero
  bytes. The ECC path writes its type byte on the way in, so an ECC wipe really
  does empty the slot. Pinned by `19-rsa-keys`, which will fail when it is fixed.
- **The LOCK keypress types Super+L at the host** before rebooting
  (`lock_ok_and_screen`), so on a workstation it locks your screen. It is not a
  cheaper relock than a reboot - it *ends* in `CPU_RESTART()`.

## Device state

States are defined once in `lib/fixtures/states/` with a `check()` and an
`apply()`. On the emulator, `apply()` runs once in a builder and the resulting
`flash.bin`/`eeprom.bin` are cached under `~/.cache/onlykey-testing/fixtures/`,
keyed by a fingerprint over the built firmware and the state module. Each file
then boots from a fresh copy - which is what removes the cross-contamination
that forced the old kit to be run one file at a time by hand. On hardware the
same module checks the device and runs the real setup flow, because a physical
key cannot have an image pushed into it.

```sh
node bin/okt.js fixture initialized     # build or rebuild, before a run
```

## An OnlyKey DUO

The same firmware runs on a DUO, which it detects at boot, and the kit drives
it differently (`lib/model.js`): buttons 1–3, PIN digits 4–6 as holds of 1–3,
config mode from button 1 held past 180 rounds, challenge codes mod 3, and its
PINs set the App's way (one `OKSETPIN` carrying the digits) by the
`initialized` fixture, whose cache is per model.

```sh
OKEMU_HARDWARE=duo node bin/okt.js run 01-protocol/44-duo.test.js   # an emulated DUO
OKT_MODEL=duo node bin/okt.js run --hardware 01-protocol/44-duo.test.js   # a hard DUO
```

`OKEMU_HARDWARE=duo` needs a node-onlykey-emulator with the `hardware` board
option; the firmware's own detection then decides, as on a real board. An
emulator built with `OKEMU_MODEL=duo` is also read as a DUO. Files that only
make sense on one model require the `duo` or `classic` capability; a press of
4–6 on a DUO is refused with an error, because no finger can make one.

## Flashing a key

```sh
node bin/okt.js flash                   # the sibling builder's OnlyKey.cpp.hex
node bin/okt.js flash path/to.hex       # or an explicit image
```

Tap the button on the key first, so it enumerates as the HalfKay bootloader
(`16C0:0478`). The image goes out as 1089-byte reports written straight to
`/dev/hidrawN` - no node-hid, no python.

It **paces the writes**, which is the one thing it does differently from
`onlykey-usb-hid-passthrough/tools/halfkay_flash.py`, and the reason it is here
rather than borrowed. HalfKay programs a block after acknowledging the
transfer and NAKs anything arriving while it is busy; the kernel reports that
as `EPIPE`. Flashing *through* the Feather proxy never hits it, because the
proxy holds each report for up to `PROXY_OUT_BLOCK_MS` waiting for a slot - it
is the back-pressure. Attached directly there is none, and the original tool
dies a few blocks in:

```
FAILED writing block at 0x001000 (block 4): [Errno 32] Broken pipe
```

15ms between blocks fixes it and costs three seconds on a 210-block image.

Four limits of snapshot restore, none of them bugs:

- A snapshot **always boots locked**. The flags and PIN hashes are RAM, rebuilt
  in `setup()`; snapshots skip provisioning, not unlocking.
- **No attestation.** FSEC is written fresh every boot from an anonymous mapping,
  so it latches to already-provisioned and the one-time provisioning branch never
  runs: no factory key derivation, no firmware hash in EEPROM, no lock bits.
- **Time is RAM-only** and rebased every boot.
- A rebuild of the firmware invalidates the cache automatically.

## Sections

```
test/00-sanity/     built    no device at all - the kit's own oracles
test/01-protocol/   built    Node over the wire protocols
test/02-cli/        built    the CLI through the Python venv
test/03-gui/        built    the WEB app (apps.onlykey.io): 00-09 headless, 10+ in nw.js
test/04-app/        built    the OnlyKey APP (OnlyKey-App), a packaged nw.js app
```

**Sections 3 and 4 are different codebases, and both get called "the app".**
Section 3 is `apps.onlykey.io` (web app 4.0.0 on node-onlykey-lib), served by express and opened in the kit's own
nw.js, reaching the device over the WebAuthn tunnel. Section 4 is
`OnlyKey-App`, a packaged Chrome-App-style nw.js application that reaches the
device with `chrome.hid`. `lib/gui.js` drives the first and `lib/app.js` the
second; they share only the process plumbing. See TODO's §5 and "Section 4's App
tier" above.

**Every section is now built, and this block has twice said otherwise** - it
claimed sections 2 and 3 were stubs until 2026-08-05 and section 4 until
2026-08-06, each time because it was written when that section was empty and
nothing updated it as it filled. That is the failure PLAN's dated counts table
exists to prevent, and the reason to distrust any count in this file that does
not carry a date. PLAN has the numbers and when each was measured.

The sanity section runs first and declares `device: false`, so the runner never
starts a device host for it: it checks the kit's own pure-JS oracles - CBOR, the
keystroke decoder, the vendor and CTAPHID framing, the backup format, the X-Wing
maths - against known answers, in under a second. If those disagree with their
answers, nothing the device sections go on to say can be trusted.

The admission test for section 1 is not "is this protocol-level" but **"does
this reach the device without a kernel device node"**. Sections 2-4 are not
merely deferred on a hosted runner - they are permanently impossible there.
There is no `/dev/hidraw`, so python-onlykey, lib-agent and node-hid have
nothing to open, and no display, so nothing that needs a browser runs. Those
files skip themselves with the reason named, every run - section 3's headless
tier is the exception and runs there, because it reaches the device over the
in-process bus like section 1.

## Not built yet

- ~~**The hardware adapter** is a declared seam with a stub behind it.~~ **IT IS
  BUILT AND IT DRIVES A KEY** - this bullet was stale until 2026-08-06, and had
  been contradicted by PLAN's own hardware column for two days. `okt run
  00-sanity 01-protocol --hardware` is **147 passed, 0 failed, 19
  skipped-with-reason in 837s** against a physical key.

  What the run exercises, so the claim is bounded rather than a boast: selection
  by sysfs (a real key chosen over the gadget by its `dummy_hcd` ancestry),
  all four interfaces opened, the report-ID prepend, SEREMU NUL-stripping,
  keyboard capture, and reboot-as-re-enumeration across **~30 restarts** - the
  fixture relock, `03-wipe`, `04-provisioning`, config-mode entry and exit, and
  the restore that reboots as its completion.

  What it does NOT exercise, by construction: `setPlugged()` throws (a key needs
  a hand on the cable), and anything gated `storage-files`, `image-snapshots`,
  `device-host`, `full-wipe`, `fido-reset` or `client-access` skips - which is
  every one of the 19.

  **One caveat worth knowing before trusting a hardware number.** A
  re-enumerating key races udev, so a reopen can hit `EACCES` on a node that
  exists but has no rules applied yet - 34 to 42 times in an 840-second sweep.
  That is now handled (a pre-flight `fs.access` and an all-or-nothing open), but
  until 2026-08-06 it leaked handles and doubled the SEREMU stream, which
  corrupted the console oracle intermittently and presented as flaky firmware.
  Any hardware result recorded before that date was measured through it.
- **Section 3's `/app/pgp-pqc` page**, and only that one. This bullet named
  `/app/encrypt` and `/app/decrypt` as well until 2026-08-06; both are driven in
  nw.js by `03-gui/14-gui-encrypt-decrypt`. Everything under pgp-pqc is proven
  headless, so a failure there means the page.
- **Section 4's tabs are done bar the excluded one.** Slots, Keys,
  Backup, **Setup, Preferences and Advanced** are driven as of 2026-08-06 - 28
  tests, the whole tab set bar Firmware.
  **Tools is not, by decision**: it is a launcher, eight external anchors that
  `nw.Shell.openExternal` hands to the user's real browser, with no input,
  select or form on the panel. A link that opens an external page has no
  behaviour to assert, so the file that pinned its hrefs was removed rather than
  maintained. The one thing worth keeping from it is written up in
  [FINDING-app-tools-origin.md](FINDING-app-tools-origin.md). The **restore** half of Backup is measured but unsettled (see TODO's
  premises table). The **Firmware** tab is deliberately excluded - it reaches
  `OKFWUPDATE` - and Preferences' full-wipe button is excluded for the same
  class of reason, with its presence asserted so its absence would be noticed.
- **The GitHub Actions workflow is written and PARKED**, not missing: it exists,
  it is `workflow_dispatch` only, and it has never run on GitHub. Do not dispatch
  it and do not add triggers - see TODO for why hosted CI is being re-envisioned
  around a self-hosted runner. On a hosted runner it comes down to
  `sudo sysctl -w vm.mmap_min_addr=4096`, three source checkouts, building the
  addon, asserting the rung, and running section 1.
### Challenge modes, and how to use a stored key without three presses

A crypto operation on a stored or derived key normally demands a three-digit
challenge: `done_process_packets()` hashes the packet and picks
`Challenge_button1/2/3` from it, and the operation waits for all three.

Setting `stored_key_challenge_mode` (slot field 22) or
`derived_key_challenge_mode` (field 21) to **1** replaces that with a single
press of **any** button. `done_process_packets()` sets `CRYPTO_AUTH = 3` instead
of computing digits, and the press handler in `OnlyKey.ino` has a clause -
`(stored_key_challenge_mode==1 && isfade && packet_buffer_details[0])` - that
goes straight to `CRYPTO_AUTH = 4` without checking which button arrived.

**Send it as the byte `1`, not the character `'1'`.** That clause tests `== 1`
exactly. The string puts `0x31` in EEPROM, which is truthy enough for
`done_process_packets()` to take the no-digits branch - so the device primes and
appears to be waiting for one press - and then no press satisfies the clause and
the operation answers `Error incorrect challenge`.

`01-protocol/14-stored-keys.test.js` uses this to drive `OKGETPUBKEY`, `OKSIGN`
and `OKDECRYPT` against all six ECC key types, so **crypto vectors against stored
keys are built**; the derived paths are covered by `02-cli/07-derived-xwing` and
`02-cli/15-age-file-interop`.

**Slots 1-4 are RSA and the same single-press mode covers them**, which is not
obvious from either field name: `done_process_packets()` loads
`stored_key_challenge_mode` when the slot is `< 5` OR 101..116, and `< 5` *is*
the RSA range. `01-protocol/19-rsa-keys.test.js` relies on it.
