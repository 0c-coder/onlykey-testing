/*
 * The `onlykey-cli` endpoint sweep, part five: the CLI's other half.
 *
 * Six endpoints that are not python-onlykey at all. cli.py hands `credential`,
 * `set-pin`, `change-pin`, `reset`, `wink`, `ping` and `rng` straight to
 * `solo.cli.key()` - the Solo FIDO2 CLI - which finds the device through
 * python-fido2 and speaks CTAPHID. So they reach the device over the FIDO
 * interface rather than the vendor one, and they fail in a different language
 * when they fail. `ping` and `rng` are already covered in 10-cli-reads because
 * they are reads; the four that change something are here.
 *
 * `set-pin` AND `change-pin` ARE THE FIDO2 CLIENT PIN, not the device PIN. A
 * reader who assumes otherwise would expect them to change what unlocks the
 * OnlyKey, and they do not - the device PIN is set by `init` over the vendor
 * interface, in 13-cli-lifecycle.
 *
 * THREE OF THE SIX ARE CURRENTLY BROKEN BY A HOST DEPENDENCY, and that is the
 * headline. `credential`, `set-pin` and `change-pin` all die inside solo with
 *
 *     AttributeError: 'Fido2Client' object has no attribute 'client_pin'
 *
 * which is solo calling an API the installed python-fido2 no longer exposes.
 * Nothing about the firmware is involved: the device answers, the client cannot
 * use the answer. Two of them then EXIT 0 while printing that error, so a
 * caller checking the exit code is told a PIN was set when none was.
 *
 * That makes the assertions here deliberately narrow. What is stable is that
 * each command REACHES THE DEVICE over FIDO, and that is what is asserted;
 * where the outcome is deterministic the wording is pinned too. When the venv's
 * fido2 and solo are brought back into step these will start failing, which is
 * the correct behaviour for a test whose subject is a known breakage.
 *
 * SURFACES, marked per test - see PRODUCTION.md. The FIDO interface survives
 * into a production walk, so counting reports on it is a production-safe way to
 * say "this command reached the device" without reading a debug line.
 *
 * NOTHING HERE FLASHES FIRMWARE AND NOTHING HERE RESETS THE AUTHENTICATOR. Both
 * commands are driven only as far as their confirmation prompts, which is the
 * part worth testing anyway: an interlock that can be bypassed is the bug, and
 * an interlock that holds is proven by the device staying silent behind it.
 *
 * `loadfirmware` IS `OKFWUPDATE`, AND ON A PHYSICAL KEY IT NEEDS THE SPECIAL
 * BOOTLOADER. RUNNING IT LOCKS THE BOOTLOADER AND PERMANENTLY CONVERTS A
 * DEVELOPER KEY INTO A PRODUCTION KEY. That is not "needs a reflash" - the key
 * is gone as a dev key, and nothing brings it back.
 *
 * So this file carries `emulated` in its metadata. That is a MECHANICAL gate,
 * not a note: the hardware adapter cannot run the file at all, and says why it
 * skipped. `client-access` already implies the gadget in practice, but "in
 * practice" is the wrong strength of guarantee for this one.
 *
 * WHAT EMULATION CANNOT COVER, stated so that the gap is by design rather than
 * by omission: FSEC lives in an anonymous mapping rebuilt on every boot, so the
 * emulator has no lock bits and the bootloader-lock path is not reachable there
 * at all. What IS testable is the framing, the interlocks and the refusals, and
 * that is what this file tests. THE DESTRUCTIVE BEHAVIOUR IS UNTESTED, and it
 * should stay that way.
 */
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');

const { describe, it } = require('../../lib/harness');
const { IFACE, okmsg } = require('../../lib/device');
const { PINS } = require('../../lib/config');
const cli = require('../../lib/cli');

/*
 * Under the 30s inactivity budget, and that is load-bearing rather than tidy.
 * Several of these prompt, and a command blocked on stdin produces no device
 * output at all - so its own timeout must fire before the run's inactivity
 * watchdog does, or a hung CLI aborts the whole run with a watchdog message
 * instead of failing the test that caused it. Found the hard way: the first
 * probe of `credential` used a 45s timeout and killed the run at 31s.
 */
const CMD_TIMEOUT = 12000;

/* Fed to every command so that nothing can block on a prompt this file did not
 * anticipate. An unexpected prompt then shows up as a wrong answer rather than
 * as a hang. */
const NO_TO_EVERYTHING = '\n'.repeat(6);

const SOLO_PIN_BREAKAGE = /'Fido2Client' object has no attribute 'client_pin'/;

describe('onlykey-cli, the FIDO endpoints', {
  state: 'initialized',
  /* `emulated` is the loadfirmware gate - see the header. */
  requires: ['emulated', 'crypto', 'client-access'],
  timeoutMs: 300000,
}, () => {
  const needCli = ({ skip }) => {
    if (!cli.venvPresent()) skip(`no venv at ${cli.VENV_BIN}`);
    cli.binary('onlykey-cli');
  };

  /*
   * Windows keeps FIDO HID collections (usage page 0xF1D0) for its own
   * WebAuthn service: an unelevated process's hidapi does not even list them.
   * Measured 2026-09-29 over okvhid: the keyboard, vendor and console
   * collections enumerate, the FIDO one does not, and solo then reports "no
   * Device found". That is the platform's rule, not the CLI's or the device's,
   * so it is a skip that says so. Probed rather than assumed: an elevated run
   * lists the collection and the test runs.
   */
  const needFidoHid = async ({ skip, signal }) => {
    if (process.platform !== 'win32') return;
    const probe = await cli.run('python3', ['-c', [
      'import hid',
      'print(any(d["usage_page"] == 0xf1d0 for d in hid.enumerate(0x1d50, 0x60fc)))',
    ].join('\n')], { timeoutMs: 20000, signal });
    if (probe.stdout.trim() !== 'True') {
      skip('Windows hides FIDO HID collections from unelevated processes ' +
        '(reserved for its WebAuthn service), so solo cannot reach the FIDO ' +
        'interface - run elevated to include this test');
    }
  };

  /** Run a command and count what it put on each interface. */
  async function sent(device, argv, { signal, input = NO_TO_EVERYTHING }) {
    const fido = device.mark(IFACE.FIDO);
    const vendor = device.mark(IFACE.VENDOR);
    const result = await cli.run('onlykey-cli', argv, { timeoutMs: CMD_TIMEOUT, signal, input });
    await device.sleep(900, { signal });
    return {
      result,
      fidoReports: device.reportsSince(IFACE.FIDO, fido).length,
      vendorSaid: device.reportsSince(IFACE.VENDOR, vendor)
        .map((r) => okmsg.text(r).trim()).filter((t) => t && t !== 'INITIALIZED'),
    };
  }

  it('`wink` reaches the device over FIDO and comes back',
    async ({ device, assert, signal, log, skip }) => {
      needCli({ skip });
      await needFidoHid({ skip, signal });
      await device.ensureUnlocked(PINS.primary, { signal });

      /*
       * SURFACE: FIDO - survives into a production walk.
       *
       * The one command in this file that works end to end, which makes it the
       * control: it proves the solo path to the device is sound, so the three
       * failures below are about solo's PIN API rather than about the transport
       * or the venv or the gadget.
       *
       * CTAPHID_WINK has no payload and no answer worth reading - it blinks the
       * LEDs - so the assertion is the round trip: a request and a response on
       * the FIDO interface, and exit 0.
       */
      const { result, fidoReports } = await sent(device, ['wink'], { signal });
      log(`wink exited ${result.code} with ${fidoReports} FIDO reports`);

      assert.equal(result.code, 0, `wink failed: ${result.stderr.slice(-300)}`);
      assert.ok(fidoReports > 0, 'wink never reached the FIDO interface');
    });

  it('`credential` reaches the device, and cannot read what it answers',
    async ({ device, assert, signal, log, skip }) => {
      needCli({ skip });
      await needFidoHid({ skip, signal });
      await device.ensureUnlocked(PINS.primary, { signal });

      /*
       * SURFACE: FIDO - survives into a production walk.
       *
       * Two things, and keeping them apart is the point. The command DOES reach
       * the device - reports go out and come back - and then solo fails to use
       * the answer, either with CTAP 0x35 PIN_NOT_SET on a device with no FIDO2
       * PIN or with the client_pin AttributeError. Which of the two depends on
       * how far it gets before touching the missing attribute, and both are the
       * same story: the transport is fine and the client is not.
       *
       * So the assertion is the transport plus a non-zero exit. Asserting the
       * exact message would pin an ordering that is not stable; asserting
       * SUCCESS would be wrong today and is what a caller might wrongly do.
       */
      const { result, fidoReports } = await sent(device, ['credential', 'ls'], { signal });
      log(`credential ls exited ${result.code} with ${fidoReports} FIDO reports`);
      log(`  ${JSON.stringify((result.stderr || result.stdout).trim().slice(-160))}`);

      assert.ok(fidoReports > 0, 'credential never reached the FIDO interface');
      assert.notEqual(result.code, 0,
        'credential now succeeds - solo and python-fido2 may have been brought back into step, ' +
        'in which case this file should assert what it actually lists');
    });

  it('`set-pin` reaches the device, and reports success it did not have',
    async ({ device, assert, signal, log, skip }) => {
      needCli({ skip });
      await needFidoHid({ skip, signal });
      await device.ensureUnlocked(PINS.primary, { signal });

      /*
       * SURFACE: FIDO - survives into a production walk.
       *
       * The sharpest of the three. solo dies on `client.client_pin`, prints the
       * AttributeError as its own output, and EXITS 0. So a script that sets a
       * FIDO2 PIN and checks the exit code is told it worked, every time, on a
       * device with no PIN set.
       *
       * Only the transport and the exit code are asserted, not the message:
       * this command was observed both to succeed ("Done. Please use new pin to
       * verify key") and to fail this way within the same session, depending on
       * the authenticator's PIN state, and a test that demanded one of those
       * would be flaky. Exiting 0 is true in both, which is exactly the problem.
       */
      const { result, fidoReports } = await sent(device, ['set-pin'],
        { signal, input: 'oktfidopin\noktfidopin\n' });
      log(`set-pin exited ${result.code} with ${fidoReports} FIDO reports`);
      log(`  ${JSON.stringify(result.stdout.trim().slice(0, 160))}`);

      assert.ok(fidoReports > 0, 'set-pin never reached the FIDO interface');
      assert.equal(result.code, 0,
        'set-pin now reports failure in its exit code - if that is deliberate, this test ' +
        'should assert the new contract instead');
    });

  it('`change-pin` replaces a PIN it set itself',
    async ({ device, assert, signal, log, skip }) => {
      needCli({ skip });
      await needFidoHid({ skip, signal });
      await device.ensureUnlocked(PINS.primary, { signal });

      /*
       * SURFACE: FIDO - survives into a production walk.
       *
       * THIS TEST SETS THE PIN IT THEN CHANGES, and that is a correction rather
       * than thoroughness. `change-pin`'s outcome depends entirely on whether
       * the authenticator already has a FIDO2 PIN: with one it completes, and
       * without one it dies on solo's missing `client_pin` attribute. The first
       * version of this test asserted the AttributeError and passed on its own
       * while failing in sequence, because the `set-pin` test above had left a
       * PIN behind - the same predecessor hazard 11-cli-settings and
       * 13-cli-lifecycle both hit, and the third time it has appeared in this
       * sweep.
       *
       * Establishing the precondition is also the better test: it drives the
       * command's actual job rather than one of its two failure modes.
       */
      const first = await sent(device, ['set-pin'], { signal, input: 'oktfidopin\noktfidopin\n' });
      log(`set-pin (precondition) exited ${first.result.code}`);

      const { result, fidoReports } = await sent(device, ['change-pin'],
        { signal, input: 'oktfidopin\noktnewpin1\noktnewpin1\n' });
      log(`change-pin exited ${result.code} with ${fidoReports} FIDO reports`);
      log(`  ${JSON.stringify(result.stdout.trim().slice(0, 160))}`);

      assert.ok(fidoReports > 0, 'change-pin never reached the FIDO interface');

      /*
       * One of two known outcomes, and which one is not this test's business -
       * what matters is that a client_pin AttributeError is NOT among them once
       * a PIN exists, because that is solo's dependency breakage rather than a
       * refusal the device made.
       */
      assert.ok(!SOLO_PIN_BREAKAGE.test(result.stdout),
        `change-pin hit solo's client_pin breakage even with a PIN set: ${
          JSON.stringify(result.stdout.trim().slice(0, 200))}`);
      assert.includes(result.stdout, 'Done',
        `expected change-pin to complete, got ${JSON.stringify(result.stdout.trim().slice(0, 200))}`);
    });

  it('`reset` will not wipe the authenticator without an answer at its prompt',
    async ({ device, assert, signal, log, skip }) => {
      needCli({ skip });
      await needFidoHid({ skip, signal });
      await device.ensureUnlocked(PINS.primary, { signal });

      /*
       * SURFACE: FIDO - survives into a production walk.
       *
       * A FIDO2 authenticator reset destroys every resident credential on the
       * device, so the interlock IS the feature and it is what gets tested. The
       * reset itself is deliberately never completed here: on the emulator a
       * fresh fixture would undo it, but the same file is meant to be readable
       * as something safe to point at hardware later, and a test that wipes
       * credentials is not that.
       *
       * The prompt is answered with nothing, which click reads as its default N.
       *
       * ONLY THE INVARIANTS ARE ASSERTED, and the list of what is not is the
       * interesting part: `reset` was observed exiting 1 with eleven FIDO
       * reports on an authenticator with no PIN, and exiting 0 with none once a
       * PIN existed. Neither its exit code nor whether it touches the device
       * before prompting is stable, so a test pinning either would fail on
       * whichever ran before it - the same predecessor hazard this sweep has now
       * hit four times.
       *
       * What holds either way: the warning is printed before anything is
       * decided, and the authenticator is still there afterwards. Those are the
       * two things the interlock exists to guarantee.
       */
      const { result, fidoReports } = await sent(device, ['reset'], { signal });
      log(`reset exited ${result.code} with ${fidoReports} FIDO reports`);

      assert.includes(result.stdout, 'Your credentials will be lost',
        `expected the destructive-action warning, got ${JSON.stringify(result.stdout.trim().slice(0, 200))}`);
      assert.ok(!/\bdone\b/i.test(result.stdout),
        `reset reported completion without a confirmed answer: ${JSON.stringify(result.stdout.trim().slice(0, 200))}`);

      /* Still there, still answering. */
      const after = await sent(device, ['wink'], { signal });
      assert.equal(after.result.code, 0, 'the device stopped answering FIDO after a declined reset');
      assert.ok(after.fidoReports > 0, 'no FIDO traffic after a declined reset');
    });

  it('`loadfirmware` asks for a file, then asks again before flashing one',
    async ({ device, assert, signal, log, skip }) => {
      needCli({ skip });
      await device.ensureUnlocked(PINS.primary, { signal });

      /*
       * SURFACE: vendor and FIDO - both survive into a production walk, and here
       * the assertion is that NEITHER carries anything.
       *
       * This is the one endpoint in the whole CLI that can DESTROY a physical
       * key: `OKFWUPDATE` needs the special bootloader, and running it locks
       * that bootloader and permanently converts a developer key into a
       * production key. The suite's `emulated` requirement is what stops the
       * hardware adapter reaching this at all; driving it only as far as its two
       * guards is the second line, not the first. Both are tested because they fail differently: no file
       * at all is a usage error, and a file with the confirmation declined is
       * the interlock doing its job. The valuable assertion in each case is the
       * silence - a guard that has already sent something is not a guard.
       *
       * The file handed over is a one-line Intel HEX end-of-file record. It is
       * deliberately not real firmware: if the interlock ever stops working,
       * this test fails at its silence assertion rather than by flashing.
       */
      const noFile = await sent(device, ['loadfirmware'], { signal });
      assert.includes(noFile.result.stdout, 'Usage: onlykey-cli loadfirmware',
        `expected a usage line, got ${JSON.stringify(noFile.result.stdout.trim().slice(0, 200))}`);
      assert.equal(noFile.fidoReports, 0, 'loadfirmware reached the device with no file to load');
      assert.equal(noFile.vendorSaid.length, 0,
        `loadfirmware spoke to the device with no file: ${JSON.stringify(noFile.vendorSaid)}`);

      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'okt-fw-'));
      try {
        const hex = path.join(dir, 'not-really-firmware.hex');
        fs.writeFileSync(hex, ':00000001FF\n');           // Intel HEX end-of-file, nothing else

        const declined = await sent(device, ['loadfirmware', hex], { signal, input: 'no\n' });
        log(`declined: ${JSON.stringify(declined.result.stdout.trim().slice(-60))}`);

        assert.includes(declined.result.stdout, 'Type YES to continue',
          'loadfirmware did not ask before flashing');
        assert.includes(declined.result.stdout, 'Firmware update cancelled',
          'loadfirmware did not honour a declined confirmation');
        assert.equal(declined.fidoReports, 0, 'a declined firmware load still reached the device');
        assert.equal(declined.vendorSaid.length, 0,
          `a declined firmware load still spoke to the device: ${JSON.stringify(declined.vendorSaid)}`);
      } finally {
        fs.rmSync(dir, { recursive: true, force: true });
      }
    });
});
