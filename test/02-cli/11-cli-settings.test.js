/*
 * The `onlykey-cli` endpoint sweep, part two: the settings family.
 *
 * Thirteen subcommands, all the same shape underneath - `setslot(1, FIELD,
 * int(value))` - and all of them writes to device settings rather than to key
 * material. `backuppassphrase` is NOT here despite belonging to the family by
 * name: it reads from stdin with prompt_toolkit and goes out as OKSETPRIV,
 * which is a different driving problem and a different message, so it sits with
 * the interactive commands in 13-cli-lifecycle.
 *
 * SURFACES, AND WHY THIS FILE STATES THEM PER TEST
 * ------------------------------------------------
 * A production key ships without SEREMU - it is a debugging interface and on a
 * security key it is a key-extraction path - so every assertion that reads the
 * debug console is an assertion that cannot run in a future production walk.
 * What survives is what a real client can see: the keyboard, the vendor
 * interface (0xFFAB) and FIDO (0xF1D0). See PRODUCTION.md.
 *
 * So each test says which surface it is asserting on, in these words:
 *
 *   SURFACE: vendor   - survives into a production walk
 *   SURFACE: console  - does NOT survive; stated with why it is the only oracle
 *
 * This file is almost entirely the first kind, and that is a property of the
 * firmware rather than of the tests: every one of these thirteen writes is
 * acknowledged BY NAME on the vendor interface. "Successfully set keyboard
 * layout" is a different string from "Successfully set typespeed", so the
 * acknowledgement identifies the field, and a CLI that sent the wrong one is
 * caught without reading a debug line. The refusals are equally specific -
 * "Error not in config mode" is the security property itself, arriving on the
 * surface an attacker would see.
 *
 * AND THE CLIENT HAS TO RELAY IT. Every test also asserts that the CLI's stdout
 * equals the device's reply, because those are two readers of one message: the
 * kit reads the vendor interface directly over the in-process bus, python-onlykey
 * reads it over USB through hidapi. Agreement means the answer reached the
 * client; the kit alone seeing it would not.
 *
 * `onlykey-cli` EXITS 0 WHEN THE DEVICE REFUSES. Every refusal below comes back
 * as exit 0 with an error string on stdout, which is the sharpest possible
 * demonstration of this section's rule that an endpoint is not covered by
 * exiting 0. A test that checked the exit code would pass on all thirteen while
 * the device rejected every one of them.
 *
 * Every test stands alone - `okt run <file> --test keylayout` - and is named
 * after its endpoint so that selects exactly one.
 */
'use strict';

const { describe, it } = require('../../lib/harness');
const { IFACE, okmsg } = require('../../lib/device');
const { PINS } = require('../../lib/config');
const cli = require('../../lib/cli');
const pqc = require('../../lib/pqc');

/*
 * Anything the device says on the vendor interface that is not its once-a-second
 * locked-state broadcast. Used instead of matching the expected text, so that a
 * WRONG answer is compared and reported rather than waited out into a timeout
 * that names nothing.
 */
const ANSWER = (buf) => {
  const text = okmsg.text(buf);
  return !!text && text !== 'INITIALIZED';
};

describe('onlykey-cli, the settings endpoints', {
  state: 'initialized',
  requires: ['crypto', 'client-access'],
  timeoutMs: 240000,
}, () => {
  const needCli = ({ skip }) => {
    if (!cli.venvPresent()) skip(`no venv at ${cli.VENV_BIN}`);
    cli.binary('onlykey-cli');
  };

  /**
   * Run one settings subcommand and read the device's own answer off the vendor
   * interface, independently of what the CLI reports.
   *
   * SURFACE: vendor (0xFFAB) - survives into a production walk.
   */
  async function setting(device, argv, { signal }) {
    const since = device.mark(IFACE.VENDOR);
    const result = await cli.run('onlykey-cli', argv, { timeoutMs: 30000, signal });
    const reply = await device.waitHid(IFACE.VENDOR,
      { since, match: ANSWER, timeoutMs: 10000, signal });
    return { result, said: okmsg.text(reply).trim() };
  }

  /** Both readers of one message have to agree. */
  const relayed = (assert, result, said) => assert.equal(result.stdout.trim(), said,
    'the CLI printed something other than what the device answered');

  /**
   * Unlocked, and definitely NOT in config mode.
   *
   * Seven tests below assert that the device refuses something because config
   * mode is off, and none of them may assume it. Config mode is sticky and has
   * no exit but a reboot, so one earlier test entering it silently changes what
   * every later refusal means - `wipemode` and `backupkeymode` are not merely
   * gated on it, they SUCCEED inside it, so the assertion inverts rather than
   * erroring.
   *
   * Found by exactly that: the first version of this file had `derivedkeymode`
   * enter config mode and leave it on, and `wipemode` then answered
   * "Successfully set Wipe Mode to Full Wipe".
   *
   * Worth stating plainly because --isolate does NOT catch this class. Each of
   * those tests passes alone; they are broken by a PREDECESSOR rather than
   * dependent on one, and the gate only measures the second kind. Establishing
   * the state you are asserting about is the rule that covers both.
   */
  const outOfConfigMode = async (device, signal) => {
    await device.restart({ signal });
    await device.ensureUnlocked(PINS.primary, { signal });
  };

  /* ---- accepted with no gate ------------------------------------------- */

  it('`idletimeout` is accepted, and acknowledged by name',
    async ({ device, assert, signal, skip }) => {
      needCli({ skip });
      await device.ensureUnlocked(PINS.primary, { signal });

      /* SURFACE: vendor - survives into a production walk. */
      const { result, said } = await setting(device, ['idletimeout', '10'], { signal });
      assert.equal(said, 'Successfully set idle timeout', `the device answered: ${said}`);
      relayed(assert, result, said);
    });

  it('`ledbrightness` is accepted, and acknowledged by name',
    async ({ device, assert, signal, skip }) => {
      needCli({ skip });
      await device.ensureUnlocked(PINS.primary, { signal });

      /* SURFACE: vendor - survives into a production walk. */
      const { result, said } = await setting(device, ['ledbrightness', '5'], { signal });
      assert.equal(said, 'Successfully set LED brightness', `the device answered: ${said}`);
      relayed(assert, result, said);
    });

  it('`lockbutton` is accepted, and acknowledged by name',
    async ({ device, assert, signal, skip }) => {
      needCli({ skip });
      await device.ensureUnlocked(PINS.primary, { signal });

      /* SURFACE: vendor - survives into a production walk. */
      const { result, said } = await setting(device, ['lockbutton', '1'], { signal });
      assert.equal(said, 'Successfully set lock button', `the device answered: ${said}`);
      relayed(assert, result, said);
    });

  it('`keylayout` is accepted, and acknowledged by name',
    async ({ device, assert, signal, skip }) => {
      needCli({ skip });
      await device.ensureUnlocked(PINS.primary, { signal });

      /* SURFACE: vendor - survives into a production walk. */
      const { result, said } = await setting(device, ['keylayout', '1'], { signal });
      assert.equal(said, 'Successfully set keyboard layout', `the device answered: ${said}`);
      relayed(assert, result, said);
    });

  it('`keytypespeed` is accepted, and is a device setting rather than a slot one',
    async ({ device, assert, signal, log, skip }) => {
      needCli({ skip });
      await device.ensureUnlocked(PINS.primary, { signal });
      device.log.clear();

      /* SURFACE: vendor - survives into a production walk. */
      const { result, said } = await setting(device, ['keytypespeed', '7'], { signal });
      assert.equal(said, 'Successfully set typespeed', `the device answered: ${said}`);
      relayed(assert, result, said);

      /*
       * SURFACE: console - does NOT survive a production walk, and is used here
       * because nothing a client can see reports which SLOT a write went to.
       *
       * This one is worth the console. Every other command in this file sends
       * slot 1; `keytypespeed` alone sends 99, which python-onlykey's
       * send_message() rewrites to 0 - the device-wide pseudo-slot. The
       * acknowledgement is identical either way, so a CLI that started sending
       * slot 1 here would set the typing speed of ONE button rather than of the
       * device, be acknowledged in exactly the same words, and be invisible to
       * every assertion above.
       */
      const echoed = device.log.text.match(/Setting Slot #(\d+)\s+Value #(\d+)/);
      assert.ok(echoed, `the device did not echo the slot and field: ${device.log.tail(400)}`);
      log(`console echo: slot ${echoed[1]}, field ${echoed[2]}`);
      assert.equal(echoed[1], '0', 'keytypespeed went to a numbered slot, not the device-wide one');
      assert.equal(echoed[2], '13', 'keytypespeed did not go to the KEYTYPESPEED field');
    });

  /* ---- refused outside config mode ------------------------------------- */

  it('`storedkeymode` is refused outside config mode',
    async ({ device, assert, signal, skip }) => {
      needCli({ skip });
      await outOfConfigMode(device, signal);

      /*
       * SURFACE: vendor - survives into a production walk, and this is the kind
       * of assertion worth having there: the refusal IS the security property,
       * arriving on the surface an attacker would be looking at. An unlocked
       * device is not enough to change how a stored key challenges its user.
       */
      const { result, said } = await setting(device, ['storedkeymode', '1'], { signal });
      assert.equal(said, 'Error not in config mode', `the device answered: ${said}`);
      relayed(assert, result, said);

      /* And the CLI reports success regardless - see the file header. */
      assert.equal(result.code, 0,
        'onlykey-cli has started reporting a refusal in its exit code; the header says it does not');
    });

  it('`hmackeymode` is refused outside config mode',
    async ({ device, assert, signal, skip }) => {
      needCli({ skip });
      await outOfConfigMode(device, signal);

      /* SURFACE: vendor - survives into a production walk. */
      const { result, said } = await setting(device, ['hmackeymode', '1'], { signal });
      assert.equal(said, 'Error not in config mode', `the device answered: ${said}`);
      relayed(assert, result, said);
    });

  it('`sysadminmode` is refused outside config mode',
    async ({ device, assert, signal, skip }) => {
      needCli({ skip });
      await outOfConfigMode(device, signal);

      /* SURFACE: vendor - survives into a production walk. */
      const { result, said } = await setting(device, ['sysadminmode', '1'], { signal });
      assert.equal(said, 'Error not in config mode', `the device answered: ${said}`);
      relayed(assert, result, said);
    });

  it('`touchsense` is refused outside config mode',
    async ({ device, assert, signal, skip }) => {
      needCli({ skip });
      await outOfConfigMode(device, signal);

      /*
       * SURFACE: vendor - survives into a production walk.
       *
       * The config-mode gate is checked BEFORE the range check in okcore.cpp, so
       * an out-of-range value outside config mode still reports the gate. That
       * ordering is why this sends a plausible value: a rejected-for-range
       * answer here would mean the gate had moved.
       */
      const { result, said } = await setting(device, ['touchsense', '5'], { signal });
      assert.equal(said, 'Error not in config mode', `the device answered: ${said}`);
      relayed(assert, result, said);
    });

  it('`derivedkeymode` is refused outside config mode, and accepted inside it',
    async ({ device, assert, signal, skip }) => {
      needCli({ skip });

      /*
       * SURFACE: vendor - survives into a production walk.
       *
       * The one endpoint here whose ACCEPT path is driven as well as its
       * refusal, and it earns the cost - entering config mode is a long press, a
       * relock and a second unlock - because this bit is load-bearing elsewhere:
       * 03-gui/02-derive needs it set before the web app's derive call works at
       * all, and sets it over the kit's own vendor interface rather than through
       * this command. Driving the CLI's version here is what says the two agree.
       *
       * The other four gated commands assert only the refusal. That is the
       * cheap half and the half that is a security property; proving the gate
       * OPENS once is enough to say the gate is a gate rather than a wall.
       */
      /* 1 (button press), not the legacy bitfield value 8: field 21 is the
       * 0/1/2 user-input enum now, and python-onlykey 1.3.0 refuses anything
       * else host-side without sending it - so '8' left the device silent and
       * this test waiting for a report that was never coming. */
      await outOfConfigMode(device, signal);
      const refused = await setting(device, ['derivedkeymode', '1'], { signal });
      assert.equal(refused.said, 'Error not in config mode',
        `outside config mode the device answered: ${refused.said}`);
      relayed(assert, refused.result, refused.said);

      /* Restart first, then unlock, then the long press - readyForKeygen()'s
       * sequence, and it is the sequence rather than a preference: config-mode
       * entry from an unknown state feeds PIN digits to a device that may read
       * them as slot presses. */
      await pqc.readyForKeygen(device, { signal });

      const accepted = await setting(device, ['derivedkeymode', '1'], { signal });
      assert.equal(accepted.said, 'Successfully set derived key challenge mode',
        `in config mode the device answered: ${accepted.said}`);
      relayed(assert, accepted.result, accepted.said);
    });

  /* ---- refused because the device is already provisioned ---------------- */

  it('`wipemode` is refused on a device that is already set up',
    async ({ device, assert, signal, skip }) => {
      needCli({ skip });
      await outOfConfigMode(device, signal);

      /*
       * SURFACE: vendor - survives into a production walk.
       *
       * A one-way setting: okcore.cpp permits it on first use, or in config mode
       * for the full-wipe value, and refuses it otherwise. The fixture is a
       * provisioned device, so the refusal is what should be seen - and it is
       * the interesting direction, since this setting decides whether a wrong
       * PIN wipes the key.
       */
      const { result, said } = await setting(device, ['wipemode', '2'], { signal });
      assert.equal(said, 'Error Wipe Mode may not be changed', `the device answered: ${said}`);
      relayed(assert, result, said);
    });

  it('`backupkeymode` is refused on a device that is already set up',
    async ({ device, assert, signal, skip }) => {
      needCli({ skip });
      await outOfConfigMode(device, signal);

      /* SURFACE: vendor - survives into a production walk. Same one-way shape as
       * wipemode: this one decides whether the backup key can ever change. */
      const { result, said } = await setting(device, ['backupkeymode', '1'], { signal });
      assert.equal(said, 'Error Backup Key Mode may not be changed', `the device answered: ${said}`);
      relayed(assert, result, said);
    });

  it('`2ndprofilemode` is gone from the CLI, and sends the device nothing',
    async ({ device, assert, signal, skip }) => {
      needCli({ skip });
      await device.ensureUnlocked(PINS.primary, { signal });

      /*
       * SURFACE: vendor - survives into a production walk.
       *
       * python-onlykey 1.3.0 removed the command: the second profile is always
       * standard now (plausible deniability was retired), so there is nothing
       * left for it to set. This used to pin the firmware's first-use refusal,
       * "Second Profile Mode may only be changed on first use"; what matters
       * now is that the removal is clean - the CLI says so, and nothing reaches
       * the device. Unlocked, so the vendor interface is silent unless asked.
       */
      const since = device.mark(IFACE.VENDOR);
      const result = await cli.run('onlykey-cli', ['2ndprofilemode', '1'], { timeoutMs: 30000, signal });
      await device.sleep(1500, { signal });
      const said = device.reportsSince(IFACE.VENDOR, since)
        .map((r) => okmsg.text(r).trim()).filter(Boolean);

      assert.match(`${result.stdout}${result.stderr}`, /Command not found/i,
        `the CLI still accepts 2ndprofilemode: ${JSON.stringify(result.stdout.trim())}`);
      assert.equal(said.length, 0,
        `a removed command still reached the device: ${JSON.stringify(said)}`);
    });
});
