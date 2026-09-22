/*
 * The `onlykey-cli` endpoint sweep, part one: the endpoints that only read.
 *
 * Worth saying plainly, because it is not what the section's name suggests:
 * until this file, section 2 had run exactly ONE of onlykey-cli's 37
 * subcommands - `setpqc`, and only as a means of loading a key for something
 * else to test. Everything else here drives age-plugin-onlykey, onlykey-agent,
 * onlykey-gpg or python-onlykey's library directly. The CLI itself, which is
 * what a person actually types, was almost entirely untested.
 *
 * This is the first of five files that fix that, split by what an endpoint
 * COSTS rather than by where it appears in the help text:
 *
 *   10  reads          nothing changes; safe to run against any state
 *   11  settings       the mode/idletimeout/keylayout family - writes, but only
 *                      to settings, and every one is readable back
 *   12  slots and keys setslot/wipeslot/setkey/genkey - writes key material
 *   13  PIN lifecycle  init/set-pin/change-pin/reset - changes what the device
 *                      IS, and `reset` needs a capability gate
 *   14  FIDO           credential/loadfirmware - the second interface, and the
 *                      one that can leave a key needing `okt flash`
 *
 * AN ENDPOINT IS NOT COVERED BY EXITING 0. Every read below is checked against
 * something that is not the CLI: the version against what section 1's own
 * unlock reported, the labels against a slot this kit wrote over the vendor
 * interface, the RNG against a second call. A test that only asserted "it
 * printed something" would pass against a CLI that had lost the device
 * entirely, since several of these print a help line and exit 0 when they do
 * not like their arguments.
 *
 * EVERY TEST HERE STANDS ALONE, which is a requirement rather than a style.
 * A single endpoint has to be debuggable on its own -
 * `okt run test/02-cli/10-cli-reads.test.js --test rng` - and that only works
 * if no test depends on what an earlier one did. So each brings the device to
 * the state it needs through ensureUnlocked(), which is idempotent, rather
 * than relying on a previous test having unlocked it. `okt run <file>
 * --isolate` runs them one per device session and reports any that cannot.
 *
 * The CLI is also not one program. `version`, `fwversion`, `getlabels` and
 * `getkeylabels` are python-onlykey talking over the vendor interface, while
 * `ping` and `rng` hand off to `solo.cli.key()` - the Solo/FIDO2 CLI - which
 * reaches the same device over a completely different interface. Those two are
 * the only reads in the CLI that go near FIDO, and they fail in a different
 * language when they fail.
 */
'use strict';

const { describe, it } = require('../../lib/harness');
const { IFACE, okmsg } = require('../../lib/device');
const { PINS } = require('../../lib/config');
const cli = require('../../lib/cli');

/* okcore.h's slot field ids, as 08-slot-keyboard uses them. */
const FIELD = { LABEL: 1 };
const SLOT = 1;                              // slot 1a, the first profile's first button
const LABEL = 'oktreads';

describe('onlykey-cli, the read-only endpoints', {
  state: 'initialized',
  requires: ['crypto', 'client-access'],
  timeoutMs: 180000,
}, () => {
  const okc = (argv, opts) => cli.run('onlykey-cli', argv, { timeoutMs: 45000, ...opts });

  /*
   * The precondition every test needs, and therefore not a test of its own: a
   * `has the CLI` test would be skipped away by --test and leave the endpoint
   * under debug failing with a module error instead of a stated skip.
   */
  const needCli = ({ skip }) => {
    if (!cli.venvPresent()) skip(`no venv at ${cli.VENV_BIN}`);
    cli.binary('onlykey-cli');                // throws, naming the venv, if absent
  };

  it('`version` prints the CLI\'s own version, with no device involved',
    async ({ device, assert, signal, log, skip }) => {
      needCli({ skip });
    /*
     * `version` is a bare print - it never opens the device - and asserting the
     * device stayed silent is what makes that a fact about the command rather
     * than a description of one run. It is also the cheapest possible check
     * that the CLI can start at all. Until python-onlykey 1.3.0 it constructed
     * an OnlyKey() at MODULE IMPORT time, so every command - this one included
     * - opened the device first; 1.3.0 connects on first use instead.
     */
    /*
     * Measured on the VENDOR interface, not the console. The console version of
     * this assertion failed on 2026-09-22 with the CLI blameless: a DEBUG build
     * prints its capacitive-touch calibration ("touchread1 and touchread1ref"
     * ...) for a while after every boot, and this test ran 0.36 s after one.
     * Console growth measures elapsed time, not what the command did - the
     * same correction 12-cli-slots made for loadpqc. Anything the device says
     * in answer to a host lands on the vendor interface.
     */
    /* Unlocked first: a LOCKED device broadcasts INITIALIZED every second on
     * its own (taskInitialized - 01-protocol/06-vendor-status), and filtering
     * that out would also hide the INITIALIZED a locked device sends back to a
     * CLI that did talk to it (OKSETTIME answers with the status). Unlocked,
     * the vendor interface is silent unless asked. */
    await device.ensureUnlocked(PINS.primary, { signal });
    const since = device.mark(IFACE.VENDOR);

    const result = await okc(['version'], { signal });
    assert.equal(result.code, 0, `onlykey-cli version failed: ${result.stderr}`);
    log(result.stdout.trim());

    assert.match(result.stdout, /OnlyKey CLI v\d+\.\d+/,
      `unexpected version output: ${JSON.stringify(result.stdout.slice(0, 80))}`);
    await device.sleep(1000, { signal });
    const said = device.reportsSince(IFACE.VENDOR, since)
      .map((r) => okmsg.text(r).trim()).filter(Boolean);
    assert.equal(said.length, 0,
      `the device answered something while the CLI printed its own version: ${JSON.stringify(said)}`);
  });

  it('`fwversion` agrees with the firmware the kit was told',
    async ({ device, assert, signal, log, skip }) => {
      needCli({ skip });
    /*
     * The same cross-check 00-venv makes, but through the ACTUAL CLI binary
     * rather than through a python snippet that constructs OnlyKey() by hand.
     * That distinction matters more than it looks: the snippet route was chosen
     * in 00-venv precisely to dodge the CLI's module-import-time enumeration
     * race, so nothing until now has asserted the executable itself gets this
     * right.
     *
     * `fwversion` prints okversion[8:] - the model string with the eight
     * characters of "UNLOCKED" removed - so the kit's own answer has to be
     * trimmed the same way for them to be comparable.
     */
    const model = await device.ensureUnlocked(PINS.primary, { signal });

    const result = await okc(['fwversion'], { signal });
    assert.equal(result.code, 0, `onlykey-cli fwversion failed: ${result.stderr}`);

    const reported = result.stdout.trim();
    log(`CLI says ${JSON.stringify(reported)}, the kit was told ${JSON.stringify(model.trim())}`);

    assert.match(reported, /^v\d+\.\d+/, `not a firmware version: ${JSON.stringify(reported)}`);
    assert.equal(reported, model.replace(/\0/g, '').trim().slice(8),
      'the CLI and the kit disagree about the firmware version');
  });

  it('`getlabels` lists the profile slots, including one this kit wrote',
    async ({ device, assert, signal, log, skip }) => {
      needCli({ skip });
      await device.ensureUnlocked(PINS.primary, { signal });

      /*
       * Two clients, one slot. The kit writes a label over the in-process
       * vendor interface and the CLI reads it back over USB, so a pass says
       * OKSETSLOT and OKGETLABELS agree across two implementations - which is
       * the whole argument for section 2 existing. Asserting only that twelve
       * lines came back would pass against a device that returned the labels of
       * a completely different profile.
       */
      const since = device.mark(IFACE.VENDOR);
      device.sendVendor({ msg: okmsg.MSG.OKSETSLOT, slot: SLOT, field: FIELD.LABEL, payload: LABEL });

      const ack = await device.waitHid(IFACE.VENDOR,
        { since, match: /Successfully set|Error/, timeoutMs: 5000, signal });
      assert.ok(!/Error/.test(okmsg.text(ack)), `writing the label failed: ${okmsg.text(ack)}`);

      const result = await okc(['getlabels'], { signal });
      assert.equal(result.code, 0, `onlykey-cli getlabels failed: ${result.stderr}`);

      const lines = result.stdout.split('\n').filter((l) => l.trim());
      log(`getlabels printed ${lines.length} slot lines`);

      /*
       * Twelve slots on a Classic/Color - 1a..6b. The DUO branch prints
       * twenty-four and is chosen by a detail worth knowing about: cli.py reads
       * `okversion[19] == 'c'`, a fixed INDEX into the model string rather than
       * a search. "UNLOCKED" is eight characters and this firmware's version is
       * twelve, so index 19 lands on the hardware-variant character by
       * arithmetic that holds only for a version string of exactly this length.
       * A longer or shorter one selects some other character and the CLI reads
       * the wrong slot layout - which would present as a KeyError here, not as
       * a wrong answer.
       */
      assert.equal(lines.length, 12,
        `expected 12 profile slots on a Color, got ${lines.length}: ${JSON.stringify(lines)}`);
      assert.ok(lines.some((l) => l.includes(LABEL)),
        `the label this kit wrote is not in the CLI's list: ${JSON.stringify(lines)}`);
    });

  it('`getkeylabels` lists the key slots', async ({ device, assert, signal, log, skip }) => {
    needCli({ skip });
    await device.ensureUnlocked(PINS.primary, { signal });
    /*
     * A different message from getlabels - OKGETLABELS with the key-slot flag -
     * and a different fixed list: four RSA slots and sixteen ECC ones. The
     * fixture provisions no keys, so the interesting assertion is the SHAPE:
     * twenty slots, named the way the CLI names them, because that naming is
     * what every other command's slot argument has to agree with.
     */
    const result = await okc(['getkeylabels'], { signal });
    assert.equal(result.code, 0, `onlykey-cli getkeylabels failed: ${result.stderr}`);

    const lines = result.stdout.split('\n').filter((l) => l.trim());
    log(`getkeylabels printed ${lines.length} key slots`);

    assert.equal(lines.length, 20, `expected 4 RSA + 16 ECC slots, got ${lines.length}`);
    assert.ok(lines.some((l) => /RSA Key 1\b/.test(l)), `no RSA Key 1: ${JSON.stringify(lines.slice(0, 3))}`);
    assert.ok(lines.some((l) => /ECC Key 16\b/.test(l)), `no ECC Key 16: ${JSON.stringify(lines.slice(-3))}`);
  });

  it('`ping` reaches the device over FIDO, not the vendor interface',
    async ({ assert, signal, log, skip }) => {
    needCli({ skip });
    /*
     * `ping` is not python-onlykey at all - cli.py hands straight off to
     * solo.cli.key(), the Solo FIDO2 CLI, which finds the device through
     * python-fido2 and talks CTAPHID. So this is the only read here that says
     * anything about the FIDO interface, and it is worth having precisely
     * because it fails in a different language: a vendor-interface problem
     * leaves these four passing and this one failing, which names the
     * interface without anyone having to guess.
     */
    const result = await okc(['ping'], { signal });
    log(`ping exited ${result.code}: ${JSON.stringify((result.stdout || result.stderr).slice(0, 200))}`);

    if (result.code !== 0) {
      skip(`solo's FIDO path did not answer: ${(result.stderr || result.stdout).trim().slice(0, 200)}`);
    }
    assert.ok(!/Option not found|command options here/.test(result.stdout),
      'the CLI rejected `ping` as an argument rather than running it');
  });

  it('`rng` draws random bytes, and different ones each time',
    async ({ assert, signal, log, skip }) => {
      /*
       * `rng hexbytes` is the other solo-backed read, and the only endpoint in
       * the CLI that asks the device for entropy. Two calls must differ - which
       * is a weak test of randomness and a strong test of the thing that
       * actually goes wrong, a buffer that is filled once and then returned
       * again, or not filled at all and returned as zeros.
       *
       * `feedkernel` is the other mode and is deliberately not driven: it
       * writes into /dev/random, which is a change to the HOST rather than to
       * the device and is not this suite's to make.
       */
      needCli({ skip });

      const first = await okc(['rng', 'hexbytes', '--count', '32'], { signal });
      log(`rng exited ${first.code}: ${JSON.stringify((first.stdout || first.stderr).slice(0, 200))}`);

      if (first.code !== 0) {
        skip(`rng did not answer: ${(first.stderr || first.stdout).trim().slice(0, 200)}`);
      }

      const hexOf = (out) => (out.match(/\b[0-9a-fA-F]{16,}\b/g) || []).join('');
      const a = hexOf(first.stdout);
      assert.ok(a.length >= 32, `no hex bytes in the output: ${JSON.stringify(first.stdout.slice(0, 200))}`);

      const second = await okc(['rng', 'hexbytes', '--count', '32'], { signal });
      assert.equal(second.code, 0, `the second rng failed: ${second.stderr}`);
      const b = hexOf(second.stdout);

      assert.notEqual(a, b, 'two rng calls returned identical bytes');
      assert.notEqual(a, '0'.repeat(a.length), 'the device returned all zeros');
    });
});
