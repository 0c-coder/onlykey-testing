/*
 * The `onlykey-cli` endpoint sweep, part three: slots and key material.
 *
 * The first sweep file that WRITES KEY MATERIAL. Nothing here needs a wipe to
 * undo and no slot needs to be reserved for it: every file boots from a fresh
 * fixture image, so a key written here is gone before the next file starts.
 * The old kit handed slots out per file to stop one overwriting another's key
 * material - it lost whole runs to that - and that discipline is dead weight
 * here. Do not reintroduce it.
 *
 * Eight endpoints. `setslot` and `wipeslot` write the twelve profile slots -
 * the ones a button press types - and `setkey`, `genkey`, `wipekey`, `setpqc`,
 * `loadpqc` and `loadkey` write the key slots underneath them.
 *
 * SURFACES. Marked per test, as in 11-cli-settings, because a production key
 * ships without SEREMU and an assertion that reads the debug console cannot run
 * in a production walk - see PRODUCTION.md. This file needs the console for
 * nothing at all: every write is acknowledged by name on the vendor interface,
 * and the strongest assertion here reads a stored key back over the same
 * interface and checks it in pure JS.
 *
 * TWO GATES, WITH DIFFERENT WORDS FOR THE SAME CONDITION. Key material is
 * writable only in config mode, and the firmware says so twice, inconsistently:
 *
 *   OKSETPRIV  (setkey, genkey, setpqc)  "Error not in config mode"
 *   OKWIPEPRIV (wipekey)                 "Error not in config mode" (was "Error device locked")
 *
 * The second is misleading - the device is unlocked, it is simply not in config
 * mode - and it is asserted here in the firmware's own wording rather than
 * corrected, because a test that asserted the sensible message would fail
 * against the firmware that ships. okcore.cpp's OKWIPEPRIV case falls through to
 * a shared `else` that predates the config-mode branch beside it.
 *
 * AND CONFIG MODE IS NOT A SUPERSET OF NORMAL OPERATION. `OKGETPUBKEY` is
 * REFUSED while in config mode - "ERROR NOT SUPPORTED IN CONFIG MODE", printed
 * to the debug console with no vendor reply at all, so a client sees only
 * silence. That is why the readback tests below reboot before reading: writing a
 * key and reading it back cannot happen in one mode.
 */
'use strict';

const crypto = require('crypto');

const { describe, it } = require('../../lib/harness');
const { IFACE, okmsg } = require('../../lib/device');
const { PINS } = require('../../lib/config');
const cli = require('../../lib/cli');
const pqc = require('../../lib/pqc');

/* RFC 8032 test vector 1. A published value on purpose: the point of storing it
 * is to recompute its public half here rather than to trust the device. */
const SEED = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';
const ECC_SLOT = 101;                       // 'ECC1' in the CLI's spelling

const ANSWER = (buf) => {
  const text = okmsg.text(buf);
  return !!text && text !== 'INITIALIZED';
};

/** The ed25519 public key for a seed, from node:crypto - no optional deps. */
function ed25519PublicKey(seed) {
  const der = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]);
  const priv = crypto.createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
  return crypto.createPublicKey(priv).export({ format: 'der', type: 'spki' }).subarray(-32);
}

describe('onlykey-cli, the slot and key endpoints', {
  state: 'initialized',
  requires: ['crypto', 'client-access'],
  timeoutMs: 300000,
}, () => {
  const needCli = ({ skip }) => {
    if (!cli.venvPresent()) skip(`no venv at ${cli.VENV_BIN}`);
    cli.binary('onlykey-cli');
  };

  const okc = (argv, opts) => cli.run('onlykey-cli', argv, { timeoutMs: 40000, ...opts });

  /** One command, and the device's own answer read independently of the CLI. */
  async function sent(device, argv, { signal, replies = 1 }) {
    const since = device.mark(IFACE.VENDOR);
    const result = await okc(argv, { signal });
    await device.waitHid(IFACE.VENDOR, { since, match: ANSWER, timeoutMs: 12000, signal });
    /* Several of these answer more than once - wipeslot sends ten - so settle
     * before reading the whole window rather than taking the first. */
    if (replies > 1) await device.sleep(800, { signal });
    const said = device.reportsSince(IFACE.VENDOR, since)
      .map((r) => okmsg.text(r).trim()).filter((t) => t && t !== 'INITIALIZED');
    return { result, said };
  }

  /* Unlocked and definitely not in config mode - config mode is sticky and has
   * no exit but a reboot, and half the assertions here are about being outside
   * it. See 11-cli-settings for the incident that made this a helper. */
  const outOfConfigMode = async (device, signal) => {
    await device.restart({ signal });
    await device.ensureUnlocked(PINS.primary, { signal });
  };

  /* ---- the profile slots ------------------------------------------------ */

  it('`setslot` writes every field the command line can reach',
    async ({ device, assert, signal, log, skip }) => {
      needCli({ skip });
      await device.ensureUnlocked(PINS.primary, { signal });

      /*
       * SURFACE: vendor - survives into a production walk.
       *
       * Thirteen of the CLI's seventeen field types; the other four - password,
       * gkey, totpkey - read from stdin with prompt_toolkit and belong with
       * 13-cli-lifecycle's interactive commands.
       *
       * Each is acknowledged in its own words, so this is thirteen assertions
       * rather than one repeated: a CLI that mapped `delay2` onto DELAY1 would
       * be caught by the acknowledgement alone. They are in one test because
       * they are one endpoint, and `--test setslot` has to select one thing.
       */
      const fields = [
        [['label', 'oktslot'], 'Successfully set Label'],
        [['url', 'https://example.com'], 'Successfully set URL'],
        [['username', 'oktuser'], 'Successfully set Username'],
        [['delay1', '1'], 'Successfully set Delay1'],
        [['delay2', '2'], 'Successfully set Delay2'],
        [['delay3', '3'], 'Successfully set Delay3'],
        [['addchar1', '1'], 'Successfully set before Username Additional Character'],
        /* "Additonal" is the firmware's own spelling, in okcore.cpp. Asserted as
         * it ships rather than as it should read - a corrected string here would
         * fail against every device in the field. */
        [['addchar2', '2'], 'Successfully set after Username Additonal Character'],
        [['addchar3', '1'], 'Successfully set additional character after password'],
        [['addchar4', '2'], 'Successfully set before OTP Additional Character'],
        [['addchar5', '1'], 'Successfully set after OTP Character'],
        [['2fa', 'g'], 'Successfully set 2FA Type'],
        [['typespeed', '5'], 'Successfully set typespeed'],
      ];

      for (const [[field, value], expected] of fields) {
        const { result, said } = await sent(device, ['setslot', '1a', field, value], { signal });
        assert.equal(said[0], expected, `setslot ${field} answered: ${JSON.stringify(said)}`);
        assert.equal(result.stdout.trim(), said[0],
          `the CLI printed something else for ${field}`);
      }
      log(`${fields.length} slot fields, each acknowledged in its own words`);

      /*
       * And the label really landed, read back through a different command on
       * the same surface. The acknowledgement says the write was accepted; this
       * says it was stored.
       */
      const listed = await okc(['getlabels'], { signal });
      assert.equal(listed.code, 0, `getlabels failed: ${listed.stderr}`);
      assert.includes(listed.stdout, 'oktslot', 'the label written above is not in the slot list');
    });

  it('`wipeslot` clears every field of a slot, and says so field by field',
    async ({ device, assert, signal, log, skip }) => {
      needCli({ skip });
      await device.ensureUnlocked(PINS.primary, { signal });

      /* SURFACE: vendor - survives into a production walk. */
      const before = await sent(device, ['setslot', '2a', 'label', 'oktwipe'], { signal });
      assert.equal(before.said[0], 'Successfully set Label', 'could not write the label to wipe');

      const listedBefore = await okc(['getlabels'], { signal });
      assert.includes(listedBefore.stdout, 'oktwipe', 'the label to be wiped was never stored');

      /*
       * Ten acknowledgements, one per field - the whole slot goes, not just the
       * part that was written. Counting them is the assertion: a wipe that
       * cleared the label and left the password would answer fewer times, and
       * the password is the part that matters.
       */
      const { said } = await sent(device, ['wipeslot', '2a'], { signal, replies: 10 });
      log(`wipe acknowledgements: ${said.length}`);
      assert.equal(said.length, 10, `expected ten field wipes, got ${JSON.stringify(said)}`);

      for (const expected of ['Successfully wiped Label', 'Successfully wiped Password',
        'Successfully wiped Username', 'Successfully wiped 2FA Key']) {
        assert.ok(said.includes(expected), `no "${expected}" among ${JSON.stringify(said)}`);
      }

      /* And it is gone from the list, which is the client-visible proof. */
      const listedAfter = await okc(['getlabels'], { signal });
      assert.ok(!listedAfter.stdout.includes('oktwipe'),
        'the wiped label is still in the slot list');
    });

  /* ---- key material ----------------------------------------------------- */

  it('`setkey` is refused outside config mode, and stores a key the device can prove it has',
    async ({ device, assert, signal, log, skip }) => {
      needCli({ skip });
      await outOfConfigMode(device, signal);

      /*
       * SURFACE: vendor - survives into a production walk.
       *
       * The refusal first, because it is the security property: an unlocked
       * device is not enough to write key material into one.
       */
      const refused = await sent(device, ['setkey', 'ECC1', 'x', 's', SEED], { signal });
      assert.equal(refused.said[0], 'Error not in config mode',
        `outside config mode the device answered: ${JSON.stringify(refused.said)}`);

      await pqc.readyForKeygen(device, { signal });
      const accepted = await sent(device, ['setkey', 'ECC1', 'x', 's', SEED], { signal });
      assert.equal(accepted.said[0], 'Successfully set ECC Key',
        `in config mode the device answered: ${JSON.stringify(accepted.said)}`);
      assert.equal(accepted.result.stdout.trim(), accepted.said[0],
        'the CLI printed something other than what the device answered');

      /*
       * The assertion that makes the rest mean anything, and the only one here
       * that does not take the device's word for it: ask for the PUBLIC key and
       * check it is the public half of the seed that was stored, computed by
       * node:crypto. An acknowledgement says a write was accepted; this says the
       * right bytes arrived.
       *
       * The reboot is required rather than tidy. OKGETPUBKEY is REFUSED in
       * config mode - "ERROR NOT SUPPORTED IN CONFIG MODE" on the console, and
       * nothing at all on the vendor interface - so a client that tried to write
       * and read in one session would see the read time out with no explanation.
       */
      await outOfConfigMode(device, signal);

      const since = device.mark(IFACE.VENDOR);
      device.sendVendor({ msg: okmsg.MSG.OKGETPUBKEY, slot: ECC_SLOT });
      const reply = await device.waitHid(IFACE.VENDOR,
        { since, match: ANSWER, timeoutMs: 10000, signal });

      const got = reply.subarray(0, 32);
      const want = ed25519PublicKey(Buffer.from(SEED, 'hex'));
      log(`device returns ${got.toString('hex')}`);
      log(`node:crypto    ${want.toString('hex')}`);
      assert.bytes(got, want, 'the stored key is not the one the command line sent');
    });

  it('`genkey` is refused outside config mode, and generates a key on the device',
    async ({ device, assert, signal, log, skip }) => {
      needCli({ skip });
      await outOfConfigMode(device, signal);

      /* SURFACE: vendor - survives into a production walk. */
      const refused = await sent(device, ['genkey', 'ECC3', 'x', 's'], { signal });
      assert.equal(refused.said[0], 'Error not in config mode',
        `outside config mode the device answered: ${JSON.stringify(refused.said)}`);

      /*
       * `genkey` is `setkey` with the key bytes replaced by thirty-two 0xFF -
       * the firmware's "generate your own" trigger - so the same acknowledgement
       * comes back and nothing in it says a key was GENERATED rather than
       * stored. The readback is what tells them apart: a generated key is
       * random, so it must not be the published seed's public half, and it must
       * not be all-zero or all-0xFF either, which is what a trigger that fell
       * through to a plain store would leave.
       */
      await pqc.readyForKeygen(device, { signal });
      const accepted = await sent(device, ['genkey', 'ECC3', 'x', 's'], { signal });
      assert.equal(accepted.said[0], 'Successfully set ECC Key',
        `in config mode the device answered: ${JSON.stringify(accepted.said)}`);

      await outOfConfigMode(device, signal);
      const since = device.mark(IFACE.VENDOR);
      device.sendVendor({ msg: okmsg.MSG.OKGETPUBKEY, slot: 103 });
      const reply = await device.waitHid(IFACE.VENDOR,
        { since, match: ANSWER, timeoutMs: 10000, signal });

      const got = reply.subarray(0, 32);
      log(`generated public key ${got.toString('hex')}`);
      assert.notEqual(got.toString('hex'), ed25519PublicKey(Buffer.from(SEED, 'hex')).toString('hex'),
        'genkey stored the published test seed rather than generating a key');
      assert.notEqual(got.toString('hex'), '00'.repeat(32), 'the generated key is all zeros');
      assert.notEqual(got.toString('hex'), 'ff'.repeat(32),
        'the 0xFF generate trigger was stored as the key itself');
    });

  it('`wipekey` is refused outside config mode, and leaves the label alone',
    async ({ device, assert, signal, skip }) => {
      needCli({ skip });
      await outOfConfigMode(device, signal);

      /*
       * SURFACE: vendor - survives into a production walk.
       *
       * This pinned two things as they shipped, and both have since been fixed,
       * so both assertions are now the fixed behaviour:
       *
       * 1. The refusal used to read "Error device locked" for a device that
       *    was unlocked - OKWIPEPRIV fell through to a shared else. The
       *    firmware now names config mode ("Tell OKWIPEPRIV to name config
       *    mode when it refuses", libraries).
       * 2. python-onlykey's wipekey() then cleared the key's LABEL with an
       *    OKSETSLOT, which is not gated, so after a refused wipe the key stayed
       *    and lost its label, and the last line printed was "Successfully set
       *    Label". Fixed in python-onlykey 5520453: no label clear after an
       *    error. replies: 2 still waits long enough to see a second message if
       *    that regresses.
       */
      const refused = await sent(device, ['wipekey', 'ECC1'], { signal, replies: 2 });
      assert.equal(refused.said[0], 'Error not in config mode',
        `outside config mode the device answered: ${JSON.stringify(refused.said)}`);
      assert.equal(refused.said.length, 1,
        `a refused wipe was followed by ${JSON.stringify(refused.said.slice(1))} - ` +
        'wipekey() cleared the label of a key that is still on the device');

      /* And in config mode it does the thing. */
      await pqc.readyForKeygen(device, { signal });
      const wiped = await sent(device, ['wipekey', 'ECC1'], { signal, replies: 2 });
      assert.equal(wiped.said[0], 'Successfully wiped ECC Key',
        `in config mode the device answered: ${JSON.stringify(wiped.said)}`);
    });

  it('`setkey PQC1 p` reports the refusal rather than claiming success',
    async ({ device, assert, signal, log, skip }) => {
      needCli({ skip });
      await outOfConfigMode(device, signal);

      /*
       * SURFACE: vendor - survives into a production walk, and this is exactly
       * the kind of disagreement that surface exists to catch.
       *
       * THIS TEST USED TO ASSERT THE OPPOSITE, and the switch is the finding
       * closing rather than the behaviour drifting. As written it said "`setpqc`
       * reports success for a load the device refused": the device refuses each
       * of the three chunks of the 160-byte blob with "Error not in config
       * mode", and the CLI printed "Loaded composite PQC PGP key (160 bytes)
       * into RSA1" and exited 0 without ever reading a reply. A user followed
       * the documented procedure, saw success, and had an empty slot - with no
       * way to find out, because okcrypto_getpubkey() has no KEYTYPE_PQC_PGP
       * branch and a composite slot cannot be read back.
       *
       * Its own failure message asked whoever fixed it to come here and assert
       * the new behaviour, which is what this is. Fixed in python-onlykey:
       * load_composite_key() now waits for the device's acknowledgement and
       * raises on a refusal, and setpqc/loadpqc exit non-zero. See FINDINGS.md
       * #10.
       *
       * python-onlykey 1.3.0 then deleted setpqc; `setkey PQCn p` is its
       * replacement, and its first version printed only the exception class
       * and exited 0 on a refusal (fixed in python-onlykey f4a6031). Same
       * assertions, new command.
       *
       * The device half of the assertion is unchanged and still matters: it is
       * what proves the CLI is relaying a real refusal rather than failing for
       * some reason of its own.
       */
      const blob = '00'.repeat(160);
      const { result, said } = await sent(device, ['setkey', 'PQC1', 'p', blob], { signal, replies: 3 });

      log(`device said: ${JSON.stringify(said)}`);
      log(`CLI said: ${JSON.stringify(result.stdout.trim())}`);

      assert.ok(said.length > 0 && said.every((s) => s === 'Error not in config mode'),
        `expected the device to refuse every chunk, got ${JSON.stringify(said)}`);
      assert.notEqual(result.code, 0,
        'setkey p exited 0 for a load the device refused three times');
      assert.includes(result.stdout, 'not in config mode',
        'setkey p did not relay the device\'s reason for refusing');
      assert.ok(!/Loaded composite PQC PGP key/.test(result.stdout),
        'setkey p still claims to have loaded a key the device refused');
    });

  it('`loadpqc` refuses a file it cannot read, without touching the device',
    async ({ device, assert, signal, skip }) => {
      needCli({ skip });
      await device.ensureUnlocked(PINS.primary, { signal });

      /*
       * SURFACE: vendor - survives into a production walk, and here the
       * assertion IS the silence: argument handling must happen host-side,
       * before anything is sent.
       *
       * Only the rejecting path is driven. The accepting one parses a composite
       * PGP key file through a Node bridge and then takes setpqc's route into
       * the device, which 02-cli/05-composite-load already covers from the blob
       * side - what is not covered anywhere is the FILE parse, and that needs a
       * key file this file would have to generate. Tracked in TODO rather than
       * done badly here.
       *
       * "Touched the device" is measured on the VENDOR interface and not on the
       * console, and that is a correction rather than a preference: a DEBUG
       * build chatters continuously on its own - "wipe buffers after 5 sec" and
       * the like - so console growth measures elapsed time, not what this
       * command did. The first version of this test asserted the log length was
       * unchanged and failed for that reason.
       */
      const since = device.mark(IFACE.VENDOR);

      const result = await okc(['loadpqc', '/nonexistent/okt-no-such-key.asc'], { signal });
      await device.sleep(700, { signal });

      assert.match(result.stdout, /loadpqc <keyfile>|No such file|Error/i,
        `expected a usage or file error, got ${JSON.stringify(result.stdout.slice(0, 200))}`);
      assert.equal(device.reportsSince(IFACE.VENDOR, since).filter(ANSWER).length, 0,
        'loadpqc reached the device before deciding it could not read the file');
    });

  it('`loadkey` refuses a file it cannot read, without touching the device',
    async ({ device, assert, signal, skip }) => {
      needCli({ skip });
      await device.ensureUnlocked(PINS.primary, { signal });

      /* SURFACE: vendor - survives into a production walk; the assertion is the
       * silence, as above. The accepting path parses an OpenPGP private key and
       * writes it with OKSETPRIV, so it is gated the same way `setkey` is - and
       * it is tracked in TODO for the same reason loadpqc's is. Measured on the
       * vendor interface, not the console, for the reason given above. */
      const since = device.mark(IFACE.VENDOR);

      const result = await okc(['loadkey', '/nonexistent/okt-no-such-key.asc'], { signal });
      await device.sleep(700, { signal });

      assert.ok(result.stdout.trim().length > 0 || result.stderr.trim().length > 0,
        'loadkey said nothing at all about a file it could not read');
      assert.equal(device.reportsSince(IFACE.VENDOR, since).filter(ANSWER).length, 0,
        'loadkey reached the device before deciding it could not read the file');
    });
});
