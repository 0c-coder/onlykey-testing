/*
 * `loadpqc` and `loadkey` on their ACCEPTING paths - the last row of section 2.
 *
 * `12-cli-slots` drives both commands only as far as a file they cannot read,
 * which proves argument handling happens host-side and nothing else. What was
 * never covered is the half that does the work: **parsing a real OpenPGP private
 * key file** and putting what comes out of it on the device. These two commands
 * are the only place in the kit where a PGP FILE - the thing a person actually
 * has - is the input, and the parse happens in a Node/OpenPGP.js bridge that
 * python-onlykey shells out to, so it is a third implementation nothing has
 * checked against anything.
 *
 * THE FILES ARE GENERATED HERE, by the WEB APP's own vendored openpgp fork. That
 * is the same argument `05-composite-load` makes and it holds twice over: the
 * browser makes a key, a command line puts it on the device, neither can do the
 * other's job, and a disagreement about the format shows up here or nowhere.
 * Using a checked-in fixture key would test that the bridge still reads a file
 * from 2026 rather than that the two clients agree today.
 *
 * WHAT EACH COMMAND CAN BE ASKED FOR, because the two are not symmetrical:
 *
 *   loadpqc   composite PQC. There is NO READBACK - okcrypto_getpubkey() has no
 *             KEYTYPE_PQC_PGP branch, as okpqc.h says - so the only evidence a
 *             load worked is the device USING the key. This asks it to sign and
 *             verifies against the public half of the very file that was loaded.
 *   loadkey   classic RSA. The modulus IS readable, so this reads slots 1 and 2
 *             back over the vendor interface and checks them against what
 *             openpgp.js says the file's two halves are.
 *
 * THE SECOND ONE IS WORTH MORE THAN IT LOOKS, because of where the CLI puts the
 * halves. `loadkey`'s auto mode assigns "subkey 1 = decryption (slot 1), primary
 * = signing (slot 2)" - which is exactly the pair `onlykey-pgp.js`'s `slotid()`
 * hardcodes for the encrypt and decrypt pages. So this asserts that the CLI's
 * loader and the web app's key selection agree about a convention neither one
 * states, and that `03-gui/08` and `03-gui/14` would find the key where they
 * look for it if a person had loaded it this way rather than the way those files
 * do it themselves.
 *
 * SURFACES. The vendor interface carries every load and both moduli, so those
 * assertions survive into a production walk. The console is read only for the
 * challenge timing on the composite signature, through `lib/pqc.js`, which is
 * the same console-only dependency every challenge-answering test has.
 */
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { describe, it } = require('../../lib/harness');
const { IFACE, okmsg } = require('../../lib/device');
const { PINS } = require('../../lib/config');
const cli = require('../../lib/cli');
const pqc = require('../../lib/pqc');
const webenv = require('../../lib/webenv');
const { collectVendor, RSA_2048_BYTES } = require('../../lib/pgp-rsa');

const USER = { name: 'Kit', email: 'kit@example.com' };
const PASSPHRASE = 'okt-key-file-passphrase';
const HALF_ECC = 0;                 // the composite blob's Ed25519 half
const SLOT_DECRYPT = 1;             // loadkey auto puts the encryption subkey here
const SLOT_SIGN = 2;                // ...and the signing key here

const ANSWER = (buf) => {
  const text = okmsg.text(buf);
  return !!text && text !== 'INITIALIZED';
};

describe('onlykey-cli, loading keys from PGP files', {
  state: 'initialized',
  requires: ['crypto', 'client-access', 'webapp-lib', 'xwing-math'],
  timeoutMs: 300000,
}, () => {
  const needCli = ({ skip }) => {
    if (!cli.venvPresent()) skip(`no venv at ${cli.VENV_BIN}`);
    cli.binary('onlykey-cli');
  };

  /* Written where a run can be inspected afterwards and cleaned up by the OS,
   * not into the test tree - a private key on disk in a repo is a bad habit even
   * when it is thirty seconds old and belongs to nobody. */
  const tmpdir = fs.mkdtempSync(path.join(os.tmpdir(), 'okt-keyfiles-'));
  const write = (name, text) => {
    const file = path.join(tmpdir, name);
    fs.writeFileSync(file, text, { mode: 0o600 });
    return file;
  };

  /**
   * A composite PQC key FILE, and the blob its material packs into.
   *
   * `composite_pgp.js`'s own `generateCompositeKey()` hands back only the public
   * half and the blob, and `loadpqc` needs the PRIVATE file - so this makes the
   * same call it makes, keeps the private key, and packs the blob with the same
   * `packBlob()`. Doing it this way rather than reimplementing the offsets is
   * what keeps this test about the FILE PARSE rather than about the layout,
   * which `03-gui/05-composite-blob` already owns.
   */
  async function compositeKeyFile(name) {
    const openpgp = webenv.openpgp();
    const cp = webenv.loadPlain('composite_pgp.js');

    openpgp.clearHardwareHooks();
    const { privateKey, publicKey } = await openpgp.generateKey({
      type: 'pqc',
      userIDs: [USER],
      subkeys: [{}],
      format: 'object',
      config: { v6Keys: true },
    });

    const primary = privateKey.keyPacket.privateParams;
    const sub = privateKey.subkeys[0].keyPacket.privateParams;
    const blob = Buffer.from(cp.packBlob(
      primary.eccSecretKey, primary.mldsaSeed, sub.eccSecretKey, sub.mlkemSeed
    ));

    return {
      file: write(name, await privateKey.armor()),
      armoredPublic: await publicKey.armor(),
      blob,
    };
  }

  /** A classic RSA key FILE, passphrase-protected, with both halves in device terms. */
  async function rsaKeyFile(name) {
    const openpgp = webenv.openpgp();
    const { privateKey, publicKey } = await openpgp.generateKey({
      type: 'rsa', rsaBits: 2048, userIDs: [USER], passphrase: PASSPHRASE, format: 'object',
    });
    /* generateKey returns the key already locked when a passphrase is given, so
     * the moduli have to come from the PUBLIC half rather than from
     * privateParams, which are encrypted. */
    return {
      file: write(name, privateKey.armor()),
      primaryN: Buffer.from(publicKey.keyPacket.publicParams.n),
      subN: Buffer.from(publicKey.subkeys[0].keyPacket.publicParams.n),
    };
  }

  it('`loadpqc` parses a composite key file and the device signs with what came out of it',
    async ({ device, assert, signal, log, skip }) => {
      needCli({ skip });

      /*
       * SURFACE: vendor for the load, console for the challenge timing.
       *
       * The accepting path, end to end. There is no readback for a composite
       * slot, so the assertion has to be the device USING the key - and it is
       * verified against a public key that came out of the SAME FILE, so it can
       * only pass if the bridge extracted the right material, the CLI chunked it
       * correctly, and the firmware read the layout the way the web app wrote it.
       */
      const key = await compositeKeyFile('composite.asc');
      log(`composite key file ${key.file}, ${fs.statSync(key.file).size} bytes`);

      /*
       * readyForKeygen() rather than unlock() + enterConfigMode(), and the
       * difference is not stylistic. `unlock()` PRESSES the PIN digits, so on an
       * already-unlocked device they are slot presses and the call waits for an
       * `UNLOCKED` that will not come again - which is what the second test in
       * this file did on its first run, timing out thirty seconds after a
       * predecessor left the device unlocked. readyForKeygen reboots first, so
       * the state is known rather than inherited.
       */
      await pqc.readyForKeygen(device, { signal });

      const since = device.mark(IFACE.VENDOR);
      const result = await cli.run('onlykey-cli',
        ['loadpqc', key.file, 'PQC1'], { timeoutMs: 120000, signal });

      assert.equal(result.code, 0,
        `loadpqc failed: ${result.stderr || result.stdout}`);
      assert.includes(`${result.stdout}${result.stderr}`, 'Loaded composite PQC PGP key',
        `loadpqc did not report a load: ${result.stdout}`);
      assert.includes(result.stdout, key.file,
        'loadpqc did not name the file it read - its message is where a person checks ' +
        'that the right key went in');

      /*
       * The device ACCEPTED it, which `setpqc` taught us not to take from the
       * CLI's word: 12-cli-slots pins `setpqc` reporting success for a load the
       * device refused three times over. loadpqc shares that route, so its
       * success line is worth exactly as little until the device agrees.
       */
      await device.waitHid(IFACE.VENDOR,
        { since, match: ANSWER, timeoutMs: 20000, signal });
      const said = device.reportsSince(IFACE.VENDOR, since)
        .map((r) => okmsg.text(r).trim()).filter((t) => t && t !== 'INITIALIZED');
      log(`device said ${JSON.stringify(said)}`);
      assert.ok(said.length > 0 && !said.some((s) => /^Error/.test(s)),
        `the device refused the load the CLI reported as successful: ${JSON.stringify(said)}`);

      /* OKSIGN is not among config mode's eleven allowed messages, so signing
       * from inside it is silently dropped - see 05-composite-load. */
      await device.restart({ signal });
      await device.unlock(PINS.primary, { signal });

      const digest = crypto.createHash('sha256').update('loadpqc, from a file').digest();
      const primed = Buffer.concat([Buffer.from([HALF_ECC]), digest]);

      const signed = await pqc.runWithConfirm(device, 'python3', ['-c', [
        'import time, binascii',
        'from onlykey.client import OnlyKey, Message',
        'ok = OnlyKey()',
        'ok.set_time(time.time())',
        `digest = binascii.unhexlify("${digest.toString('hex')}")`,
        `ok.send_large_message2(msg=Message.OKSIGN, slot_id=1,`,
        `                       payload=bytes([${HALF_ECC}]) + digest)`,
        /* Skip the status broadcasts, and read BYTES - read_string drops every
         * zero, which turns a signature into something short and shifted. Both
         * traps are 05-composite-load's, met again here. */
        'sig = None',
        'deadline = time.time() + 25',
        'while time.time() < deadline:',
        '    got = bytearray(ok.read_bytes(64, timeout_ms=2000))',
        '    if not got:',
        '        continue',
        '    text = bytes(got).decode("latin-1")',
        '    if text.startswith("UNLOCKED") or text.startswith("INITIALIZED"):',
        '        continue',
        '    if not any(got):',
        '        continue',
        '    sig = got',
        '    break',
        'print(binascii.hexlify(bytes(sig or b"")).decode())',
        'ok.close()',
      ].join('\n')], {
        digits: pqc.challengeDigitsFor(primed), timeoutMs: 90000, signal,
      });

      assert.equal(signed.code, 0, `the device would not sign: ${signed.stderr}`);
      const hex = (signed.stdout.trim().split('\n').pop() || '').trim();
      assert.match(hex, /^[0-9a-f]{128}$/, `not a 64-byte signature: ${hex.slice(0, 80)}`);

      /*
       * Verified against the Ed25519 public half derived from the blob this test
       * packed - which is the material the FILE carries. A bridge that read the
       * primary and subkey the wrong way round would produce a perfectly valid
       * signature that fails here, which is the transposition 03-gui/06 warns
       * about arriving from a different direction.
       */
      const { ed25519 } = require('@noble/curves/ed25519.js');
      const expected = Buffer.from(ed25519.getPublicKey(key.blob.subarray(0, 32)));
      assert.ok(ed25519.verify(Buffer.from(hex, 'hex'), digest, expected),
        'the signature does not verify against the key in the file - the bridge and the ' +
        'web app disagree about what that file contains');
    });

  it('`loadkey` parses a classic RSA key file into the slots onlykey-pgp.js expects',
    async ({ device, assert, signal, log, skip }) => {
      needCli({ skip });

      /*
       * SURFACE: vendor throughout - the load, both acknowledgements and both
       * moduli, so this whole test survives into a production walk.
       *
       * `loadkey` prompts for the passphrase with prompt_toolkit, which drives
       * from a pipe: it warns and redraws oddly in captured output but the value
       * arrives intact, so `input:` is enough and no pty is needed (13-cli-lifecycle).
       */
      const key = await rsaKeyFile('classic-rsa.asc');
      log(`rsa key file ${key.file}, primary n ${key.primaryN.length} bytes`);

      /* Known state rather than inherited - see the first test. */
      await pqc.readyForKeygen(device, { signal });

      const result = await cli.run('onlykey-cli', ['loadkey', key.file, 'auto'], {
        timeoutMs: 120000, signal, input: `${PASSPHRASE}\n`,
      });
      const output = `${result.stdout}${result.stderr}`;
      log(`loadkey said ${JSON.stringify(result.stdout.trim().slice(-200))}`);
      assert.ok(!/Error loading key/.test(output),
        `loadkey could not read the file: ${output.slice(0, 300)}`);
      assert.match(output, /Found \d+ key\(s\)/,
        'loadkey did not report what it parsed out of the file');

      /* OKGETPUBKEY is REFUSED in config mode - it prints to the console and
       * sends no vendor reply at all - so the readback needs a reboot first
       * (12-cli-slots). */
      await device.restart({ signal });
      await device.ensureUnlocked(PINS.primary, { signal });

      for (const [slot, expected, what] of [
        [SLOT_DECRYPT, key.subN, 'the encryption subkey'],
        [SLOT_SIGN, key.primaryN, 'the signing key'],
      ]) {
        const since = device.mark(IFACE.VENDOR);
        device.sendVendor({ msg: okmsg.MSG.OKGETPUBKEY, slot, field: 0 });
        const published = await collectVendor(device, since, RSA_2048_BYTES, { signal });
        log(`slot ${slot} published ${published.length} bytes`);
        assert.bytes(published, expected,
          `RSA slot ${slot} does not hold ${what} - loadkey's auto assignment and ` +
          'onlykey-pgp.js\'s slotid() disagree, so the pages would use the wrong half');
      }
    });

  it('`loadkey` refuses a composite key by name, and says which command to use',
    async ({ device, assert, signal, log, skip }) => {
      needCli({ skip });

      /*
       * SURFACE: vendor - the assertion is the silence, so it is measured on
       * reports rather than on the console, which chatters on its own in a DEBUG
       * build (12-cli-slots).
       *
       * The one refusal worth driving with a REAL file rather than a missing
       * one: `loadkey` parses the file successfully and then rejects what it
       * found, which is a completely different branch from "cannot open". A
       * composite key in an RSA slot through the wrong path would store 160
       * bytes the firmware reads as P||Q, and the failure would surface much
       * later as a key that signs nonsense.
       */
      const key = await compositeKeyFile('composite-for-loadkey.asc');
      /* The idempotent form: this test needs an unlocked device and does not
       * care how it got there, and config mode would change nothing here. */
      await device.ensureUnlocked(PINS.primary, { signal });

      const since = device.mark(IFACE.VENDOR);
      const result = await cli.run('onlykey-cli', ['loadkey', key.file, 'auto'], {
        timeoutMs: 120000, signal, input: '\n',
      });
      await device.sleep(700, { signal });

      const output = `${result.stdout}${result.stderr}`;
      log(`loadkey said ${JSON.stringify(output.trim().slice(-200))}`);
      assert.includes(output, 'composite PQC PGP key',
        `loadkey did not name the reason it refused: ${output.slice(0, 300)}`);
      assert.includes(output, 'loadpqc',
        'the refusal does not say which command to use instead, which is the only ' +
        'part of it a person can act on');
      assert.equal(device.reportsSince(IFACE.VENDOR, since).filter(ANSWER).length, 0,
        'loadkey sent a composite key to the device before rejecting it');
    });
});
