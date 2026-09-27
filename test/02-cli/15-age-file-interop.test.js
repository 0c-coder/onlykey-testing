/*
 * The web app's age container, against the real `age` binary - both directions.
 *
 * `03-gui/04-age-file` proves the web app WRITES a correct age v1 container: it
 * checks the chunk boundary, the last-chunk flag and what the header MAC
 * covers, against its own reading. That is the part a round trip cannot see,
 * and it is worth having - but it is still one implementation agreeing with
 * itself. An implementation that is wrong in the same way twice encrypts and
 * decrypts its own files perfectly forever; what breaks is interoperability.
 *
 * So this is the other side, and it is deliberately BOTH directions, because
 * only one of them is the row TODO asked for and the pair is worth more than
 * either:
 *
 *   real age writes  ->  age_file.js reads     the row
 *   age_file.js writes  ->  real age reads     the complement
 *
 * A reader and a writer can be wrong in opposite ways and still pass one
 * direction each; passing both against a third party is what says the format is
 * right rather than merely self-consistent.
 *
 * WHY SECTION 2. The real `age` binary reaches an OnlyKey recipient through
 * `age-plugin-onlykey`, which finds the device through hidapi - so this needs a
 * kernel device node and can never run on a hosted runner. That is
 * `client-access`, exactly as for the rest of section 2.
 *
 * THE DEVICE HALF IS DONE OVER RAW HID, not through the tunnel, and that is
 * what keeps this file cheap. Derived decapsulation asks for confirmation by
 * default (field 30 = press), so every decapsulation here runs with field 30
 * set to "none" - the unattended-agent setting, honoured on every build for
 * slot 128 - and the default is put back after each. The PRIMED counts check
 * that no challenge was primed while it was set.
 *
 * The wire, since device custody (2026-09). The kit sends the decapsulation
 * itself; the recipient is read through the plugin, because the kit's
 * in-process capture reorders a 19-report answer (see deriveRecipient):
 *
 *   OKGETPUBKEY slot 128, buffer[6] = KEYTYPE_XWING, tag(32)
 *                 -> [ pk_M(1184) | pk_X(32) ], 19 reports
 *   OKDECRYPT   slot 128, [ tag(32) | ct(1120) ] = 1152 bytes = 20 x 57 + 12,
 *                 0xFF in buffer[6] on every report but the last
 *                 -> ss(32), the X-Wing shared secret
 *
 * This file used to receive [pk_X | mlkem_seed] and [ss_X | mlkem_seed] and do
 * the ML-KEM half host-side. The firmware stopped returning the seed - it is
 * private key material - so the device's ss is now used as is.
 *
 * SURFACES, per test - see PRODUCTION.md. Everything here is the vendor
 * interface plus host-side arithmetic; the console is read for nothing.
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
const ours = require('../../lib/age-pqc');
const webenv = require('../../lib/webenv');

/* okcore.h. 128 is RESERVED_KEY_WEB_DERIVATION; 6 is KEYTYPE_XWING. */
const WEB_DERIVATION = 128;
const KEYTYPE_XWING = 6;

/* The device's announcement that it primed a button challenge. Nothing in this
 * file may cause one - see the header. */
const PRIMED = /Encrypted Buffer/g;

const LABEL = 'age:interop';
const PLAINTEXT = 'The real age binary and the web app must agree, byte for byte.\n';

const ANSWER = (buf) => {
  const text = okmsg.text(buf);
  return !!text && text !== 'INITIALIZED';
};

/** SHA256(utf8(label)) - the convention onlykey_hid.py and the firmware share. */
const labelTag = (label) => crypto.createHash('sha256').update(label, 'utf8').digest();

describe('the web app\'s age container against the real age binary', {
  state: 'initialized',
  requires: ['crypto', 'client-access', 'xwing-math', 'webapp-lib'],
  timeoutMs: 300000,
}, () => {
  const needCli = ({ skip }) => {
    if (!cli.venvPresent()) skip(`no venv at ${cli.VENV_BIN}`);
    cli.binary('age');
    cli.binary('age-plugin-onlykey');
  };

  const ageFile = () => webenv.loadPlain('age_file.js');

  /*
   * DEVICE CUSTODY (firmware 2026-09): the device holds both halves of a derived
   * X-Wing key. It used to answer a recipient request with [pk_X | mlkem_seed]
   * and a decapsulation with ss_X, leaving the host to expand the ML-KEM half
   * and combine - which meant a public-key request returned private material.
   * Now:
   *
   *   OKGETPUBKEY  slot 128, keytype 6, tag(32)       -> [pk_M(1184) | pk_X(32)]
   *   OKDECRYPT    slot 128, [tag(32) | ct(1120)]     -> ss(32), the X-Wing secret
   *
   * so this file checks the web app's container code against the real age
   * binary with the device's own shared secret, and nothing is split host-side.
   */
  const XWING_PK = 1216;
  const XWING_CT = 1120;

  /**
   * The whole 1216-byte derived recipient for a label, read the way a real host
   * reads it: age-plugin-onlykey, over the kernel hidraw node.
   *
   * NOT from the kit's in-process vendor capture. For this 19-report answer
   * that capture comes back ROTATED - reports 9..18 then 0..8, the same every
   * time (measured 2026-09-22: the plugin's first 16 bytes sit at offset 640
   * of the capture, the capture's at 576 of the plugin's) - while the plugin,
   * reading the node, gets the stream in order, and 02-cli/07 proves its
   * recipient right by decrypting to it. The firmware sends the reports in
   * order (send_transport_response, i += 64), so the rotation is on the
   * harness side: nothing drains the gadget's hidraw node while the kit
   * captures in-process, and the device-host's back-pressure reorders what
   * the capture sees. Tracked in TODO; until then the node is the instrument.
   */
  async function deriveRecipient(device, label, { signal }) {
    const r = await cli.run('age-plugin-onlykey',
      ['--derived', '--label', label, '--recipient'], { timeoutMs: 30000, signal });
    if (r.code !== 0) throw new Error(`age-plugin-onlykey --recipient failed: ${r.stderr}`);
    const pk = Buffer.from(ours.decodeRecipient(r.stdout.trim()));
    if (pk.length !== XWING_PK) throw new Error(`derived recipient decoded to ${pk.length} bytes, not ${XWING_PK}`);
    return pk;
  }

  /**
   * The X-Wing shared secret for a label and a stanza ciphertext, over the
   * chunked derived branch: [tag | ct] = 1152 bytes = 20 x 57 + 12, 0xFF in
   * buffer[6] meaning "more coming" and the real count on the last report.
   * Run it under withoutPress(): decapsulation asks for confirmation by default.
   */
  async function deriveDecap(device, label, ciphertext, { signal }) {
    if (ciphertext.length !== XWING_CT) throw new Error(`stanza ciphertext is ${ciphertext.length} bytes, not ${XWING_CT}`);
    const payload = Buffer.concat([labelTag(label), Buffer.from(ciphertext)]);
    const since = device.mark(IFACE.VENDOR);
    for (let off = 0; off < payload.length; off += 57) {
      const part = payload.subarray(off, off + 57);
      const last = off + 57 >= payload.length;
      device.sendVendor({
        msg: okmsg.MSG.OKDECRYPT, slot: WEB_DERIVATION,
        field: last ? part.length : 0xFF, payload: part,
      });
    }
    const reply = await device.waitHid(IFACE.VENDOR, { since, match: ANSWER, timeoutMs: 15000, signal });
    const said = okmsg.text(reply);
    if (/^Error|^Timeout/.test(said)) throw new Error(`derived decaps refused: ${said}`);
    return reply.subarray(0, 32);
  }

  /* Field 30 (slot 128's user input mode), so decapsulation runs unattended
   * here; the default (press) is put back afterwards. */
  const FIELD_WEB_AGENT_DERIVE_MODE = 30;
  async function setDeriveMode(device, value, { signal }) {
    await pqc.readyForKeygen(device, { signal });
    const since = device.mark(IFACE.VENDOR);
    device.sendVendor({
      msg: okmsg.MSG.OKSETSLOT, slot: 1, field: FIELD_WEB_AGENT_DERIVE_MODE,
      payload: Buffer.from([value]),
    });
    const ack = await device.waitHid(IFACE.VENDOR, { since, match: /Success|Error/, timeoutMs: 8000, signal });
    await device.restart({ signal });
    await device.ensureUnlocked(PINS.primary, { signal });
    return okmsg.text(ack).trim();
  }
  async function withoutPress(device, work, { signal }) {
    const set = await setDeriveMode(device, 2, { signal });
    if (!/^Success/.test(set)) throw new Error(`setting field 30 to no-press: ${set}`);
    try {
      return await work();
    } finally {
      await setDeriveMode(device, 1, { signal });
    }
  }

  /** A working directory that a failure leaves behind as evidence. */
  const workdir = () => fs.mkdtempSync(path.join(os.tmpdir(), 'okt-agefile-'));

  it('the real age binary encrypts to a recipient the device derived',
    async ({ device, assert, signal, log, skip }) => {
      needCli({ skip });
      await device.ensureUnlocked(PINS.primary, { signal });

      /*
       * SURFACE: vendor - survives into a production walk.
       *
       * The precondition for everything below, and an assertion in its own
       * right: the recipient this kit builds from the device's two halves has
       * to be the one the PLUGIN builds for the same label, or the two sides
       * are deriving different keys and every later failure would be blamed on
       * the container format instead.
       */
      const primed = device.log.count(PRIMED);

      const pk = await deriveRecipient(device, LABEL, { signal });
      const recipient = ours.encodeRecipient(pk);
      log(`device derives ${recipient.slice(0, 40)}...`);

      /* The kit no longer builds a recipient of its own - the device holds both
       * halves - so "kit and plugin agree" became "the device answers the same
       * recipient twice", and the round trips below are what prove it right. */
      const again = ours.encodeRecipient(await deriveRecipient(device, LABEL, { signal }));
      assert.equal(recipient, again, 'the device derived two different recipients for one label');

      const dir = workdir();
      fs.writeFileSync(path.join(dir, 'plain.txt'), PLAINTEXT);
      const sealed = path.join(dir, 'real.age');

      const enc = await pqc.encrypt(recipient, path.join(dir, 'plain.txt'), sealed, { signal });
      assert.equal(enc.code, 0, `age encrypt failed: ${enc.stderr}`);

      const bytes = fs.readFileSync(sealed);
      assert.includes(bytes.toString('latin1'), 'age-encryption.org/v1',
        'the real binary did not write an age v1 header');
      assert.includes(bytes.toString('latin1'), 'mlkem768x25519',
        'the real binary did not write an X-Wing stanza');

      assert.equal(device.log.count(PRIMED), primed,
        'the derived path primed a button challenge - it has no CRYPTO_AUTH gate');
      fs.rmSync(dir, { recursive: true, force: true });
    });

  it('the web app\'s parser opens a container the real age binary wrote',
    async ({ device, assert, signal, log, skip }) => {
      needCli({ skip });
      await device.ensureUnlocked(PINS.primary, { signal });

      /*
       * SURFACE: vendor - survives into a production walk.
       *
       * THE ROW. Every byte of this container was produced by the real `age`
       * binary - its header, its stanza wrapping, its 16-byte STREAM nonce and
       * its chunked body - and it is opened by age_file.js, which shares no code
       * with it. The device contributes exactly one value, ss_X, and the
       * ML-KEM half is finished on the host, which is the split-custody design.
       *
       * `decryptAgeFile` takes the shared secret through a callback, which is
       * how the real page supplies it too - so standing in for the page here is
       * the interface rather than a shortcut.
       */
      const primed = device.log.count(PRIMED);
      const dir = workdir();

      try {
        const pk = await deriveRecipient(device, LABEL, { signal });
        const recipient = ours.encodeRecipient(pk);

        fs.writeFileSync(path.join(dir, 'plain.txt'), PLAINTEXT);
        const sealed = path.join(dir, 'real.age');
        const enc = await pqc.encrypt(recipient, path.join(dir, 'plain.txt'), sealed, { signal });
        assert.equal(enc.code, 0, `age encrypt failed: ${enc.stderr}`);

        const fileBytes = fs.readFileSync(sealed);
        const ciphertext = pqc.xwingCiphertextOf(sealed);
        log(`stanza ciphertext ${ciphertext.length} bytes`);

        /* The one device call, and the only 32 bytes of the ciphertext it sees. */
        const shared = await withoutPress(device,
          () => deriveDecap(device, LABEL, ciphertext, { signal }), { signal });

        const opened = await ageFile().decryptAgeFile(new Uint8Array(fileBytes), async () => shared);
        assert.bytes(Buffer.from(opened), Buffer.from(PLAINTEXT),
          'the web app opened the real binary\'s file and got different bytes');

        assert.equal(device.log.count(PRIMED), primed,
          'the derived decapsulation primed a button challenge');
        fs.rmSync(dir, { recursive: true, force: true });
      } catch (err) {
        log(`evidence left in ${dir}`);
        throw err;
      }
    });

  it('the real age binary opens a container the web app\'s code wrote',
    async ({ device, assert, signal, log, skip }) => {
      needCli({ skip });
      await device.ensureUnlocked(PINS.primary, { signal });

      /*
       * SURFACE: vendor - survives into a production walk.
       *
       * The complement, and the harder direction: a reader is forgiving in ways
       * a writer cannot be. Here age_file.js produces the whole container and
       * the real binary has to accept all of it - the armor, the stanza
       * wrapping, the header MAC and the STREAM framing - with the device doing
       * the decapsulation through the plugin, exactly as a user would.
       *
       * The encapsulation is done HOST-SIDE with no device at all, which is not
       * a shortcut but the shape of the thing: X-Wing encapsulation is entirely
       * public-key, so a sender never needs the recipient's device. That is
       * what makes an age recipient useful.
       */
      const primed = device.log.count(PRIMED);
      const dir = workdir();

      try {
        const pk = await deriveRecipient(device, LABEL, { signal });

        /* The sender's side, with nothing plugged in. */
        const { ciphertext, sharedSecret } = ours.xwingEncapsHost(pk);
        const container = ageFile().encryptAgeFile(
          new TextEncoder().encode(PLAINTEXT), { ciphertext, sharedSecret });

        const sealed = path.join(dir, 'webapp.age');
        fs.writeFileSync(sealed, Buffer.from(container));
        log(`the web app wrote ${container.length} bytes`);

        /* The identity is the label in an envelope - no device involved in
         * making it, which 07-derived-xwing asserts separately. */
        const ident = await cli.run('age-plugin-onlykey',
          ['--derived', '--label', LABEL, '--identity'], { timeoutMs: 30000, signal });
        assert.equal(ident.code, 0, `--identity failed: ${ident.stderr}`);
        const identity = ident.stdout.split('\n').find((l) => l.startsWith('AGE-PLUGIN-ONLYKEY-1'));
        assert.ok(identity, 'no derived identity came back');
        fs.writeFileSync(path.join(dir, 'identity.txt'), `${identity.trim()}\n`);

        const out = path.join(dir, 'opened.txt');
        const dec = await withoutPress(device, () => cli.run('age',
          ['-d', '-i', path.join(dir, 'identity.txt'), '-o', out, sealed],
          { timeoutMs: 90000, signal, env: { PATH: `${cli.VENV_BIN}:${process.env.PATH}` } }),
        { signal });

        assert.equal(dec.code, 0,
          `the real age binary refused the web app's container: ${dec.stderr.slice(-400)}`);
        assert.bytes(fs.readFileSync(out), Buffer.from(PLAINTEXT),
          'the real binary opened the web app\'s file and got different bytes');

        assert.equal(device.log.count(PRIMED), primed, 'a challenge was primed');
        fs.rmSync(dir, { recursive: true, force: true });
      } catch (err) {
        log(`evidence left in ${dir}`);
        throw err;
      }
    });

  it('a real container fails by the right KIND for each thing tampered with',
    async ({ device, assert, signal, log, skip }) => {
      needCli({ skip });
      await device.ensureUnlocked(PINS.primary, { signal });

      /*
       * SURFACE: vendor - survives into a production walk.
       *
       * 04-age-file separates these failure KINDS on containers the web app wrote
       * itself. Doing it on a container the REAL binary wrote is the part that
       * could not be checked there, and the distinction matters: it tells
       * somebody which half of the file to go and look at.
       *
       * TWO TAMPERS, because the first version of this test used one and had the
       * wrong model of the format. Corrupting the stanza BODY does not reach the
       * MAC check at all - the body is the HPKE-sealed file key, so it fails
       * inside openFileKey() as an AEAD tag, and it fails there FIRST because
       * the MAC cannot even be computed until the file key has been recovered.
       * That ordering is correct and is now asserted rather than assumed.
       *
       * To reach the MAC check the file key has to survive, so the second tamper
       * edits the MAC line itself - the one part of the header that is not
       * covered by the value it carries.
       */
      const dir = workdir();

      try {
        const pk = await deriveRecipient(device, LABEL, { signal });
        const recipient = ours.encodeRecipient(pk);

        fs.writeFileSync(path.join(dir, 'plain.txt'), PLAINTEXT);
        const sealed = path.join(dir, 'real.age');
        const enc = await pqc.encrypt(recipient, path.join(dir, 'plain.txt'), sealed, { signal });
        assert.equal(enc.code, 0, `age encrypt failed: ${enc.stderr}`);

        const fileBytes = fs.readFileSync(sealed);
        const ciphertext = pqc.xwingCiphertextOf(sealed);
        const shared = await withoutPress(device,
          () => deriveDecap(device, LABEL, ciphertext, { signal }), { signal });

        /* Untouched, it opens - so the tamper below is the only variable. */
        const lib = ageFile();
        await lib.decryptAgeFile(new Uint8Array(fileBytes), async () => shared);

        const lines = fileBytes.toString('latin1').split('\n');
        const flip = (line) => (line[4] === 'A' ? 'B' : 'A') + line.slice(1).replace(/^(.{3})./, '$1x');

        const reject = async (bytes, what) => {
          let failure = null;
          try {
            await lib.decryptAgeFile(new Uint8Array(bytes), async () => shared);
          } catch (err) {
            failure = err;
          }
          assert.ok(failure, `${what} opened anyway`);
          log(`${what} reported: ${failure.message}`);
          return failure.message;
        };

        /*
         * The sealed file key, on the line after the stanza header. It never
         * reaches the MAC: HPKE fails to open it first.
         */
        const stanzaAt = lines.findIndex((l) => l.startsWith('-> mlkem768x25519'));
        assert.ok(stanzaAt >= 0, 'no X-Wing stanza line to tamper with');

        const bodyEdit = [...lines];
        const body = bodyEdit[stanzaAt + 1];
        bodyEdit[stanzaAt + 1] = (body[0] === 'A' ? 'B' : 'A') + body.slice(1);

        const bodyFailure = await reject(Buffer.from(bodyEdit.join('\n'), 'latin1'),
          'a corrupted sealed file key');
        assert.match(bodyFailure, /tag|decrypt|open/i,
          `expected an AEAD failure for a corrupted file key, got ${JSON.stringify(bodyFailure)}`);
        assert.ok(!/MAC/i.test(bodyFailure),
          'a corrupted file key was reported as a header MAC failure - it never gets that far');

        /*
         * The MAC line itself, which is the only edit that leaves the file key
         * recoverable and the header no longer vouched for.
         */
        const macAt = lines.findIndex((l) => l.startsWith('--- '));
        assert.ok(macAt >= 0, 'no MAC line in the header');

        const macEdit = [...lines];
        const mac = macEdit[macAt];
        macEdit[macAt] = `--- ${mac[4] === 'A' ? 'B' : 'A'}${mac.slice(5)}`;

        const macFailure = await reject(Buffer.from(macEdit.join('\n'), 'latin1'),
          'a tampered header MAC');
        assert.match(macFailure, /MAC/i,
          `expected a header MAC failure, got ${JSON.stringify(macFailure)}`);

        fs.rmSync(dir, { recursive: true, force: true });
      } catch (err) {
        log(`evidence left in ${dir}`);
        throw err;
      }
    });
});
