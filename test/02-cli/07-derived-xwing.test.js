/*
 * TC-16/17: the derived X-Wing path from the command line - no slot, no button.
 *
 * `03-pqc-decrypt` proves the STORED model: a key generated into slot 101, kept
 * there, and used. This is the other model the plugin supports. Nothing is
 * stored at all - the key is reproduced on demand from (the device's web
 * derivation key, a label) with no origin in it (seed/v3) - and it is the same
 * key the web app's age-derive page produces on any origin, which is what makes
 * CLI and browser interoperable rather than merely similar.
 *
 * `03-gui/03-xwing-derive` already proves this maths against the device over
 * the CTAP2 vendor bridge. This is the same firmware arithmetic reached the
 * other way: raw HID, `OKGETPUBKEY`/`OKDECRYPT` with
 * `RESERVED_KEY_WEB_DERIVATION`. Two transports into one derivation, which is
 * the arrangement that catches a transport-shaped bug - and there was one here.
 * `okcrypto_decrypt()`'s dispatch used to require `(buffer[6] & 0x0F) ==
 * KEYTYPE_XWING`, but this request is 64 bytes over a 57-byte report, so
 * buffer[6] carries a continuation marker instead of a keytype and the check
 * matched neither chunk. Both fell through to slot dispatch, ran the wrong
 * decapsulation on a stale type, and returned a shared secret that never
 * matched - with no error anywhere. That is what this file is standing guard
 * over, and it is invisible to anything that only checks exit codes.
 *
 * TWO THINGS ARE ASSERTED RATHER THAN ASSUMED, and both are the point:
 *
 *   - NO BUTTON PRESS. This branch has no CRYPTO_AUTH gate, so none of
 *     lib/pqc.js's challenge machinery is involved. Rather than demonstrate
 *     that by not calling it, the tests count the device's own priming marker
 *     and require it not to move. A firmware change that started demanding a
 *     confirmation here would otherwise show up as this file timing out, which
 *     names nothing.
 *   - NO DEVICE for the identity. `cmd_identity_derived()` is pure local
 *     encoding - it is the label in an envelope, not a key - so it must work
 *     with the device doing nothing at all.
 *
 * No `derivedkeymode` setup either, and that is a real difference from
 * `03-gui/02-derive` rather than an omission: bit 3 is checked in
 * `fido2/ok_extension.cpp`, on the tunnelled path only. The raw-HID branch in
 * `okcrypto.cpp` has no such gate.
 */
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');

const { describe, it } = require('../../lib/harness');
const { PINS } = require('../../lib/config');
const cli = require('../../lib/cli');
const pqc = require('../../lib/pqc');
const { IFACE, okmsg } = require('../../lib/device');

/* Field 30, the user input mode for slot 128 (web-and-agent derived keys) on
 * both transports. Press is the default; "none" is honoured on every build for
 * this slot - it is the unattended-agent setting. */
const FIELD_WEB_AGENT_DERIVE_MODE = 30;
const USER_INPUT_PRESS = 1;
const USER_INPUT_NONE = 2;

/** Write field 30 in config mode, leave config mode, and return the answer. */
async function setDeriveMode(device, value, { signal }) {
  await pqc.readyForKeygen(device, { signal });
  const since = device.mark(IFACE.VENDOR);
  device.sendVendor({
    msg: okmsg.MSG.OKSETSLOT, slot: 1, field: FIELD_WEB_AGENT_DERIVE_MODE,
    payload: Buffer.from([value]),
  });
  const ack = await device.waitHid(IFACE.VENDOR,
    { since, match: /Success|Error/, timeoutMs: 8000, signal });
  const said = okmsg.text(ack).trim();
  await device.restart({ signal });
  await device.ensureUnlocked(PINS.primary, { signal });
  return said;
}

/** Run `work` with field 30 set to no-press, and put the default back. */
async function withoutPress(device, assert, work, { signal }) {
  const set = await setDeriveMode(device, USER_INPUT_NONE, { signal });
  assert.match(set, /^Success/, `setting field 30 to no-press: ${set}`);
  try {
    return await work();
  } finally {
    await setDeriveMode(device, USER_INPUT_PRESS, { signal });
  }
}

/* The device's own announcement that it has primed a confirmation challenge -
 * the same marker 03-pqc-decrypt watches. Nothing here may cause it. */
const PRIMED = /Encrypted Buffer/g;

const LABEL = 'age:personal';
const OTHER = 'age:work';

describe('derived X-Wing from the command line', {
  state: 'initialized',
  requires: ['crypto', 'client-access'],
  timeoutMs: 240000,
}, () => {
  let dir = null;
  let recipient = null;
  let identity = null;

  const at = (name) => path.join(dir, name);

  /** `age-plugin-onlykey --derived --label <label> <mode>`. */
  const derived = (label, mode, opts) => cli.run('age-plugin-onlykey',
    ['--derived', '--label', label, mode], { timeoutMs: 30000, ...opts });

  it('derives a recipient for a label, and the same one twice',
    async ({ device, assert, signal, log }) => {
      if (!cli.venvPresent()) throw new Error(`no venv at ${cli.VENV_BIN}`);

      dir = fs.mkdtempSync(path.join(os.tmpdir(), 'okt-tc16-'));
      fs.writeFileSync(at('plaintext.txt'),
        'TC-17: derived, reproduced on demand, never stored.\n');
      log(`working in ${dir}`);

      await device.unlock(PINS.primary, { signal });
      const primed = device.log.count(PRIMED);

      const first = await derived(LABEL, '--recipient', { signal });
      assert.equal(first.code, 0, `--derived --recipient failed: ${first.stderr}`);

      recipient = first.stdout.trim();
      assert.match(recipient, /^age1onlykey1[a-z0-9]+$/,
        `not an age recipient: ${JSON.stringify(recipient.slice(0, 60))}`);

      /*
       * Determinism is the whole claim of a derived key. If the same label gave
       * two answers there would be nothing to encrypt to - the recipient handed
       * out yesterday would not be the one the device reproduces today, and the
       * failure would arrive much later as "no identity matched any of the
       * recipients".
       */
      const again = await derived(LABEL, '--recipient', { signal });
      assert.equal(again.code, 0, `the second --recipient failed: ${again.stderr}`);
      assert.equal(again.stdout.trim(), recipient,
        'the same label derived two different recipients');

      assert.equal(device.log.count(PRIMED), primed,
        'deriving a recipient primed a button challenge - this branch has no CRYPTO_AUTH gate');
    });

  it('derives a different recipient for a different label',
    async ({ device, assert, signal }) => {
      /*
       * The other half of determinism, and not a formality: the label is hashed
       * into a 32-byte tag before it reaches the device, so a derivation that
       * ignored the tag entirely would pass the test above perfectly and fail
       * this one. Together they say the label is both honoured and sufficient.
       */
      const primed = device.log.count(PRIMED);

      const other = await derived(OTHER, '--recipient', { signal });
      assert.equal(other.code, 0, `--recipient for ${OTHER} failed: ${other.stderr}`);

      assert.notEqual(other.stdout.trim(), recipient,
        `${OTHER} and ${LABEL} derived the same recipient`);
      assert.equal(device.log.count(PRIMED), primed, 'a challenge was primed');
    });

  it('encodes the identity locally, with the device untouched',
    async ({ device, assert, signal }) => {
      /*
       * A derived identity is not a key and does not come from the device - it
       * is the label in an envelope, so `age` knows which plugin to run and
       * what to ask it for. Asserting the device stayed silent is what makes
       * that a fact about the design rather than a description of one run.
       *
       * The prefix is `AGE-PLUGIN-ONLYKEY-1`, the SAME one a slot identity
       * uses, and deliberately so: `age` chooses the plugin executable from
       * that literal text, so a tidier prefix would send it looking for an
       * `age-plugin-onlykey-derived` binary that does not exist. Slot and
       * derived are told apart by a marker byte inside the decoded payload.
       */
      const before = device.log.text.length;

      const result = await derived(LABEL, '--identity', { signal });
      assert.equal(result.code, 0, `--derived --identity failed: ${result.stderr}`);

      identity = result.stdout.split('\n').find((l) => l.startsWith('AGE-PLUGIN-ONLYKEY-1'));
      assert.ok(identity, `no identity line in: ${JSON.stringify(result.stdout.slice(0, 120))}`);
      identity = identity.trim();
      assert.match(identity, /^AGE-PLUGIN-ONLYKEY-1[A-Z0-9]+$/, `malformed identity: ${identity}`);

      const twice = await derived(LABEL, '--identity', { signal });
      assert.equal(twice.stdout.split('\n').find((l) => l.startsWith('AGE-PLUGIN-ONLYKEY-1')).trim(),
        identity, 'the same label encoded two different identities');

      assert.equal(device.log.text.length, before,
        'the device said something while an identity was being encoded locally');

      fs.writeFileSync(at('identity.txt'), `${identity}\n`);
    });

  it('encrypts to the derived recipient with no device at all',
    async ({ assert, signal }) => {
      /* Same asymmetry as the stored path: X-Wing encapsulation is entirely
       * public-key, so this half would work with the key unplugged. */
      const result = await pqc.encrypt(recipient, at('plaintext.txt'), at('secret.age'), { signal });

      assert.equal(result.code, 0, `age encrypt failed: ${result.stderr}`);
      assert.ok(fs.existsSync(at('secret.age')), 'age produced no output file');
    });

  it('decrypts it on the device, byte for byte and without a press',
    async ({ device, assert, signal }) => {
      /*
       * The whole round trip closes here, and it is deliberately run WITHOUT
       * any challenge answering: `age` is spawned raw rather than through
       * pqc.decrypt(). Derived decapsulation asks for confirmation by default
       * (field 30 = press, since the 2026-09 firmware), so this runs with field
       * 30 set to "none" - the unattended-agent setting, honoured on every
       * build for slot 128 - and puts the default back afterwards. Under the
       * default the plugin prints the prompt and the device answers "Timeout
       * occured while waiting for confirmation" after 20 s (measured
       * 2026-09-22), which is the design, not a failure of the round trip.
       *
       * The byte comparison is what proves the derivation reproduced the same
       * key the recipient was built from. The decapsulation request is the
       * chunked one: [label32 | ct 1120] = 1152 bytes = 20 x 57 + 12. A shared
       * secret that comes back wrong rather than absent is the signature of a
       * framing bug, and it presents as `age` failing with "no identity
       * matched any of the recipients" - which blames the identity file.
       */
      const primed = device.log.count(PRIMED);

      const result = await withoutPress(device, assert, () => cli.run('age',
        ['-d', '-i', at('identity.txt'), '-o', at('decrypted.txt'), at('secret.age')],
        { timeoutMs: 90000, signal, env: { PATH: `${cli.VENV_BIN}:${process.env.PATH}` } }),
      { signal });

      assert.equal(result.code, 0, `age -d exited ${result.code}: ${result.stderr}`);
      assert.ok(fs.existsSync(at('decrypted.txt')), 'age -d produced no output file');

      assert.bytes(
        fs.readFileSync(at('decrypted.txt')),
        fs.readFileSync(at('plaintext.txt')),
        'the decrypted file'
      );

      assert.equal(device.log.count(PRIMED), primed,
        'a derived decapsulation primed a button challenge');
    });

  it('will not decrypt with a different label\'s identity',
    async ({ device, assert, signal }) => {
      /*
       * The device really is deriving from the label. Without this, everything
       * above holds equally for a firmware that ignored the tag and returned
       * one key for every label - the round trip would still close, because
       * both ends would be wrong in the same way.
       */
      const other = await derived(OTHER, '--identity', { signal });
      assert.equal(other.code, 0, `--identity for ${OTHER} failed: ${other.stderr}`);
      fs.writeFileSync(at('other-identity.txt'),
        `${other.stdout.split('\n').find((l) => l.startsWith('AGE-PLUGIN-ONLYKEY-1')).trim()}\n`);

      /* Without a press too, so a refusal here is the wrong key failing to
       * decapsulate and not a confirmation nobody gave timing out. */
      const result = await withoutPress(device, assert, () => cli.run('age',
        ['-d', '-i', at('other-identity.txt'), '-o', at('nope.txt'), at('secret.age')],
        { timeoutMs: 90000, signal, env: { PATH: `${cli.VENV_BIN}:${process.env.PATH}` } }),
      { signal });

      assert.notEqual(result.code, 0, `age decrypted with ${OTHER}'s identity`);
      assert.ok(!fs.existsSync(at('nope.txt')), 'age wrote output for a decryption that failed');
    });

  it('cleans up after itself', async ({ assert }) => {
    /* Visible, not a hook - and a failure above leaves the directory behind on
     * purpose, because the age file that would not open is the evidence. */
    fs.rmSync(dir, { recursive: true, force: true });
    assert.ok(!fs.existsSync(dir), `${dir} is still there`);
  });
});
