/*
 * TC-05: encrypt on the host, decrypt on the device, get the file back.
 *
 * The end-to-end claim the other PQC tests only approach: real `age`, a real
 * age file, the real plugin, and a device that holds half the secret. Encryption
 * is host-only - X-Wing encapsulation needs nothing but the public key - so only
 * the decrypt half touches the device, and only it needs a button.
 *
 * This is also what the two keygen bugs actually cost. A device that stored a
 * different key from the one it reported, and a --generate whose recipient was a
 * status message with a key stapled to it, both produce exactly one symptom
 * here: "no identity matched any of the recipients". So this file is the proof
 * that libraries@83353cf fixed something real, in the only terms that matter -
 * a file encrypted to this key can be read back.
 *
 * Ordering is deliberate and the tests share state: generate, publish, encrypt,
 * decrypt, and only then clean up. A failure leaves the temp directory behind,
 * which is a feature - the age file that would not decrypt is the evidence.
 */
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');

const { describe, it } = require('../../lib/harness');
const { PINS } = require('../../lib/config');
const cli = require('../../lib/cli');
const pqc = require('../../lib/pqc');

const SLOT = 101;

describe('age round trip through the device',
  { state: 'initialized', requires: ['crypto', 'client-access'], timeoutMs: 240000 }, () => {
    let dir = null;
    let recipient = null;

    const at = (name) => path.join(dir, name);

    it('generates the key the file will be encrypted to',
      async ({ device, assert, signal, log }) => {
        if (!cli.venvPresent()) throw new Error(`no venv at ${cli.VENV_BIN}`);

        dir = fs.mkdtempSync(path.join(os.tmpdir(), 'okt-tc05-'));
        fs.writeFileSync(at('plaintext.txt'),
          'TC-05: encrypted on the host, decrypted on the device.\n');

        const result = await pqc.generate(device, ['--generate', '--slot', String(SLOT)], { signal });
        assert.equal(result.code, 0, `--generate failed: ${result.stderr}`);

        recipient = pqc.parseGenerated(result).recipient;
        assert.ok(recipient, `no recipient printed: ${JSON.stringify(result.stderr)}`);
        log(`working in ${dir}`);
      });

    it('publishes the identity and the recipient', async ({ device, assert, signal }) => {
      /*
       * Two different things, and the difference matters. The identity is just
       * the slot number encoded - encode_identity() never opens the device - so
       * it says WHERE to look, not what is there. The recipient is the public
       * key, and reading it needs the device, unlocked and out of config mode.
       */
      await device.restart({ signal });
      await device.unlock(PINS.primary, { signal });

      const identity = await cli.run('age-plugin-onlykey',
        ['--identity', '--slot', String(SLOT)], { timeoutMs: 30000, signal });
      assert.equal(identity.code, 0, `--identity failed: ${identity.stderr}`);
      fs.writeFileSync(at('identity.txt'), identity.stdout);

      const read = await cli.run('age-plugin-onlykey',
        ['--recipient', '--slot', String(SLOT)], { timeoutMs: 30000, signal });
      assert.equal(read.code, 0, `--recipient failed: ${read.stderr}`);

      /*
       * The same assertion 01-pqc-keygen makes, kept here because this file
       * would otherwise fail two tests later with "no identity matched any of
       * the recipients", which names neither the key nor the cause.
       */
      assert.equal(pqc.parseGenerated(read).recipient, recipient,
        'the slot holds a different key from the one --generate reported');
    });

    it('encrypts to it without the device', async ({ assert, signal }) => {
      /*
       * No press, no unlock, and it would work with the key unplugged: X-Wing
       * encapsulation is entirely public-key. That asymmetry is the point of
       * the scheme, so it is worth one assertion rather than an assumption.
       */
      const result = await pqc.encrypt(recipient, at('plaintext.txt'), at('secret.age'), { signal });

      assert.equal(result.code, 0, `age encrypt failed: ${result.stderr}`);
      assert.ok(fs.existsSync(at('secret.age')), 'age produced no output file');

      const ct = pqc.xwingCiphertextOf(at('secret.age'));
      assert.equal(ct.length, pqc.XWING_CT_SIZE,
        'the stanza does not carry a full X-Wing ciphertext');
    });

    it('decrypts it on the device, byte for byte', async ({ device, assert, signal }) => {
      const result = await pqc.decrypt(device, {
        ageFile: at('secret.age'),
        identityFile: at('identity.txt'),
        output: at('decrypted.txt'),
      }, { signal });

      assert.equal(result.code, 0, `age -d exited ${result.code}: ${result.stderr}`);
      assert.ok(fs.existsSync(at('decrypted.txt')), 'age -d produced no output file');

      assert.bytes(
        fs.readFileSync(at('decrypted.txt')),
        fs.readFileSync(at('plaintext.txt')),
        'the decrypted file'
      );
    });

    it('refuses a file encrypted to a key it does not have',
      async ({ device, assert, signal }) => {
        /*
         * The device really is deciding. Slot 103 has no key at all, so an
         * identity pointing at it cannot produce the shared secret however
         * willing the plugin is - and if this passed, the decrypt above would
         * not have proved that the KEY mattered, only that the machinery ran.
         *
         * No button is answered here on purpose: the request must fail before
         * anything asks for one, and a challenge primed for a slot with no key
         * would itself be worth knowing about.
         */
        const wrong = await cli.run('age-plugin-onlykey',
          ['--identity', '--slot', '103'], { timeoutMs: 30000, signal });
        assert.equal(wrong.code, 0, `--identity for slot 103 failed: ${wrong.stderr}`);
        fs.writeFileSync(at('wrong-identity.txt'), wrong.stdout);

        const primed = device.log.count(/Encrypted Buffer/g);
        const result = await cli.run('age',
          ['-d', '-i', at('wrong-identity.txt'), '-o', at('nope.txt'), at('secret.age')],
          { timeoutMs: 60000, signal, env: cli.venvPathEnv() });

        assert.notEqual(result.code, 0, 'age decrypted a file with the wrong slot');
        assert.ok(!fs.existsSync(at('nope.txt')), 'age wrote output for a decryption that failed');
        assert.equal(device.log.count(/Encrypted Buffer/g), primed,
          'the device primed a confirmation challenge for a slot with no key in it');
      });

    it('cleans up after itself', async ({ assert }) => {
      /* Visible, like everything else - a hook here would be an invisible step,
       * and a leaked temp directory is exactly what nobody notices. */
      fs.rmSync(dir, { recursive: true, force: true });
      assert.ok(!fs.existsSync(dir), `${dir} is still there`);
    });
  });
