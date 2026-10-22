/*
 * THE UPGRADE PATH, phase B: the old key's backup restored onto a key on the NEW firmware.
 *
 * Phase A (23-upgrade-source) left in OKT_UPGRADE_DIR what a key on the last signed release
 * gives - its SSH key, its GnuPG identity, a stored PGP key - and the backup it typed. This
 * restores that backup the way a user would, with the release's own `onlykey-cli restore`
 * (OKT_VENV), and checks each of them comes out the same. Upgrading a key IS this: back up,
 * load the new firmware, restore. A derived key that changes here is a user locked out of
 * every server and every message tied to it, so any difference is a firmware finding.
 *
 * Run on a hard key (--hardware): the target's own PINs are the fixture's, and the backup's
 * passphrase is set on it first, because the device decrypts a backup with ITS backup key.
 * Each CLI runs inside device.lendToClient(), so the kit and the CLI never hold the key's
 * client interfaces at the same time; the kit keeps the console for presses and challenges.
 * Writes OKT_UPGRADE_DIR/target-<firmware>-<platform>.json beside the source record.
 */
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { describe, it } = require('../../lib/harness');
const { IFACE, okmsg } = require('../../lib/device');
const { PINS } = require('../../lib/config');
const { KIT_ROOT } = require('../../lib/paths');
const cli = require('../../lib/cli');
const pqc = require('../../lib/pqc');
const webenv = require('../../lib/webenv');

const OUT = process.env.OKT_UPGRADE_DIR ? path.resolve(process.env.OKT_UPGRADE_DIR) : path.join(KIT_ROOT, 'runs', 'upgrade');
const BACKUP_KEY_TYPE = 161;
const BACKUP_KEY_SLOT = 131;
const VENV_PATH = cli.venvPathEnv();
const PLAINTEXT = 'sealed to the key the old firmware stored';

describe('upgrade path, phase B: the old key\'s backup restored onto the new firmware', {
  state: 'initialized',
  requires: ['crypto', 'client-lend', 'webapp-lib'],
  timeoutMs: 900000,
}, () => {
  let source = null;
  const record = {};
  const save = () => fs.writeFileSync(
    path.join(OUT, `target-${record.firmware || 'unknown'}-${process.platform}.json`),
    JSON.stringify(record, null, 2));

  /* The web app's own PGP engine over the device, as 03-gui/08 drives it: the pages' code, not ours. */
  async function engine(device, { signal }) {
    const { okcrypto, window, app } = await webenv.browserLib(device, { signal });
    const createPgpEngine = webenv.webappModule('onlykey-lib/pgp-engine.js');
    return createPgpEngine({
      app,
      okLib: { okcrypto: async () => okcrypto },
      getKey: (value) => Promise.resolve(value),
      window,
    });
  }
  const settle = (promise, reject) => {
    if (promise && typeof promise.catch === 'function') promise.catch(reject);
  };
  const encryptWith = (pgp, to, from, message) => new Promise((resolve, reject) => {
    settle(pgp.startEncryption(to, from, message, null, (err, data) => (
      err ? reject(new Error(String(err))) : resolve(data)
    )), reject);
  });
  const decryptWith = (pgp, signer, mine, message) => new Promise((resolve, reject) => {
    settle(pgp.startDecryption(signer, mine, message, null, (err, data) => (
      err ? reject(new Error(String(err))) : resolve(data)
    )), reject);
  });

  it('unlocks the target and records which firmware it is', async ({ device, assert, log }) => {
    const file = path.join(OUT, 'source.json');
    assert.ok(fs.existsSync(file), `run phase A first: no ${file}`);
    source = JSON.parse(fs.readFileSync(file, 'utf8'));
    for (const part of ['ssh', 'gpg', 'stored', 'backup']) assert.ok(source[part], `source.json has no ${part}`);
    const model = await device.unlock(PINS.primary);
    record.firmware = String(model).replace(/^UNLOCKED/, '');
    record.source = source.firmware;
    log(`restoring a ${source.firmware} backup onto ${record.firmware}`);
    save();
  });

  it('restores the backup with onlykey-cli restore, in config mode with the backup passphrase set',
    async ({ device, assert, log, signal }) => {
      await device.enterConfigMode(PINS.primary, { signal });
      const since = device.mark(IFACE.VENDOR);
      device.sendVendor({
        msg: okmsg.MSG.OKSETPRIV, slot: BACKUP_KEY_SLOT,
        payload: Buffer.concat([Buffer.from([BACKUP_KEY_TYPE]),
          crypto.createHash('sha256').update(source.passphrase, 'utf8').digest()]),
      });
      const reply = await device.waitHid(IFACE.VENDOR, { since, match: /Successfully|Error/, timeoutMs: 10000, signal });
      assert.match(okmsg.text(reply), /Successfully set Backup Passphrase/, 'the backup key was refused');

      /* The reboot is the device's only "done": a refused restore stays up and says so on the vendor channel. */
      const before = device.generation;
      const vendorSince = device.mark(IFACE.VENDOR);
      const r = await device.lendToClient(() => cli.run('onlykey-cli', ['restore', path.join(OUT, source.backup.file)],
        { timeoutMs: 180000, signal, env: VENV_PATH }));
      assert.equal(r.code, 0, r.stderr.slice(-800) || r.stdout.slice(-800));
      log(`cli: ${r.stdout.trim().split('\n').slice(-2).join(' | ')}`);
      try {
        await device.waitForReboot({ from: before, timeoutMs: 90000, signal });
      } catch (err) {
        const said = device.hidSince ? device.hidSince(IFACE.VENDOR, vendorSince) : null;
        throw new Error(`no reboot after the restore (${err.message})${said ? `; the key said: ${said}` : ''}`);
      }
      assert.ok(!device.fatal, 'the device died during the restore');
      record.restored = { bytes: source.backup.bytes, sha256: source.backup.sha256 };
      save();
    });

  it('comes back with the target\'s PINs', async ({ device, assert, signal }) => {
    await device.waitReady({ signal });
    const after = await device.status({ signal });
    if (after.state === 'locked') {
      assert.match(await device.unlock(PINS.primary, { signal }), /^UNLOCKED/, 'the PIN no longer works after the restore');
    }
    assert.equal((await device.status({ signal })).state, 'unlocked');
  });

  it('derives the same SSH key onlykey-agent derived on the old firmware', async ({ device, assert, log, signal }) => {
    const r = await device.lendToClient(() => cli.run('onlykey-agent', [source.ssh.identity],
      { timeoutMs: 60000, signal, env: VENV_PATH }));
    assert.equal(r.code, 0, r.stderr.slice(-800));
    const key = (r.stdout.match(/(ssh-ed25519 [A-Za-z0-9+/=]+)/) || [])[1];
    record.ssh = { identity: source.ssh.identity, key, same: key === source.ssh.key };
    save();
    log(`ssh: ${record.ssh.same ? 'same' : 'DIFFERENT'} (${String(key).slice(0, 60)}...)`);
    assert.equal(key, source.ssh.key, 'the restored key derives a different SSH key - every server it logs into is lost');
  });

  it('derives the same GnuPG identity onlykey-gpg derived on the old firmware', async ({ device, assert, log, signal }) => {
    const homedir = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'okt-upgrade-b-')), 'gnupg');
    const init = await device.lendToClient(() => pqc.confirmFromConsole(device, () => cli.run('onlykey-gpg',
      ['init', source.gpg.userId, '-t', source.gpg.time, '--homedir', homedir],
      { timeoutMs: 240000, signal, env: VENV_PATH }), { signal }));
    assert.equal(init.code, 0, init.stderr.slice(-1500) || init.stdout.slice(-1500));
    const list = await cli.runHost('gpg', ['--homedir', homedir, '--with-colons', '--list-keys'], { timeoutMs: 30000, signal });
    const fprs = list.stdout.split('\n').filter((l) => l.startsWith('fpr:')).map((l) => l.split(':')[9]);
    const same = fprs.join(' ') === source.gpg.fingerprints.join(' ');
    record.gpg = { fingerprints: fprs, same };
    save();
    log(`gpg: ${same ? 'same' : 'DIFFERENT'} (${fprs.join(' ')})`);
    assert.equal(fprs.join(' '), source.gpg.fingerprints.join(' '),
      'the restored key derives a different GnuPG identity - every signature and message tied to it is lost');
  });

  it('decrypts, through the web app\'s engine, a message sealed to the stored key (RSA slot 1)',
    async ({ device, assert, log, signal }) => {
      const openpgp = webenv.openpgp();
      const armoredPub = fs.readFileSync(path.join(OUT, 'pgp-pub.asc'), 'utf8');
      const publicKey = await openpgp.readKey({ armoredKey: armoredPub });
      assert.equal(publicKey.getFingerprint().toUpperCase(), source.stored.fingerprint, 'pgp-pub.asc is not the stored key');
      const message = await openpgp.encrypt({
        message: await openpgp.createMessage({ text: PLAINTEXT }),
        encryptionKeys: publicKey,
        format: 'armored',
      });
      const pgp = await engine(device, { signal });
      pgp._$mode('Decrypt Only');
      device.log.clear();
      const text = await pqc.confirmFromConsole(device, () => decryptWith(pgp, '', armoredPub, String(message)), { signal });
      record.stored = { fingerprint: source.stored.fingerprint, decrypt: String(text) === PLAINTEXT };
      save();
      assert.equal(String(text), PLAINTEXT, 'the restored slot 1 did not open a message sealed to the stored key');
      log('stored key: slot 1 decrypts');
    });

  it('signs, through the web app\'s engine, with the stored key (RSA slot 2), and openpgp.js verifies it',
    async ({ device, assert, log, signal }) => {
      const openpgp = webenv.openpgp();
      const armoredPub = fs.readFileSync(path.join(OUT, 'pgp-pub.asc'), 'utf8');
      const pgp = await engine(device, { signal });
      pgp._$mode('Sign Only');
      device.log.clear();
      const armored = await pqc.confirmFromConsole(device, () => encryptWith(pgp, '', armoredPub, PLAINTEXT), { signal });
      const verified = await openpgp.verify({
        message: await openpgp.readMessage({ armoredMessage: String(armored) }),
        verificationKeys: await openpgp.readKey({ armoredKey: armoredPub }),
        expectSigned: true,
        format: 'utf8',
      });
      const ok = verified.data === PLAINTEXT && await verified.signatures[0].verified;
      record.stored = { ...record.stored, sign: !!ok };
      save();
      assert.ok(ok, 'the restored slot 2 did not make a signature the stored public key verifies');
      log('stored key: slot 2 signs');
    });
});
