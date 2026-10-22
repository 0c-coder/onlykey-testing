/*
 * THE UPGRADE PATH, phase A: what a key on the OLD firmware gives, and its backup.
 *
 * Run against an emulated release (OKEMU_VERSION=v3.0.4 OKEMU_DEBUG=1 - the last signed release),
 * through the gadget, with the release's own python tools (OKT_VENV). It records, into
 * OKT_UPGRADE_DIR:
 *   - the SSH public key onlykey-agent derives for one identity;
 *   - the GnuPG identity onlykey-gpg init derives (a fixed creation time, so its fingerprint
 *     depends on the key material only);
 *   - a stored PGP key loaded into RSA slots 1 (decrypt) and 2 (sign) - the key file
 *     OKT_UPGRADE_DIR/pgp-sec.asc, one the web app can read (no RFC 9580 subpacket 34);
 *   - the backup the key TYPES (button 1 held), captured and checked against its chained SHA256,
 *     under a known backup passphrase.
 *
 * Phase B (release-3.1.0-test/tools/upgrade-target.*) restores that backup onto a key on the NEW
 * firmware with `onlykey-cli restore` and checks every one of these comes out the same - which is
 * what upgrading a key is: back up, load the new firmware, restore.
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
const backup = require('../../lib/device/backup');
const cli = require('../../lib/cli');
const pqc = require('../../lib/pqc');
const webenv = require('../../lib/webenv');
const { loadSlots } = require('../../lib/pgp-rsa');

const OUT = process.env.OKT_UPGRADE_DIR ? path.resolve(process.env.OKT_UPGRADE_DIR) : path.join(KIT_ROOT, 'runs', 'upgrade');
const PASSPHRASE = 'onlykey 3.1.0 upgrade path backup passphrase';
const BACKUP_KEY_TYPE = 161;
const BACKUP_KEY_SLOT = 131;
const SSH_ID = 'upgrade@rc-test.example';
const GPG_ID = 'RC Upgrade <upgrade@rc-test.example>';
const GPG_TIME = '1700000000';
const VENV_PATH = cli.venvPathEnv();

const record = {};
const save = () => fs.writeFileSync(path.join(OUT, 'source.json'), JSON.stringify(record, null, 2));

describe('upgrade path, phase A: an old key\'s derived keys, stored key and backup', {
  state: 'initialized',
  requires: ['crypto', 'client-access', 'keyboard-capture', 'webapp-lib'],
  timeoutMs: 900000,
}, () => {
  let homedir = null;

  it('unlocks the key and records which firmware it is', async ({ device, assert, log }) => {
    fs.mkdirSync(OUT, { recursive: true });
    assert.ok(fs.existsSync(path.join(OUT, 'pgp-sec.asc')), `put the stored key in ${OUT}/pgp-sec.asc first`);
    const model = await device.unlock(PINS.primary);
    record.firmware = String(model).replace(/^UNLOCKED/, '');
    record.passphrase = PASSPHRASE;
    log(`source firmware: ${record.firmware}`);
    save();
  });

  it('records the SSH key onlykey-agent derives', async ({ assert, log, signal }) => {
    const r = await cli.run('onlykey-agent', [SSH_ID], { timeoutMs: 60000, signal, env: VENV_PATH });
    assert.equal(r.code, 0, r.stderr.slice(-800));
    const key = (r.stdout.match(/(ssh-ed25519 [A-Za-z0-9+/=]+)/) || [])[1];
    assert.ok(key, `no ssh key in: ${r.stdout.slice(0, 200)}`);
    record.ssh = { identity: SSH_ID, key };
    log(`ssh: ${key.slice(0, 60)}...`);
    save();
  });

  it('records the GnuPG identity onlykey-gpg derives (fixed creation time)', async ({ device, assert, log, signal }) => {
    homedir = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'okt-upgrade-')), 'gnupg');
    const init = await pqc.confirmFromConsole(device, () => cli.run('onlykey-gpg',
      ['init', GPG_ID, '-t', GPG_TIME, '--homedir', homedir], { timeoutMs: 240000, signal, env: VENV_PATH }), { signal });
    assert.equal(init.code, 0, init.stderr.slice(-1500) || init.stdout.slice(-1500));
    const list = await cli.runHost('gpg', ['--homedir', homedir, '--with-colons', '--list-keys'], { timeoutMs: 30000, signal });
    const fprs = list.stdout.split('\n').filter((l) => l.startsWith('fpr:')).map((l) => l.split(':')[9]);
    assert.ok(fprs.length >= 1, 'no fingerprint listed');
    record.gpg = { userId: GPG_ID, time: GPG_TIME, fingerprints: fprs };
    log(`gpg: ${fprs.join(' ')}`);
    save();
  });

  it('loads the stored PGP key into RSA slots 1 and 2, with a backup passphrase set', async ({ device, assert, log, signal }) => {
    await device.enterConfigMode(PINS.primary, { signal });
    /* the backup key - the same as 10-backup-restore sets it */
    const since = device.mark(IFACE.VENDOR);
    device.sendVendor({
      msg: okmsg.MSG.OKSETPRIV, slot: BACKUP_KEY_SLOT,
      payload: Buffer.concat([Buffer.from([BACKUP_KEY_TYPE]),
        crypto.createHash('sha256').update(PASSPHRASE, 'utf8').digest()]),
    });
    const reply = await device.waitHid(IFACE.VENDOR, { since, match: /Successfully|Error/, timeoutMs: 10000, signal });
    assert.match(okmsg.text(reply), /Successfully set Backup Passphrase/, 'the backup key was refused');

    const openpgp = webenv.openpgp();
    const privateKey = await openpgp.readPrivateKey({ armoredKey: fs.readFileSync(path.join(OUT, 'pgp-sec.asc'), 'utf8') });
    const half = (packet) => ({
      pq: Buffer.concat([Buffer.from(packet.privateParams.p), Buffer.from(packet.privateParams.q)]),
      n: Buffer.from(packet.publicParams.n), e: Buffer.from(packet.publicParams.e),
    });
    const key = { privateKey, primary: half(privateKey.keyPacket), sub: half(privateKey.subkeys[0].keyPacket) };
    await loadSlots(device, key, ['sign', 'decrypt'], { signal, assert, log });
    record.stored = { file: 'pgp-sec.asc', fingerprint: privateKey.getFingerprint().toUpperCase(), slots: { sign: 2, decrypt: 1 } };
    save();
  });

  it('types its backup when button 1 is held, and the chained SHA256 checks', async ({ device, assert, log, signal }) => {
    await device.restart({ signal });                       // a backup cannot be taken in config mode
    await device.unlock(PINS.primary, { signal });
    let started = false;
    for (let attempt = 1; attempt <= 6 && !started; attempt++) {
      device.log.clear();
      device.keys.clear();
      device.pressLine([{ button: 1, hold: 'hold' }]);
      started = await Promise.any([
        device.log.waitFor(/Backing up Label Number/, { timeoutMs: 5000, signal }),
        device.waitKeystrokes(/-----BEGIN ONLYKEY BACKUP-----/, { timeoutMs: 5000, signal }),
      ]).then(() => true, () => device.keystrokes.length > 0);
      if (!started) log(`hold ${attempt} landed mid-fade and was discarded`);
    }
    assert.ok(started, 'the device never started a backup');
    await device.waitKeystrokes(/-----END ONLYKEY BACKUP-----/, { timeoutMs: 600000, signal });
    const captured = device.keystrokes;
    const parsed = backup.parse(captured);
    assert.ok(parsed.complete && parsed.storedHash, 'an incomplete backup');
    assert.equal(parsed.computedHash.toString('hex'), parsed.storedHash.toString('hex'), 'the chained hash does not match');
    const text = captured.slice(captured.indexOf(backup.BEGIN), captured.indexOf(backup.END) + backup.END.length);
    fs.writeFileSync(path.join(OUT, 'backup.txt'), `${text}\n`);
    record.backup = { file: 'backup.txt', bytes: parsed.data.length, sha256: parsed.storedHash.toString('hex') };
    log(`backup: ${parsed.data.length} bytes, recorded in ${OUT}`);
    save();
  });
});
