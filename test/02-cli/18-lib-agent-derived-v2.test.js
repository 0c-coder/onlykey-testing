/*
 * onlykey-agent --skey derived-v2: the opt-in HKDF agent derivation.
 *
 * v1 (slot 132, sign 201-203, decrypt 202-204) is and stays the default:
 * sk = SHA256(K132 || sha256(user@host)). v2 is selected per command with
 * `--skey derived-v2` / `--dkey derived-v2` (or ECC32v2) and asks the device
 * for slot 232 (sign 221-223, decrypt 222-224):
 *
 *     sk = HKDF-SHA256(salt = [0x20 | sha256(user@host)], IKM = K132,
 *                      info = "onlykey/agent/v2", L = 32)
 *
 * Same device key, different KDF, so the two must never produce the same key
 * for an identity, and the default must stay v1 - changing it would move every
 * existing user's SSH/GPG key. What is checked:
 *
 *   - the default still answers with the v1 key (same as 08's key),
 *   - derived-v2 answers, deterministically, per identity,
 *   - v1 and v2 differ for the same identity,
 *   - lib-agent and this kit (OKGETPUBKEY 232 over the other transport) agree,
 *   - the published key is the ed25519 public half of the seed the device
 *     printed for v2 (`Agent derivation v2 private key`),
 *   - nothing was primed and nothing was written by the exports,
 *   - OKDECRYPT 224 (X25519) agrees with node:crypto against the device's own
 *     v2 public key, and 221 (Ed25519, no ECDH) is refused for decryption,
 *   - `onlykey-gpg init --skey/--dkey derived-v2` signs (221) and records
 *     derived-v2 in run-agent.sh.
 *
 * Firmware without libraries PR #18 refuses 232 and 221-224 ("Error invalid
 * derived key slot").
 */
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { describe, it } = require('../../lib/harness');
const { IFACE, okmsg } = require('../../lib/device');
const { byteprintAfter } = require('../../lib/device/logbuf');
const { PINS } = require('../../lib/config');
const cli = require('../../lib/cli');
const pqc = require('../../lib/pqc');

const PRIMED = /Encrypted Buffer/g;
const ERASED = /Erase Sector/g;

const DERIVATION_V2_PUBKEY_CODE = 232;
const KEYTYPE_ED25519 = 1;

const IDENTITY = 'ssh://okt@example.com';
const OTHER = 'ssh://someone-else@example.com';

const identityHash = (userAtHost) => crypto.createHash('sha256').update(userAtHost, 'ascii').digest();

function sshKey(stdout) {
  const lines = stdout.split('\n').filter((l) => l.trim());
  if (lines.length !== 1) throw new Error(`expected one public key line, got ${JSON.stringify(lines)}`);
  const [type, b64, ...rest] = lines[0].trim().split(/\s+/);
  const blob = Buffer.from(b64, 'base64');
  const typeLen = blob.readUInt32BE(0);
  const keyLen = blob.readUInt32BE(4 + typeLen);
  return { type, key: blob.subarray(8 + typeLen, 8 + typeLen + keyLen), comment: rest.join(' ') };
}

function ed25519PublicKey(seed) {
  const der = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]);
  const priv = crypto.createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
  return crypto.createPublicKey(priv).export({ format: 'der', type: 'spki' }).subarray(-32);
}

describe('onlykey-agent derived-v2 (opt-in HKDF derivation)', {
  state: 'initialized',
  requires: ['crypto', 'client-access'],
  timeoutMs: 180000,
}, () => {
  let v1 = null;
  let v2 = null;
  let primedAtStart = 0;
  let erasedAtStart = 0;

  const agent = (args, opts) => cli.run('onlykey-agent', args, { timeoutMs: 45000, ...opts });

  it('the default is still the v1 key', async ({ device, assert, signal, log, skip }) => {
    if (!cli.venvPresent()) skip(`no venv at ${cli.VENV_BIN}`);
    await device.unlock(PINS.primary, { signal });
    primedAtStart = device.log.count(PRIMED);
    erasedAtStart = device.log.count(ERASED);

    const r = await agent([IDENTITY], { signal });
    assert.equal(r.code, 0, `onlykey-agent exited ${r.code}: ${r.stderr}`);
    v1 = sshKey(r.stdout);
    log(`default (v1) ${v1.key.toString('hex')}`);
    assert.ok(/Agent derivation private key/.test(device.log.text),
      'the default did not take the v1 (SHA256) derivation');
  });

  it('--skey derived-v2 answers with a different key for the same identity',
    async ({ assert, signal, log }) => {
      const r = await agent(['--skey', 'derived-v2', IDENTITY], { signal });
      assert.equal(r.code, 0, `onlykey-agent --skey derived-v2 exited ${r.code}: ${r.stderr}`);
      v2 = sshKey(r.stdout);
      log(`derived-v2 ${v2.key.toString('hex')}`);
      assert.equal(v2.type, 'ssh-ed25519', `derived-v2 printed ${v2.type}`);
      assert.equal(v2.key.length, 32);
      assert.notEqual(v2.key.toString('hex'), v1.key.toString('hex'),
        'v1 and v2 derived the same key - the version is not reaching the device');
    });

  it('is the ed25519 public half of the seed the device derived for v2', async ({ device, assert }) => {
    const seed = byteprintAfter(device.log.text, 'Agent derivation v2 private key');
    assert.ok(seed, 'the device never printed a v2 derived key - is this a DEBUG build with v2?');
    assert.bytes(ed25519PublicKey(seed), v2.key,
      'the published derived-v2 key is not the public key of the seed the device derived');
  });

  it('is deterministic, and different per identity', async ({ assert, signal }) => {
    const again = sshKey((await agent(['--skey', 'derived-v2', IDENTITY], { signal })).stdout);
    assert.bytes(again.key, v2.key, 'derived-v2 gave two different keys for one identity');
    const other = sshKey((await agent(['--skey', 'derived-v2', OTHER], { signal })).stdout);
    assert.notEqual(other.key.toString('hex'), v2.key.toString('hex'),
      'derived-v2 gave the same key for two identities');
  });

  it('matches what this kit derives with OKGETPUBKEY 232', async ({ device, assert, signal }) => {
    const since = device.mark(IFACE.VENDOR);
    device.sendVendor({
      msg: okmsg.MSG.OKGETPUBKEY,
      slot: DERIVATION_V2_PUBKEY_CODE,
      payload: Buffer.concat([Buffer.from([KEYTYPE_ED25519]), identityHash('okt@example.com')]),
    });
    const reply = await device.waitHid(IFACE.VENDOR, { since, timeoutMs: 10000, signal });
    assert.ok(!/^Error/.test(okmsg.text(reply)), `the device refused OKGETPUBKEY 232: ${okmsg.text(reply)}`);
    assert.bytes(reply.subarray(0, 32), v2.key, 'lib-agent and this kit got different v2 keys');
    assert.bytes(reply.subarray(32), Buffer.alloc(32), 'the device answered with a non-ed25519 key');
  });

  it('primed nothing and wrote nothing', async ({ device, assert }) => {
    assert.equal(device.log.count(PRIMED), primedAtStart, 'exporting a derived key primed a challenge');
    assert.equal(device.log.count(ERASED) - erasedAtStart, 0, 'exporting a derived key wrote flash');
  });

  it('ECDH with code 224 agrees with the v2 Curve25519 public key', async ({ device, assert, signal, log }) => {
    /* The decrypt half: OKDECRYPT 224 = [peer X25519 public (32) | identity hash (32)],
     * confirmed like any derived decrypt. The oracle is node:crypto doing the
     * other side of the exchange against the device's own v2 public key. */
    const idHash = identityHash('okt@example.com');
    let since = device.mark(IFACE.VENDOR);
    device.sendVendor({ msg: okmsg.MSG.OKGETPUBKEY, slot: DERIVATION_V2_PUBKEY_CODE,
      payload: Buffer.concat([Buffer.from([4]), idHash]) });
    const pubReply = await device.waitHid(IFACE.VENDOR, { since, timeoutMs: 10000, signal });
    const devicePub = Buffer.from(pubReply.subarray(0, 32));
    assert.notEqual(devicePub.toString('hex'), '00'.repeat(32), 'no v2 Curve25519 public key');

    const peer = crypto.generateKeyPairSync('x25519');
    const peerPub = peer.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
    const expected = crypto.diffieHellman({
      privateKey: peer.privateKey,
      publicKey: crypto.createPublicKey({
        key: Buffer.concat([Buffer.from('302a300506032b656e032100', 'hex'), devicePub]),
        format: 'der', type: 'spki',
      }),
    });

    const payload = Buffer.concat([peerPub, idHash]);
    const reply = await pqc.confirmFromConsole(device, async () => {
      since = device.mark(IFACE.VENDOR);
      for (let off = 0; off < payload.length; off += 57) {
        const part = payload.subarray(off, off + 57);
        const last = off + 57 >= payload.length;
        device.sendVendor({ msg: okmsg.MSG.OKDECRYPT, slot: 224, field: last ? part.length : 0xFF, payload: part });
      }
      return device.waitHid(IFACE.VENDOR, {
        since, timeoutMs: 45000, signal,
        match: (b) => okmsg.text(b) !== 'INITIALIZED' && !/^(Enter|Press)/.test(okmsg.text(b)),
      });
    }, { signal });
    assert.ok(!/^Error/.test(okmsg.text(reply)), `OKDECRYPT 224 was refused: ${okmsg.text(reply)}`);
    log(`shared secret ${reply.subarray(0, 32).toString('hex')}`);
    assert.bytes(reply.subarray(0, 32), expected,
      'the device\'s v2 ECDH does not match X25519 against its own v2 public key');
  });

  it('refuses an Ed25519 code (221) for decryption', async ({ device, assert, signal }) => {
    /* 201/211/221 name Ed25519, which has no ECDH. The decrypt path used to
     * fall through with whatever key and type the last operation left behind. */
    const payload = Buffer.concat([crypto.randomBytes(32), identityHash('okt@example.com')]);
    const reply = await pqc.confirmFromConsole(device, async () => {
      const since = device.mark(IFACE.VENDOR);
      for (let off = 0; off < payload.length; off += 57) {
        const part = payload.subarray(off, off + 57);
        const last = off + 57 >= payload.length;
        device.sendVendor({ msg: okmsg.MSG.OKDECRYPT, slot: 221, field: last ? part.length : 0xFF, payload: part });
      }
      return device.waitHid(IFACE.VENDOR, {
        since, timeoutMs: 45000, signal,
        match: (b) => okmsg.text(b) !== 'INITIALIZED' && !/^(Enter|Press)/.test(okmsg.text(b)),
      });
    }, { signal });
    assert.match(okmsg.text(reply), /Error invalid derived key slot/, 'OKDECRYPT 221 was not refused');
  });

  it('onlykey-gpg init --skey/--dkey derived-v2 signs with code 221', async ({ device, assert, signal, log }) => {
    const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'okt-v2-gpg-'));
    const homedir = path.join(parent, 'gnupg');
    try {
      const before = (device.log.text.match(/Agent derivation v2 private key/g) || []).length;
      const init = await pqc.confirmFromConsole(device, () => cli.run('onlykey-gpg',
        ['init', 'OKT v2 <okt-v2@example.com>', '--homedir', homedir, '--skey', 'derived-v2', '--dkey', 'derived-v2'],
        { timeoutMs: 240000, signal, env: { PATH: `${cli.VENV_BIN}:${process.env.PATH}` } }), { signal });
      log(`onlykey-gpg init exited ${init.code}`);
      assert.equal(init.code, 0, `init failed: ${init.stderr.slice(-1500) || init.stdout.slice(-1500)}`);
      const script = fs.readFileSync(path.join(homedir, 'run-agent.sh'), 'utf8');
      assert.includes(script, '--skey-slot=derived-v2', 'run-agent.sh does not record the v2 signing key');
      assert.includes(script, '--dkey-slot=derived-v2', 'run-agent.sh does not record the v2 decryption key');
      const after = (device.log.text.match(/Agent derivation v2 private key/g) || []).length;
      assert.ok(after > before, 'no v2 derivation ran during init');
    } finally {
      for (const pid of agentsFor(homedir)) { try { process.kill(pid); } catch { /* gone */ } }
      fs.rmSync(parent, { recursive: true, force: true });
    }
  });
});

function agentsFor(dir) {
  const pids = [];
  for (const entry of fs.readdirSync('/proc')) {
    if (!/^\d+$/.test(entry)) continue;
    let cmdline;
    try { cmdline = fs.readFileSync(`/proc/${entry}/cmdline`, 'utf8').split('\0').join(' '); } catch { continue; }
    if (cmdline.includes('gpg-agent') && cmdline.includes(dir)) pids.push(Number(entry));
  }
  return pids;
}
