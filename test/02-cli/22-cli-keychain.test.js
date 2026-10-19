'use strict';
/*
 * onlykey-js keychain - the CLI's Key Chain commands against the real
 * firmware, with the device's own answers as the truth.
 *
 *   keychain gen <type> --slot ECCn --label …   generate inside the key (config mode)
 *   keychain slots                             every key slot: kind, label, fingerprint
 *   keychain pub ECCn                          the public key, as hex and an SSH line
 *   keychain derive ssh <type> <user@host>     a derived public key (no slot)
 *
 * What the lib's own tests cannot show: that these run against a device and
 * that what they print is what the device holds. So the public key the CLI
 * prints is compared with a RAW OKGETPUBKEY (no lib involved), and a
 * generation over a named key without --yes must leave that key in place.
 *
 * ECC7 (107): no other kit test touches it (36-keychain keeps to 105, 106 and
 * 109-116). It is wiped again at the end.
 */
const { describe, it } = require('../../lib/harness');
const { IFACE, okmsg } = require('../../lib/device');
const { PINS } = require('../../lib/config');
const cli = require('../../lib/cli');

const SLOT = 107;
const NAME = 'ECC7';
const LABEL = 'ssh:clikit';
const REPORT = 64;

const isStatus = (buf) => /^(UNLOCKED|INITIALIZED|LOCKED|CONFIG)/.test(Buffer.from(buf).toString('latin1'));
const hexLine = (out) => (/^hex\s+([0-9a-f]+)/m.exec(out) || [])[1];

/* One OKGETPUBKEY, raw: the device's own answer, ended by a quiet bus. */
async function rawPublicKey(device, signal, slot) {
  const since = device.mark(IFACE.VENDOR);
  device.sendVendor({ msg: okmsg.MSG.OKGETPUBKEY, slot, field: 0 });
  const deadline = Date.now() + 8000;
  let seen = 0;
  let quietSince = Date.now();
  while (Date.now() < deadline) {
    await device.sleep(50, { signal });
    const n = device.reportsSince(IFACE.VENDOR, since).filter((r) => !isStatus(r)).length;
    if (n !== seen) { seen = n; quietSince = Date.now(); }
    else if (seen && Date.now() - quietSince >= 500) break;
  }
  return Buffer.concat(device.reportsSince(IFACE.VENDOR, since)
    .filter((r) => !isStatus(r)).map((r) => Buffer.from(r).subarray(0, REPORT)));
}

describe('onlykey-js keychain: gen, slots, pub and derive against the real firmware', {
  state: 'initialized',
  requires: ['crypto', 'client-access'],
  negative: true,
  timeoutMs: 600000,
}, () => {
  const js = (argv, signal, opts = {}) => cli.runLib(argv, { timeoutMs: 60000, signal, ...opts });
  const show = (log, what, r) => log(`${what}: exit ${r.code}\n${(r.stdout + r.stderr).trim()}`);
  const made = {};

  const needCli = ({ skip }) => {
    const missing = cli.libCliMissing();
    if (missing) skip(missing);
  };

  it('`keychain gen ed25519 --slot ECC7 --label …` generates inside the key, in config mode',
    async ({ device, assert, signal, log, skip }) => {
      needCli({ skip });
      await device.restart({ signal });
      await device.ensureUnlocked(PINS.primary, { signal });
      await device.enterConfigMode(PINS.primary, { signal });
      const r = await js(['keychain', 'gen', 'ed25519', '--slot', NAME, '--label', LABEL, '--yes'], signal);
      show(log, 'keychain gen', r);
      assert.equal(r.code, 0, `keychain gen failed: ${r.stderr.trim()}`);
      assert.ok(/keychain pub ECC7/.test(r.stdout), 'the CLI did not say how to read the key after the restart');
    });

  it('after the restart, `keychain slots` names it and `keychain pub` prints what the device holds',
    async ({ device, assert, signal, log, skip }) => {
      needCli({ skip });
      await device.restart({ signal });
      await device.ensureUnlocked(PINS.primary, { signal });
      const list = await js(['keychain', 'slots'], signal);
      show(log, 'keychain slots', list);
      assert.equal(list.code, 0, `keychain slots failed: ${list.stderr.trim()}`);
      const row = list.stdout.split('\n').find((l) => l.startsWith(`${NAME} `));
      assert.ok(row && /\bed25519\b/.test(row) && row.includes(LABEL), `keychain slots does not show ECC7 as ed25519 "${LABEL}": ${row}`);

      const pub = await js(['keychain', 'pub', NAME], signal);
      show(log, 'keychain pub', pub);
      assert.equal(pub.code, 0, `keychain pub failed: ${pub.stderr.trim()}`);
      const printed = hexLine(pub.stdout);
      const raw = (await rawPublicKey(device, signal, SLOT)).subarray(0, 32).toString('hex');
      log(`CLI ${printed}\nraw ${raw}`);
      assert.equal(printed, raw, 'keychain pub prints another key than the device answers');
      const ssh = (/ssh-ed25519 (\S+)/.exec(pub.stdout) || [])[1];
      assert.ok(ssh && Buffer.from(ssh, 'base64').subarray(-32).toString('hex') === raw,
        'the SSH line does not carry the device\'s key');
      made.key = raw;
    });

  it('`keychain gen` refuses a named slot without --yes, and the key stays',
    async ({ device, assert, signal, log, skip }) => {
      needCli({ skip });
      if (!made.key) skip('no key from the test above');
      await device.enterConfigMode(PINS.primary, { signal });
      const r = await js(['keychain', 'gen', 'ed25519', '--slot', NAME], signal);
      show(log, 'keychain gen (no --yes)', r);
      assert.ok(r.code !== 0, 'keychain gen replaced a named key without --yes');
      assert.ok(r.stderr.includes(LABEL), `the refusal does not name the key it protects: ${r.stderr.trim()}`);
      await device.restart({ signal });
      await device.ensureUnlocked(PINS.primary, { signal });
      const raw = (await rawPublicKey(device, signal, SLOT)).subarray(0, 32).toString('hex');
      assert.equal(raw, made.key, 'the refused generation changed the key anyway');
    });

  /*
   * The ssh scheme: agent derivation over the vendor interface. The label
   * scheme runs over FIDO (CTAPHID), which the desktop HID pipe does not open
   * (cli/transport-hid.js) - `keychain derive label` cannot run from a desktop
   * as the CLI stands (2026-10-01; open for the owner).
   */
  it('`keychain derive ssh ed25519 …` gives the same public key twice', async ({ device, assert, signal, log, skip }) => {
    needCli({ skip });
    await device.ensureUnlocked(PINS.primary, { signal });
    const one = await js(['keychain', 'derive', 'ssh', 'ed25519', 'kit@keychain.example'], signal);
    const two = await js(['keychain', 'derive', 'ssh', 'ed25519', 'kit@keychain.example'], signal);
    show(log, 'keychain derive', one);
    assert.equal(one.code, 0, `keychain derive failed: ${one.stderr.trim()}`);
    assert.ok(hexLine(one.stdout), 'keychain derive printed no public key');
    assert.equal(hexLine(two.stdout), hexLine(one.stdout), 'the same label derived two different keys');
  });

  /*
   * The label scheme runs over FIDO (CTAPHID). The desktop pipe opens the FIDO
   * interface on first use (lib cli/transport-hid.js, 2026-10-01); before
   * that, this command could not run from a desktop at all.
   *
   * Windows hands a security key's FIDO interface only to an elevated program
   * (its WebAuthn service keeps it), and onlykey-js says so and exits. From a
   * normal shell that is the platform, not a fault, so the test skips with the
   * CLI's own reason; any other failure still fails.
   */
  it('`keychain derive label p256 …` over FIDO gives the same public key twice', async ({ device, assert, signal, log, skip }) => {
    needCli({ skip });
    await device.ensureUnlocked(PINS.primary, { signal });
    const one = await js(['keychain', 'derive', 'label', 'p256', 'keychain-kit.example'], signal);
    if (process.platform === 'win32' && one.code !== 0 && /only to an elevated program/.test(one.stderr)) {
      skip(`Windows: ${one.stderr.trim().replace(/^onlykey-js: /, '')}`);
    }
    const two = await js(['keychain', 'derive', 'label', 'p256', 'keychain-kit.example'], signal);
    show(log, 'keychain derive label', one);
    assert.equal(one.code, 0, `keychain derive label failed: ${one.stderr.trim()}`);
    assert.ok(hexLine(one.stdout), 'keychain derive label printed no public key');
    assert.equal(hexLine(two.stdout), hexLine(one.stdout), 'the same label derived two different keys');
  });

  it('tidy: ECC7 wiped again', async ({ device, assert, signal, log, skip }) => {
    needCli({ skip });
    await device.ensureUnlocked(PINS.primary, { signal });
    await device.enterConfigMode(PINS.primary, { signal });
    const r = await js(['wipekey', NAME], signal);
    show(log, 'wipekey', r);
    assert.equal(r.code, 0, `wipekey failed: ${r.stderr.trim()}`);
    await device.restart({ signal });
  });
});
