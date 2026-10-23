'use strict';
/*
 * F9 through the user's own path: a typed backup that holds a composite PQC-PGP key
 * (made by f9-pqc-backup.test.js with OKT_F9_SAVE on a machine that can capture one),
 * restored with the release's `onlykey-cli restore` - the way phase B restores, so it
 * runs where a typed backup cannot be captured (Windows).
 *
 *   OKT_F9_BACKUP=<the saved backup file>  [OKT_F9_PASSPHRASE=<its passphrase>]
 *
 * The RC refuses such a backup ("Error key configuration backup file format incorrect")
 * and then restarts itself, so the reboot is no proof here: what the key SAID is.
 */
const crypto = require('node:crypto');
const fs = require('node:fs');
const { describe, it } = require('../../lib/harness');
const { IFACE, okmsg } = require('../../lib/device');
const { PINS } = require('../../lib/config');
const cli = require('../../lib/cli');

const FILE = process.env.OKT_F9_BACKUP || null;
const PASSPHRASE = process.env.OKT_F9_PASSPHRASE || 'okt f9 pqc backup passphrase';

describe('F9: a backup holding a PQC-PGP key, restored with onlykey-cli', { state: 'initialized', timeoutMs: 600000, requires: ['crypto', 'client-lend'] }, () => {
  it('onlykey-cli restore loads it', async ({ device, assert, log, signal, skip }) => {
    if (!FILE) return skip('OKT_F9_BACKUP names no backup file');
    assert.ok(fs.existsSync(FILE), `no backup file at ${FILE}`);
    await device.ensureUnlocked(PINS.primary, { signal });
    await device.enterConfigMode(PINS.primary, { signal });
    const since = device.mark(IFACE.VENDOR);
    device.sendVendor({ msg: okmsg.MSG.OKSETPRIV, slot: 131, payload: Buffer.concat([Buffer.from([161]), crypto.createHash('sha256').update(PASSPHRASE, 'utf8').digest()]) });
    assert.match(okmsg.text(await device.waitHid(IFACE.VENDOR, { since, match: /Successfully|Error/, timeoutMs: 10000, signal })), /Successfully set Backup Passphrase/);

    /*
     * The vendor channel is the CLI's during the lend; the kit keeps the debug console, where a
     * DEBUG build prints the restore's answer either way ("Successfully loaded backup", or the
     * format error). Cleared first, so only this restore's answer is read.
     */
    const before = device.generation;
    device.log.clear();
    const r = await device.lendToClient(() => cli.run('onlykey-cli', ['restore', FILE], { timeoutMs: 180000, signal, env: cli.venvPathEnv() }));
    log(`cli exit ${r.code}: ${(r.stdout + r.stderr).trim().split('\n').slice(-2).join(' | ').slice(0, 200)}`);
    await device.waitForReboot({ from: before, timeoutMs: 90000, signal });
    const said = `${device.log.tail(200000)} ${r.stdout} ${r.stderr}`;
    log(`the key said: ${(said.match(/Successfully loaded backup|Error[^\n|]*/) || ['(nothing recognised)'])[0]}`);
    await device.waitReady({ signal });
    await device.ensureUnlocked(PINS.primary, { signal });
    assert.ok(!/format incorrect/.test(said), 'the restore was refused: "Error key configuration backup file format incorrect"');
    assert.match(said, /Successfully loaded backup/, 'the key never said "Successfully loaded backup"');
  });
});
