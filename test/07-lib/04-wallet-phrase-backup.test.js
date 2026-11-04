/*
 * A WALLET PHRASE SURVIVES A BACKUP (PASSWORD-MANAGER-SPEC.md, "Wallet mnemonics" and "Backup
 * restores the derive": "An e2e test proves it on the bench before the wallet option ships: back
 * up, restore into a fresh soft key, and the phrase for a test label must come out identical";
 * "Known-answer vectors ... catch drift at build time"). Brad, 2026-10-12: "Do it now".
 *
 * A wallet phrase is derived again from the key every time, never stored, so it is only as
 * recoverable as the derive key (ECC slot 128) - the claim is that an OnlyKey backup carries it.
 * Three steps on the kit's emulator, through the lib exactly as the app calls it
 * (lib/wallet-phrase.js):
 *
 *   own        this device's phrase A; then it types its own backup;
 *   recorded   a COMMITTED backup (test/00-sanity/fixtures/wallet-phrase-backup.json, from another
 *              emulator's random derive key) restored here gives the words recorded with it: a
 *              restore replaces the derive key, and a firmware or lib change that moves the
 *              phrase (derivation drift) fails here;
 *   back       this device's own backup restored again gives A back.
 *
 * The fixture is made by 39-wallet-phrase-record (OKT_RECORD=1), on a separately set-up
 * emulator: the kit's 'initialized' image is built on each machine with its own random slot 128,
 * so a fixture from it would hold this machine's key and 'recorded' would compare a key with
 * itself.
 *
 * SURFACES: the lib over the kit's in-process emulator (lib/libstack.js), vendor + keyboard
 * capture.
 */
'use strict';

const fs = require('fs');

const { describe, it } = require('../../lib/harness');
const backup = require('../../lib/device/backup');
const wp = require('../../lib/wallet-phrase');

describe('a wallet phrase survives an OnlyKey backup (and does not drift)', {
  state: 'initialized',
  requires: ['crypto', 'keyboard-capture'],
  timeoutMs: 900000,
}, () => {
  let own = null;
  let words = null;

  it('own: the phrase is derived touch-free, and the device types its backup',
    async ({ device, assert, signal, log }) => {
      await wp.prepare(device, signal, assert);
      words = await wp.phraseOf(device, signal);
      assert.equal(words.split(' ').length, 12);
      assert.equal(wp.mnemonic.isValidPhrase(words), true, 'not a valid BIP39 phrase');
      assert.equal(await wp.phraseOf(device, signal), words, 'the same key gave two phrases');
      log(`phrase for "${wp.NAME}": 12 words (not logged)`);

      own = await wp.typeBackup(device, signal, log);
      const parsed = backup.parse(own);
      assert.ok(parsed.complete && parsed.storedHash, 'the typed backup is incomplete');
      assert.control("the typed backup's chained hash matches - every keystroke was captured",
        parsed.computedHash.toString('hex') === parsed.storedHash.toString('hex'));
    });

  it('recorded: a committed backup restores the words recorded with it (drift check)',
    async ({ device, assert, signal }) => {
      assert.ok(own && words, 'no phrase from the first test');
      assert.ok(fs.existsSync(wp.FIXTURE),
        `no fixture at ${wp.FIXTURE}: run 07-lib/05-wallet-phrase-record.test.js with OKT_RECORD=1, check it, commit it`);
      const fixture = JSON.parse(fs.readFileSync(wp.FIXTURE, 'utf8'));
      await wp.restore(device, signal, assert, fixture.backup);
      const got = await wp.phraseOf(device, signal);
      assert.control("the restore replaced the derive key (another phrase than this device's own)", got !== words);
      assert.equal(got, fixture.words, 'the recorded backup no longer gives its recorded phrase - derivation drift');
    });

  it("back: this device's own backup restored gives its phrase back",
    async ({ device, assert, signal }) => {
      assert.ok(own && words, 'no backup from the first test');
      await wp.restore(device, signal, assert, own);
      assert.equal(await wp.phraseOf(device, signal), words, 'the restored key gives another phrase');
    });
});
