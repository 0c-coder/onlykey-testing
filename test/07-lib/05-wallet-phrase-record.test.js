/*
 * RECORDS the fixture 39-wallet-phrase-backup restores: a backup and the wallet phrase its derive
 * key gives (test/00-sanity/fixtures/wallet-phrase-backup.json). Runs only with OKT_RECORD=1;
 * otherwise every test is skipped.
 *
 * WHY ITS OWN FILE, FROM 'blank'. The fixture's derive key must differ from the test device's on
 * every machine, or the drift check would compare a key with itself. The kit's 'initialized'
 * image is built once per machine, so its random slot 128 is the same in every file there. This
 * file starts from 'blank' and runs the same setup ('initialized' state's apply()), so the
 * firmware draws a NEW random slot 128 (okcore.cpp:3059, RNG from the platform CSPRNG on the
 * emulator). The host cannot write slot 128 itself: OKSETPRIV answers "Error cannot set key in
 * reserved slot (117-132)" - only a restore fills it.
 *
 * Re-record only on purpose (the words change with it): delete the file, run this with
 * OKT_RECORD=1, check it, commit it.
 */
'use strict';

const fs = require('fs');
const path = require('path');

const { describe, it } = require('../../lib/harness');
const backup = require('../../lib/device/backup');
const initialized = require('../../lib/fixtures/states/initialized');
const wp = require('../../lib/wallet-phrase');

const RECORD = process.env.OKT_RECORD === '1';

describe('record the wallet phrase fixture (OKT_RECORD=1)', {
  state: 'blank',
  requires: ['crypto', 'keyboard-capture'],
  timeoutMs: 900000,
}, () => {
  it('a freshly set-up key: its phrase and its backup become the fixture',
    async ({ device, assert, signal, log, skip }) => {
      /* only on purpose: a new recording changes the committed words */
      if (!RECORD) skip('records the wallet phrase fixture only with OKT_RECORD=1');
      await initialized.apply(device, { log, signal });
      await wp.prepare(device, signal, assert);
      const words = await wp.phraseOf(device, signal);
      assert.equal(words.split(' ').length, 12);
      assert.equal(wp.mnemonic.isValidPhrase(words), true, 'not a valid BIP39 phrase');
      const typed = await wp.typeBackup(device, signal, log);
      const parsed = backup.parse(typed);
      assert.ok(parsed.complete && parsed.storedHash, 'the typed backup is incomplete');
      assert.control("the typed backup's chained hash matches - every keystroke was captured",
        parsed.computedHash.toString('hex') === parsed.storedHash.toString('hex'));
      fs.mkdirSync(path.dirname(wp.FIXTURE), { recursive: true });
      fs.writeFileSync(wp.FIXTURE, `${JSON.stringify({
        v: 1,
        why: 'test/07-lib/05-wallet-phrase-record: a throwaway emulator (set up from blank, random derive key) - its typed backup, and the wallet phrase its derive key gives for the name below. Test keys only.',
        passphrase: wp.PASSPHRASE,
        name: wp.NAME,
        out: 'bip39-12',
        words,
        backup: typed,
      }, null, 2)}\n`);
      log(`recorded ${path.relative(process.cwd(), wp.FIXTURE)} - check it and commit it`);
    });
});
