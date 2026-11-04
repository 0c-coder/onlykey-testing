/*
 * Section 4: the App's Backup/Restore tab, against a backup the device made.
 *
 * THE APP'S OWN SUITE CANNOT REACH THIS AT ALL, and not merely because nobody
 * wrote the test. Its `chrome.hid` is mocked with canned strings, and a backup
 * is six hundred KEYSTROKES the device types on its keyboard interface over the
 * better part of a minute. There is nothing to mock: a backup is either produced
 * by a real device or it is a fixture somebody pasted in once, and a fixture
 * only ever proves the verifier still reads a file from the year it was made.
 *
 * So this file gets a REAL backup - the device types it, the kit captures it
 * off the keyboard interface, exactly as `01-protocol/10-backup-restore` does -
 * and then asks the App two questions about it.
 *
 * TWO VERIFIERS, ONE ARTEFACT, AND NEITHER WROTE IT. The backup's integrity is
 * a CHAIN of SHA256 values, one folded into the next per line, computed by the
 * firmware while it typed. `lib/device/backup.js` recomputes that chain, and the
 * App's `verifyBackupFile()` computes it again in its own code. The device is
 * the only author; the two verifiers are independent readers. That is the same
 * shape as `02-cli/00-venv` asserting the CLI and the kit agree about what the
 * device just said, and it is the strongest thing available here - a round trip
 * through one implementation would prove nothing, because a broken writer and
 * its matching reader agree perfectly.
 *
 * SURFACE: keyboard (the backup itself) and vendor (what the restore put back).
 * The debug console is read for ONE thing - the "Backing up Label Number" line
 * that says a hold was not discarded mid-fade - and that is a timing signal
 * rather than an assertion, the same use `10-backup-restore` makes of it.
 *
 * OUTSIDE `--isolate` AND `--reverse` BY CONSTRUCTION, like the rest of the
 * section. Within the file the backup is captured once and both tests read it,
 * which is the coupling this tier allows: capturing it twice would cost another
 * minute of typing to assert one more property of the same artefact.
 */
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const { describe, it } = require('../../lib/harness');
const { IFACE, okmsg } = require('../../lib/device');
const { PINS } = require('../../lib/config');
const backup = require('../../lib/device/backup');

const session = require('../../lib/app-session-holder');

const PASSPHRASE = 'onlykey-testing backup passphrase 2026';
const BACKUP_KEY_TYPE = 161;        /* 128 backup | 32 decryption | 1 */
const BACKUP_KEY_SLOT = 131;
const FIELD = { LABEL: 1 };
const SLOT = 3;                     /* 1 is 11-app-slot-config's, 2 is 10-backup-restore's */
const LABEL = 'appbkup3';

describe('app backup', {
  state: 'initialized',
  requires: ['client-access', 'display', 'nwjs', 'keyboard-capture'],
  timeoutMs: 1200000,                // a physical key types its backup at keyboard speed, which takes minutes
}, () => {
  let captured = null;

  it('captures a real backup the device typed, and the kit verifies its chain', async ({ device, assert, signal, log }) => {
    /*
     * ESTABLISH EVERYTHING THIS ASSERTS ABOUT. A backup needs a backup key
     * (OKSETPRIV slot 131, which is refused outside config mode) and something
     * worth backing up. And it CANNOT BE TAKEN IN CONFIG MODE - payload()'s
     * backup branch requires !isfade and config mode holds the LED animation
     * forever - so the device leaves config mode before the hold.
     */
    await device.ensureUnlocked(PINS.primary, { signal });
    await device.enterConfigMode(PINS.primary, { signal });

    const key = crypto.createHash('sha256').update(PASSPHRASE, 'utf8').digest();
    let since = device.mark(IFACE.VENDOR);
    device.sendVendor({
      msg: okmsg.MSG.OKSETPRIV,
      slot: BACKUP_KEY_SLOT,
      payload: Buffer.concat([Buffer.from([BACKUP_KEY_TYPE]), key]),
    });
    let reply = await device.waitHid(IFACE.VENDOR,
      { since, match: /Successfully|Error/, timeoutMs: 10000, signal });
    assert.match(okmsg.text(reply), /Successfully set Backup Passphrase/,
      'the device refused the backup key');

    since = device.mark(IFACE.VENDOR);
    device.sendVendor({ msg: okmsg.MSG.OKSETSLOT, slot: SLOT, field: FIELD.LABEL, payload: LABEL });
    reply = await device.waitHid(IFACE.VENDOR,
      { since, match: /Successfully|Error/, timeoutMs: 8000, signal });
    assert.ok(!/Error/.test(okmsg.text(reply)), okmsg.text(reply));

    await device.restart({ signal });
    await device.unlock(PINS.primary, { signal });

    /* A hold that lands mid-fade is discarded and prints nothing, so this
     * retries on the device's own "Backing up" line, as 10-backup-restore does. */
    let started = false;
    for (let attempt = 1; attempt <= 6 && !started; attempt++) {
      device.log.clear();
      device.keys.clear();
      device.pressLine([{ button: 1, hold: 'hold' }]);
      started = await device.log.waitFor(/Backing up Label Number/, { timeoutMs: 5000, signal })
        .then(() => true, () => false);
      if (!started) log(`hold ${attempt} landed mid-fade and was discarded`);
    }
    assert.ok(started, 'the device never started a backup in six attempts');

    await device.waitKeystrokes(/-----END ONLYKEY BACKUP-----/, { timeoutMs: 600000, signal }); // a physical key types at keyboard speed (see lib/wallet-phrase.js)
    captured = device.keystrokes;

    const parsed = backup.parse(captured);
    assert.ok(parsed.complete, 'the captured backup is missing a marker');
    assert.ok(backup.verify(parsed),
      "the kit could not verify the device's own chained SHA256 - the capture " +
      'dropped a keystroke, and nothing this file says about the App would mean ' +
      'anything against a corrupt artefact');
    log(`captured a ${parsed.data.length}-byte backup over ${parsed.lines} lines`);
  });

  it('the App\'s own verifier accepts the same backup - two readers, one device-written artefact', async ({ device, assert, signal, log }) => {
    assert.ok(captured, 'no backup was captured by the first test');

    const s = session.get();
    const page = await s.attach('app');
    try {
      await s.waitForDevice(page, device, { signal, log });

      /*
       * `verifyBackupFile()` reads #backupData, walks the lines, and recomputes
       * the same chain the firmware computed while typing. It reports into
       * #verifyBackupMessage on success and #backupFormError on failure - and
       * BOTH are read, because a verifier that silently does nothing would
       * otherwise look like a pass.
       */
      const result = JSON.parse(await page.eval(`(() => {
        document.getElementById('show-backup-panel').click();
        const box = document.getElementById('backupData');
        box.value = ${JSON.stringify(captured)};
        box.dispatchEvent(new Event('input', {bubbles: true}));
        document.getElementById('verifyBackupMessage').innerText = '';
        document.getElementById('backupFormError').innerText = '';
        document.getElementById('backupVerify').click();
        return JSON.stringify({ clicked: true });
      })()`));
      assert.ok(result.clicked, 'the Backup tab did not accept the pasted backup');

      /* The verifier is synchronous but the DOM write is not observed until the
       * next evaluation; give it a beat rather than racing it. */
      await device.sleep(1500, { signal });

      const outcome = JSON.parse(await page.eval(`JSON.stringify({
        ok: document.getElementById('verifyBackupMessage').innerText || '',
        err: document.getElementById('backupFormError').innerText || '',
      })`));
      log(`the App's verifier said ${JSON.stringify(outcome)}`);

      assert.equal(outcome.err, '',
        `the App rejected a backup this device typed and the kit verified: ${outcome.err}`);
      assert.ok(outcome.ok.length > 0,
        'the App reported neither success nor failure for the backup - its ' +
        'verifier produced no output at all, which is not a pass');
    } finally {
      page.close();
    }
  });

  /*
   * THE RESTORE HALF IS NOT HERE YET, and this is the record of why rather
   * than an omission. Driving `#doRestore` with a backup file attached over
   * CDP's DOM.setFileInputFiles gets the App as far as displaying "Restoring
   * from backup please wait..." with an empty error box - and then **nothing
   * reaches the device**: zero vendor replies and no reboot across 45 seconds,
   * with the device still answering `unlocked` throughout.
   *
   * Two readings, and this could not distinguish them, which is the whole
   * reason it is not asserted:
   *
   *   1. the App's restore stalls before it transmits, which would be a real
   *      defect in a path that carries a whole device's secrets, or
   *   2. `submitRestore()` reads the file with a FileReader, and a File
   *      injected by the debugger is not one this nw.js will read - a
   *      HARNESS artefact that says nothing about the App.
   *
   * What would settle it in one run: instrument `submitRestoreData()` from the
   * page - it is a top-level function, so it can be wrapped the way
   * `initSlotConfigForm` was in 04-app/11 - and see whether it is ever called
   * and with how many bytes. If it is called, the App is transmitting and the
   * fault is downstream; if it is not, the file never got read and reading 2
   * above is the likely one. See TODO.
   *
   * Worth noting what IS established meanwhile: the same backup restores fine
   * over the vendor interface, which `01-protocol/10-backup-restore` does end
   * to end, so the device half is not in question.
   */
});
