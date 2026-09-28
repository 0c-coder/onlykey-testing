/*
 * Section 3, browser tier: the age-derive page - encrypt and decrypt, in the
 * browser, against the device.
 *
 * This page is the whole derived X-Wing feature in one screen: a label becomes
 * an identity, the device derives a recipient for it, the page seals an age file
 * to that recipient, and the device is asked for its half again to open it. Two
 * device calls per direction, a real age container in between, and none of it
 * stored anywhere.
 *
 * Every piece is already proven separately - 03-xwing-derive for the device
 * calls, 04-age-file for the container, 01-age-pqc-parity for the maths - so
 * what is new here is only that the PAGE joins them up correctly. That is the
 * point of the tier, and it is why this file can spend its assertions on
 * interoperability rather than on whether the crypto works.
 *
 * The assertion worth having is the last one: an age file produced BY THE
 * BROWSER is opened by this kit, using this kit's own age-pqc and its own
 * transport to the device. If those disagree, a file encrypted in the web app
 * cannot be read by the CLI or anything else - which is exactly the failure
 * nobody notices until it is somebody's data.
 *
 * localhost and the matching rpId, for the reason 11-password-generator
 * records: WebAuthn refuses an IP address, and the RPID is folded into the
 * derivation, so the oracle has to ask the same question the browser does.
 */
'use strict';

const { describe, it } = require('../../lib/harness');
const { PINS } = require('../../lib/config');
const { IFACE, okmsg } = require('../../lib/device');
const ours = require('../../lib/age-pqc');
const webenv = require('../../lib/webenv');
const session = require('../../lib/gui-session-holder');

const RP_ID = 'localhost';
const PAGE = `http://${RP_ID}:3000/app/age-derive`;

const FIELD_DERIVED_KEY_MODE = 21;
/*
 * USER_INPUT_NONE, not a bit.
 *
 * This was 8 - "bit 3" - which is the LEGACY field-21 bitfield encoding. Field
 * 30 is an enum: 0 = challenge code, 1 = button press (the default), 2 = no
 * press. set_slot() refuses anything above USER_INPUT_NONE, so 8 came back as
 * "Error invalid user input mode" and read as a firmware fault. Splitting the
 * enum out of the bitfield is exactly what field 30 exists for (okcore.h), and
 * four files in this section still spoke the old encoding.
 */
const DERIVE_WITHOUT_TOUCH = 2;   // USER_INPUT_NONE

const LABEL = 'age:kit-test';
const PLAINTEXT = 'sealed in a browser, opened by the kit';

describe('the age-derive page', {
  state: 'initialized',
  requires: ['crypto', 'xwing-math', 'client-access', 'display', 'nwjs', 'webapp-lib'],
  timeoutMs: 240000,
}, () => {
  let page = null;
  let third = null;
  let ageFileB64 = null;

  const val = (id) => page.eval(`document.querySelector(${JSON.stringify(`#${id}`)}).value`);

  const setVal = (id, value) => page.eval(`(() => {
    const el = document.querySelector(${JSON.stringify(`#${id}`)});
    el.value = ${JSON.stringify(value)};
    el.dispatchEvent(new Event('input', { bubbles: true }));
    return true;
  })()`);

  it('unlocks the device before anything opens a page',
    async ({ device, assert, signal, skip }) => {
      await device.unlock(PINS.primary, { signal });
      await device.enterConfigMode(PINS.primary, { signal });

      const since = device.mark(IFACE.VENDOR);
      device.sendVendor({
        msg: okmsg.MSG.OKSETSLOT,
        slot: 1,
        field: FIELD_DERIVED_KEY_MODE,
        payload: Buffer.from([DERIVE_WITHOUT_TOUCH]),
      });
      const reply = await device.waitHid(IFACE.VENDOR,
        { since, match: /Successfully set|Error/, timeoutMs: 5000, signal });
      if (/unsupported user input mode/.test(okmsg.text(reply))) {
        skip('this build has OK_ALLOW_NO_PRESS off, so user-input mode 2 (no press) ' +
          'is refused by design - onlykey.h ships it commented out and a stale 2 in ' +
          'EEPROM fails closed to challenge code');
      }
      assert.ok(!/Error/.test(okmsg.text(reply)),
        `setting the derived-key mode failed: ${okmsg.text(reply)}`);

      await device.restart({ signal });
      const model = await device.unlock(PINS.primary, { signal });
      assert.match(model, /^UNLOCKED/, 'the device is not unlocked');

      /* The kit's own way to the same device, for the cross-checks below. */
      const imports = webenv.create(device, { signal, rpId: RP_ID });
      const api = webenv.load(imports, 'onlykey-api.js');
      third = webenv.load(imports, 'onlykey-3rd-party.js', api)();
    });

  it('opens the page', async ({ assert, log }) => {
    page = await session.get().open(PAGE, { timeoutMs: 60000 });
    await page.waitFor('!!document.querySelector("#encrypt_start")', { timeoutMs: 60000 });
    log(`opened ${await page.eval('location.href')}`);

    for (const id of ['label', 'plaintext', 'age_file_out', 'identity_out',
      'decrypt_file_in', 'decrypt_start', 'decrypted_out']) {
      assert.ok(await page.eval(`!!document.querySelector("#${id}")`), `no #${id}`);
    }
  });

  it('turns a label into the identity the CLI would', async ({ assert }) => {
    /*
     * No device in this one - the identity is the label encoded, and the page
     * renders it as you type. It still matters: `age -i` dispatches on that
     * literal prefix, so a page that produced a differently-shaped identity
     * would hand the user a file age cannot even route to a plugin.
     *
     * Checked against this kit's encoder, which 00-sanity checks against
     * python's actual output.
     */
    await setVal('label', LABEL);
    await page.waitFor('document.querySelector("#identity_out").value.length > 0',
      { timeoutMs: 10000 });

    assert.equal(await val('identity_out'), ours.encodeIdentity(LABEL),
      'the page and the kit encode identities differently');
  });

  it('encrypts through the browser', async ({ assert, log }) => {
    page.console.length = 0;

    await setVal('plaintext', PLAINTEXT);
    await page.eval('document.querySelector("#encrypt_start").click()');

    await page.waitFor('document.querySelector("#age_file_out").value.length > 0',
      { timeoutMs: 90000 }).catch(() => {
      throw new Error(`the page produced no age file. Its console: ${
        JSON.stringify(page.console.slice(-8))}`);
    });

    ageFileB64 = await val('age_file_out');
    assert.ok(!/^ERROR/.test(ageFileB64), `the page reported: ${ageFileB64.slice(0, 200)}`);
    log(`age file, ${Buffer.from(ageFileB64, 'base64').length} bytes`);
  });

  it('wrote a real age file, with a real X-Wing stanza', async ({ assert }) => {
    const file = Buffer.from(ageFileB64, 'base64');
    const text = file.toString('latin1');

    assert.ok(text.startsWith('age-encryption.org/v1\n'), 'not an age v1 file');
    assert.match(text, /^--- \S+$/m, 'no header MAC line');

    const stanza = text.match(/^-> mlkem768x25519 (\S+)$/m);
    assert.ok(stanza, 'no X-Wing recipient stanza');
    assert.equal(Buffer.from(stanza[1], 'base64').length, ours.XWING_CT,
      'the stanza does not carry a full 1120-byte X-Wing ciphertext');
  });

  it('reads its own file back', async ({ assert }) => {
    /* The page's own round trip, which is what a user would do. */
    page.console.length = 0;

    await setVal('decrypt_file_in', ageFileB64);
    await page.eval('document.querySelector("#decrypt_start").click()');

    await page.waitFor('document.querySelector("#decrypted_out").value.length > 0',
      { timeoutMs: 90000 }).catch(() => {
      throw new Error(`the page decrypted nothing. Its console: ${
        JSON.stringify(page.console.slice(-8))}`);
    });

    const out = await val('decrypted_out');
    assert.ok(!/^ERROR/.test(out), `the page reported: ${out.slice(0, 200)}`);
    assert.equal(out, PLAINTEXT, 'the page did not recover its own plaintext');
  });

  it('refuses a file that belongs to a different label', async ({ assert }) => {
    /*
     * The label IS the key. A page that decrypted this anyway would mean the
     * derivation ignored its input, and every "separate" identity would be the
     * same one.
     */
    await setVal('label', 'age:some-other-label');
    await setVal('decrypt_file_in', ageFileB64);
    await page.eval('document.querySelector("#decrypted_out").value = ""');
    await page.eval('document.querySelector("#decrypt_start").click()');

    await page.waitFor('document.querySelector("#decrypted_out").value.length > 0',
      { timeoutMs: 90000 });

    const out = await val('decrypted_out');
    assert.match(out, /^ERROR/, `a file for another label decrypted anyway: ${out.slice(0, 120)}`);

    await setVal('label', LABEL);
  });

  it('the kit can open what the browser sealed', async ({ device, assert, signal }) => {
    /*
     * The assertion this file exists for: interoperability, not self-consistency.
     * The browser produced this file through Chromium's WebAuthn over the USB
     * gadget; it is opened here with this kit's own age-pqc and its own CTAP2
     * over the in-process bus. If these two disagree, a file encrypted in the
     * web app cannot be read by anything else - and nobody finds out until it
     * is somebody's data.
     */
    const file = Buffer.from(ageFileB64, 'base64');
    const m = file.toString('latin1').match(/^-> mlkem768x25519 (\S+)$/m);
    const ciphertext = Buffer.from(m[1], 'base64');

    /* The device's two halves, asked for by this kit rather than by the page. */
    const { pkX, seed } = await new Promise((resolve, reject) => {
      third.derive_xwing_recipient(LABEL, false, (err, x, s) => (
        err ? reject(new Error(String(err))) : resolve({ pkX: x, seed: s })
      ));
    });
    const ssX = await new Promise((resolve, reject) => {
      third.derive_xwing_decap(LABEL, Buffer.from(ours.ctXOf(ciphertext)), false,
        (err, s) => (err ? reject(new Error(String(err))) : resolve(s)));
    });

    const shared = ours.splitDecapsulate(
      Buffer.from(ssX), ciphertext, Buffer.from(pkX), Buffer.from(seed)
    );

    const ageFile = webenv.loadPlain('age_file.js');
    const opened = await ageFile.decryptAgeFile(file, async () => shared);

    assert.equal(Buffer.from(opened).toString('utf8'), PLAINTEXT,
      'the kit could not open the file the browser sealed');
  });

  it('closes its window', async ({ assert }) => {
    page.close();
    page = null;
    assert.ok(true, 'window closed');
  });
});
