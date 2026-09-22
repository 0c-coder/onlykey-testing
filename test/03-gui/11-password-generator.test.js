/*
 * Section 3, browser tier: the password-generator page, in a real Chromium,
 * against a real device.
 *
 * This is the first test in the kit where the DEVICE CALL GOES THROUGH THE
 * BROWSER. Everything below it in section 3 reaches the device by handing the
 * library a shim; here Chromium's own WebAuthn stack does it, over the USB
 * gadget, exactly as it would for somebody at onlykey.github.io. That is the
 * one thing the headless tier cannot prove, and the only reason to pay for a
 * display.
 *
 * What makes it worth having is the pairing. 02-derive already proved
 * derive_public_key and derive_shared_secret work when called directly, so if
 * this fails the page is at fault - the wiring, the ids, the click handler -
 * rather than the device or the library. That is the whole argument for two
 * tiers, and it only pays off if both exist.
 *
 * The assertion is a cross-check rather than a shape check: the same phrase is
 * derived twice, once by the page through Chromium and once by this kit through
 * its own CTAP2 over the in-process bus, and the two have to produce the same
 * secret. Two clients, two transports, one device. A page that merely put SOME
 * string in the output box would pass a "not empty" test and fail this one.
 *
 * ORDER MATTERS AND IS NOT NEGOTIABLE. The device is unlocked BEFORE the page
 * opens. An app page loaded against a locked device times out its startup
 * OKCONNECT, and Chromium then raises a native WebAuthn dialog that no CDP
 * command can dismiss - which wedges the whole session, not just this file.
 */
'use strict';

const { describe, it } = require('../../lib/harness');
const { PINS } = require('../../lib/config');
const { IFACE, okmsg } = require('../../lib/device');
const webenv = require('../../lib/webenv');
const session = require('../../lib/gui-session-holder');

/*
 * localhost, NOT 127.0.0.1, and the difference is not cosmetic.
 *
 * The library asks for a WebAuthn assertion with `rpId = window.location.hostname`.
 * WebAuthn does not accept an IP address as a relying-party id, so a page served
 * from 127.0.0.1 fails with "SecurityError: This is an invalid domain." before
 * the device is ever contacted - and the page swallows it, so the only symptom
 * is an output box that never fills. `localhost` is special-cased by the spec
 * and works. The old kit used it too; this is why.
 *
 * The rpId used to be folded into the derivation - okcrypto_hkdf() v1 read it
 * out of ctap_buffer - so a page on localhost derived a DIFFERENT key from one
 * on onlyagent.app, with no error anywhere. v2 (2026-09-22) has no origin in
 * it, so that is no longer true; the oracle below still asks for the same rpId
 * the browser will, which costs nothing and keeps this file independent of
 * that decision. 01-protocol/30-derive-no-origin is what pins it.
 */
const ORIGIN = 'http://localhost:3000';
const RP_ID = 'localhost';
const PAGE = `${ORIGIN}/app/password-generator`;

/* See 02-derive: without this the device refuses a touch-free derivation, and
 * says so as CTAP2_ERR_EXTENSION_NOT_SUPPORTED. */
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

const KEYTYPE_P256R1 = 1;
const PHRASE = 'kit-test-site.example';

describe('the password-generator page', {
  state: 'initialized',
  requires: ['crypto', 'client-access', 'display', 'nwjs', 'webapp-lib'],
  timeoutMs: 240000,
}, () => {
  let page = null;
  let expected = null;

  it('unlocks the device before anything opens a page',
    async ({ device, assert, signal, skip }) => {
      /*
       * A visible step, and the first one deliberately: everything after it
       * depends on the device being unlocked, and the failure it prevents is
       * not a failed test but a wedged session.
       */
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
    });

  it('derives the answer the page should reach', async ({ device, assert, signal, log }) => {
    /*
     * Computed HERE, through the kit's own transport, before the browser is
     * involved at all. This is the oracle the page is checked against, and
     * taking it first means a later disagreement cannot be explained away by
     * the device having changed.
     */
    const imports = webenv.create(device, { signal, rpId: RP_ID });
    const api = webenv.load(imports, 'onlykey-api.js');
    const third = webenv.load(imports, 'onlykey-3rd-party.js', api)();

    const pub = await new Promise((resolve, reject) => {
      third.derive_public_key(PHRASE, KEYTYPE_P256R1, false,
        (err, key) => (err ? reject(new Error(String(err))) : resolve(key)));
    });
    expected = await new Promise((resolve, reject) => {
      third.derive_shared_secret(PHRASE, pub, KEYTYPE_P256R1, false,
        (err, key) => (err ? reject(new Error(String(err))) : resolve(key)));
    });

    log(`expecting ${String(expected).slice(0, 24)}…`);
    assert.ok(expected, 'the kit could not derive the secret itself');
  });

  it('opens the page', async ({ assert, log }) => {
    const s = session.get();
    page = await s.open(PAGE, { timeoutMs: 60000 });

    /* The app is a single-page thing that renders after its scripts run, so
     * the fields are what to wait for, not the load event. */
    await page.waitFor('!!document.querySelector("#onlykey_start")', { timeoutMs: 60000 });
    log(`opened ${await page.eval('location.href')}`);

    assert.ok(await page.eval('!!document.querySelector("#phrase")'), 'no phrase field');
    assert.ok(await page.eval('!!document.querySelector("#phrase_out")'), 'no output field');
  });

  it('derives a password through the browser', async ({ assert, log }) => {
    /*
     * Driven the way a person would: type into the field, click the button.
     * Calling the library from the page's console instead would test the same
     * thing the headless tier already covers and skip the only part that is
     * new - that the page is wired to it correctly.
     *
     * The page swallows its errors (`if (error) return;` on both callbacks), so
     * a failure leaves the output box empty and says nothing. The wait below is
     * therefore the real error report, which is why it names what it wanted.
     */
    page.console.length = 0;

    await page.eval(`(() => {
      const el = document.querySelector('#phrase');
      el.value = ${JSON.stringify(PHRASE)};
      el.dispatchEvent(new Event('input', { bubbles: true }));
      document.querySelector('#onlykey_start').click();
      return true;
    })()`);

    await page.waitFor('document.querySelector("#phrase_out").value.length > 0',
      { timeoutMs: 90000 }).catch(() => {
      throw new Error(
        'the page produced no password. It swallows both callbacks\' errors, so ' +
        `the only account is its console: ${JSON.stringify(page.console.slice(-8))}`
      );
    });

    const shown = await page.eval('document.querySelector("#phrase_out").value');
    log(`page produced ${String(shown).slice(0, 24)}…`);
    assert.ok(shown, 'the output field is empty');
  });

  it('produced the same secret the kit did', async ({ assert }) => {
    /*
     * The cross-check. Chromium's WebAuthn over the USB gadget on one side,
     * this kit's CTAP2 over the in-process bus on the other, one device
     * underneath - and a disagreement would say the two transports do not
     * derive the same key, which no single-client test could tell you.
     */
    const shown = await page.eval('document.querySelector("#phrase_out").value');

    assert.equal(String(shown), String(expected),
      'the page and the kit derived different secrets for the same phrase');
  });

  it('closes its window', async ({ assert }) => {
    /* Visible, like the services themselves. A window left open holds a device
     * handle, and the next file's page would be fighting it for the device. */
    page.close();
    page = null;
    assert.ok(true, 'window closed');
  });
});
