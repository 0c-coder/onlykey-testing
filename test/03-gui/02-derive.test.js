/*
 * Section 3, headless: derived keys, through the library the web app uses.
 *
 * `derive_public_key` and `derive_shared_secret` are what the password-generator
 * and vault pages are built on, and they are the pair the old kit only ever
 * reached through a browser (14-gui-password-generator). Reached from Node they
 * need no display and no USB, so what was a GUI test becomes something CI can
 * run - and when the GUI test is eventually written, a failure there with a pass
 * here says the PAGE is wrong rather than the device.
 *
 * The derivation is a device secret plus data the host supplies: the device
 * holds the derivation key and never emits it, and the same input always
 * produces the same key, which is the entire premise of "a different password
 * per site with nothing stored anywhere". Both properties are asserted below,
 * because neither is visible from a single successful call.
 *
 * press_required is false throughout. That is the "derived keys per site
 * without touch" path, and it is a device setting rather than a client choice
 * (derived_key_challenge_mode); if a device demands the press, these calls
 * simply never come back, so the file bounds itself rather than sitting there.
 */
'use strict';

const { describe, it } = require('../../lib/harness');
const { PINS } = require('../../lib/config');
const { IFACE, okmsg } = require('../../lib/device');
const webenv = require('../../lib/webenv');

/*
 * The device setting that allows derivation without a finger on the button.
 *
 * python-onlykey calls it `derivedkeymode`, the firmware calls the field
 * SSHCHALENGEMODE (21), and it is an ordinary OKSETSLOT on slot 1 - so this kit
 * can set it over its own vendor interface rather than shelling to onlykey-cli.
 * That matters: reaching for the CLI would drag `client-access` in and take this
 * file out of CI, which is most of what it is for.
 *
 * Bit 3 is "derived keys per site without touch". Without it the firmware
 * refuses the tunnelled derive outright, and the refusal arrives as
 * CTAP2_ERR_EXTENSION_NOT_SUPPORTED - which reads like the request being
 * malformed rather than a setting being off.
 */
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

/* onlykey-3rd-party.js's own KEYTYPE. P256R1 is the one the password-generator
 * page uses, and the only one whose derive pair does a real ECDH. */
const KEYTYPE = { NACL: 0, P256R1: 1, P256K1: 2, CURVE25519: 3 };
const NO_PRESS = false;

describe('derived keys, through the web app\'s library', {
  state: 'initialized',
  requires: ['crypto', 'webapp-lib'],
  timeoutMs: 60000,
}, () => {
  let third = null;

  const verbose = () => (process.env.OKT_WEBLIB_VERBOSE === 'yes' ? console : undefined);

  /**
   * The library's callback style, as a promise that always settles.
   *
   * The bound is not belt-and-braces. Every failure path in these two functions
   * returns without calling the callback - `if (!response.data) { ...; return; }`
   * and anything thrown inside the async `.then()` - so a device that answers
   * unusably is indistinguishable from one that never answered, and both
   * present as the test hanging until a watchdog names the wrong thing. This
   * turns that into a sentence.
   */
  const settle = (name, fn, ms = 25000) => new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(
      `${name} never called its callback within ${ms}ms - the library returns ` +
      'without calling back on every failure path, so the device probably ' +
      'answered something it could not use'
    )), ms);
    fn((err, value) => {
      clearTimeout(timer);
      if (err) reject(new Error(String(err)));
      else resolve(value);
    });
  });

  const derivePublic = (ok, data, keytype) => settle('derive_public_key',
    (cb) => ok.derive_public_key(data, keytype, NO_PRESS, cb));

  const deriveShared = (ok, data, pubkey, keytype) => settle('derive_shared_secret',
    (cb) => ok.derive_shared_secret(data, pubkey, keytype, NO_PRESS, cb));

  it('allows derivation without a touch', async ({ device, assert, signal, skip }) => {
    /*
     * A visible step, because it changes the DEVICE rather than the test, and
     * because the failure it prevents does not look like a missing setting: the
     * firmware answers a tunnelled derive with CTAP2_ERR_EXTENSION_NOT_SUPPORTED,
     * and the library then returns without calling its callback, so the whole
     * thing presents as a hang in a function that never mentions settings.
     *
     * The mode fields are guarded by mod_keys_enabled, so this needs config
     * mode - which then has to be left again, because config mode is an
     * allow-list of eleven vendor messages and nothing else gets through.
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
    const text = okmsg.text(reply);
    if (/unsupported user input mode/.test(text)) {
      skip('this build has OK_ALLOW_NO_PRESS off, so user-input mode 2 (no press) is ' +
        'refused by design - onlykey.h ships it commented out and a stale 2 in EEPROM ' +
        'fails closed to challenge code. There is no no-touch derivation to test here');
    }
    assert.ok(!/Error/.test(text), `setting the derived-key mode failed: ${text}`);

    /* The only way out of config mode, and it re-locks on the way. */
    await device.restart({ signal });
    const model = await device.unlock(PINS.primary, { signal });
    assert.match(model, /^UNLOCKED/, 'the device did not come back unlocked');
  });

  it('builds the third-party api', async ({ device, assert, signal }) => {
    /*
     * After the reboot above, deliberately: a Ctap2 channel belongs to one boot,
     * and an api built before the restart would be holding a channel the device
     * no longer knows about.
     *
     * Two-stage construction, and the shape is the library's own - the module is
     * function (imports, onlykeyApi) returning a factory that takes nothing. The
     * page does exactly this, down to the no-op arguments it passes.
     */
    const imports = webenv.create(device, { signal, console: verbose() });
    const api = webenv.load(imports, 'onlykey-api.js');
    const factory = webenv.load(imports, 'onlykey-3rd-party.js', api);
    third = factory();

    assert.ok(typeof third.derive_public_key === 'function', 'no derive_public_key');
    assert.ok(typeof third.derive_shared_secret === 'function', 'no derive_shared_secret');
  });

  it('derives a public key for a passphrase', async ({ assert, signal, log }) => {
    const key = await derivePublic(third, 'a passphrase for a site', KEYTYPE.P256R1);
    log(`derived ${String(key).slice(0, 24)}…`);

    assert.ok(key, 'the device returned no derived public key');
    assert.ok(String(key).length > 16, `implausibly short derived key: ${key}`);
  });

  it('derives the same key for the same passphrase, every time', async ({ assert, signal }) => {
    /*
     * The property the whole feature rests on. Nothing is stored - not on the
     * device, not in the browser - so a derived password only exists because
     * the same input reproduces it. If this were not stable, every site's
     * password would silently become a new one on the next visit.
     */
    const once = await derivePublic(third, 'a passphrase for a site', KEYTYPE.P256R1);
    const twice = await derivePublic(third, 'a passphrase for a site', KEYTYPE.P256R1);

    assert.equal(String(twice), String(once), 'the same passphrase derived two different keys');
  });

  it('derives a different key for a different passphrase', async ({ assert, signal }) => {
    /*
     * The other half, and not a formality: this exact case is what caught a
     * real bug in the library's own history. Uint8Array.from() on a string
     * coerces every character with Number(), so every letter became 0 and two
     * different passphrases of the same LENGTH derived the same key. The
     * comment recording that sits at the top of onlykey-3rd-party.js; this is
     * the assertion that would have caught it.
     */
    const a = await derivePublic(third, 'one passphrase', KEYTYPE.P256R1);
    const b = await derivePublic(third, 'two passphrase', KEYTYPE.P256R1);

    assert.notEqual(String(a), String(b),
      'two different passphrases of the same length derived the same key');
  });

  it('derives a shared secret against that public key', async ({ assert, signal, log }) => {
    /*
     * The second half of the pair, and what the page actually uses: derive a
     * public key, hand it back to the device, and get the ECDH shared secret
     * the password is made from.
     */
    const pub = await derivePublic(third, 'a passphrase for a site', KEYTYPE.P256R1);
    const secret = await deriveShared(third, 'a passphrase for a site', pub, KEYTYPE.P256R1);
    log(`shared secret ${String(secret).slice(0, 24)}…`);

    assert.ok(secret, 'the device returned no shared secret');
    assert.notEqual(String(secret), String(pub),
      'the shared secret is just the public key back again');

    const again = await deriveShared(third, 'a passphrase for a site', pub, KEYTYPE.P256R1);
    assert.equal(String(again), String(secret), 'the shared secret is not stable');
  });
});
