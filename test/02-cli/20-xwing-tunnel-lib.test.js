/*
 * Derived X-Wing (device custody) over the WebAuthn tunnel, through
 * node-onlykey-lib - the second client for audit #8.
 *
 * 03-gui/03-xwing-derive runs the same round trip through web app 4.0.0 and
 * fails inside the web app's own transit_open(): "message failed
 * authentication" on the device's decapsulation reply. The audit rule is to
 * ask a second, independent client the same question against the same
 * firmware before blaming anyone. This is that client: the library, composed
 * exactly as a browser will compose it (see 19-composite-tunnel-lib), deriving
 * the recipient for a label, encrypting to it host-side, and asking the device
 * to decapsulate - the chunked OKDECRYPT to the web-and-agent derivation slot
 * with [label32 | ct(1120)] that firmware 3.1.0+ requires.
 *
 *   library passes, web app fails  -> the web app's transit handling is wrong
 *   both fail the same way         -> the firmware's reply is suspect
 *
 * Touch-free is set first (field 30 = 2, as 03-gui/02-derive does), so no
 * button press is involved and the result is about the wire alone.
 */
'use strict';

const { describe, it } = require('../../lib/harness');
const { PINS } = require('../../lib/config');
const { IFACE, okmsg } = require('../../lib/device');
const webenv = require('../../lib/webenv');

const FIELD_WEB_AGENT_DERIVE_MODE = 30;   // okcore.cpp case 30
const DERIVE_WITHOUT_TOUCH = 2;           // USER_INPUT_NONE
const LABEL = 'age:personal';
const PLAINTEXT = 'sealed to a derived X-Wing identity, opened by the device';

function composeBrowserStack(device, signal) {
  const Rectify = require('@bmatusiak/rectify');
  const plugins = [
    require('node-onlykey-lib/plugins/host'),
    require('node-onlykey-lib/plugins/transport/tunnel'),
    require('node-onlykey-lib/plugins/session'),
    require('node-onlykey-lib/plugins/device'),
    require('node-onlykey-lib/plugins/okcrypto'),
  ];
  const { createWebAuthnCtap } = require('node-onlykey-lib/transport/webauthn');
  const { window } = webenv.create(device, { signal });
  plugins.config = {
    okcrypto: { ctap: createWebAuthnCtap({ credentials: window.navigator.credentials }) },
  };
  return new Promise((resolve, reject) => {
    const app = Rectify.build(plugins, (err, started) => (err ? reject(err) : resolve(started)));
    app.start();
  });
}

describe('derived X-Wing over the WebAuthn tunnel, through node-onlykey-lib', {
  state: 'initialized',
  requires: ['crypto', 'client-access', 'xwing-math'],
  timeoutMs: 180000,
}, () => {
  let app = null;
  let okcrypto = null;
  let recipient = null;

  it('sets derivation without a touch, and composes the browser stack',
    async ({ device, assert, signal }) => {
      await device.unlock(PINS.primary, { signal });
      await device.enterConfigMode(PINS.primary, { signal });
      const since = device.mark(IFACE.VENDOR);
      device.sendVendor({
        msg: okmsg.MSG.OKSETSLOT, slot: 1, field: FIELD_WEB_AGENT_DERIVE_MODE,
        payload: Buffer.from([DERIVE_WITHOUT_TOUCH]),
      });
      const reply = await device.waitHid(IFACE.VENDOR,
        { since, match: /Successfully set|Error/, timeoutMs: 5000, signal });
      const text = okmsg.text(reply);
      await device.restart({ signal });
      await device.unlock(PINS.primary, { signal });
      assert.ok(!/Error/.test(text), `setting field 30 failed: ${text}`);

      app = await composeBrowserStack(device, signal);
      okcrypto = app.services.okcrypto;
      const connected = await okcrypto.connectTunnel();
      assert.equal(connected.capabilities.xwingDeviceCustody, true,
        'this firmware should do X-Wing in device custody');
    });

  it('derives the recipient for a label', async ({ assert, log }) => {
    const id = await okcrypto.deviceAge.identity(LABEL);
    recipient = id.recipient || id.publicKey || id;
    log(`recipient ${Buffer.from(recipient).toString('hex').slice(0, 24)}…`);
    assert.equal(Buffer.from(recipient).length, 1216, 'an X-Wing recipient is 1216 bytes');
  });

  it('decapsulates on the device - chunked OKDECRYPT, sealed, v2 reply opened', async ({ assert }) => {
    const sealed = await okcrypto.deviceAge.encrypt(Buffer.from(PLAINTEXT), recipient);
    const opened = await okcrypto.deviceAge.decrypt(sealed, LABEL);
    assert.equal(Buffer.from(opened).toString('utf8'), PLAINTEXT,
      'the device did not open a file sealed to its own derived recipient');
  });

  it('tears the stack down', async () => {
    if (app) await app.destroy();
  });
});
