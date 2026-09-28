/*
 * The App's User Input Modes and Webcrypt Access forms, end to end: the form
 * writes the field, the device acknowledges that field by name, and - out of
 * config mode - the key BEHAVES as the form said.
 *
 * These are the settings the v3.0.5 release notes send users to. Web PGP with
 * stored keys is off after the upgrade (field 31 bit 0), and "Allow Webcrypt
 * to use my stored keys (PGP)" is how a person turns it on without a command
 * line; field 30 = "no press" is the unattended-agent setting. A form that
 * wrote the wrong field, or the right field with the wrong byte, would pass a
 * test that only looked for "Successfully set", so both halves are checked:
 *
 *   ACKNOWLEDGEMENT  each write answers with its own string - "derived key
 *                    challenge mode", "stored key challenge mode", "web and
 *                    agent derived key mode", "webcrypt policy" - so the
 *                    field is proven, and three writes sent back to back by
 *                    submitUserInputModes() must ALL arrive.
 *   EFFECT           field 30 = none: a derived X-Wing decapsulation over USB
 *                    answers with no press (a press-mode key would wait for a
 *                    button the kit never presses). Field 31 bit 0: a stored-
 *                    slot OKSIGN over FIDO2 from a trusted origin is not
 *                    refused - checkable only where the origin table is
 *                    enforced; on a DEBUG build (trust-all) that half skips
 *                    and says so.
 *
 * The writes need config mode and the effects need it left, so the device is
 * restarted between. Defaults are restored in `finally` (21 = 0, 22 = 0,
 * 30 = 1, 31 = 0) over the vendor interface.
 *
 * RUN IT UNDER THE nw.js THE APP SHIPS WITH (0.71.x): OKT_NW_BINARY pointing
 * at an nwjs-sdk-v0.71.1 `nw`. Under nw.js 0.114 the App's window never leaves
 * document.readyState 'loading', its load handler never creates myOnlyKey,
 * and every 04-app test that needs the device fails in waitForDevice - for
 * upstream OnlyKey-App too. See TODO.md.
 */
'use strict';

const crypto = require('crypto');

const { describe, it } = require('../../lib/harness');
const { IFACE, okmsg } = require('../../lib/device');
const { Ctap2 } = require('../../lib/device/ctap2');
const tunnel = require('../../lib/device/tunnel');
const transit = require('../../lib/device/transit');
const { PINS } = require('../../lib/config');
const pqc = require('../../lib/pqc');

const session = require('../../lib/app-session-holder');

const ACK = /Successfully set|Error/;
const DEFAULTS = [[21, 0], [22, 0], [30, 1], [31, 0]];
const REFUSED = /stored key use over FIDO2 not enabled/;

/* A 1152-byte derived decapsulation request: [tag | ct(1120)]. X-Wing never
 * fails on a well-formed length, so any ciphertext yields a secret. */
const PAYLOAD = Buffer.concat([
  crypto.createHash('sha256').update('app-17', 'utf8').digest(),
  Buffer.alloc(1120, 0x5A),
]);

async function showPanel(page, showId) {
  await page.eval(`(() => {
    const el = document.getElementById(${JSON.stringify(showId)});
    if (!el) throw new Error('no such panel control: ' + ${JSON.stringify(showId)});
    el.click();
  })()`);
}

/** Tick radios / checkboxes by id, then press a button - what a user does. */
async function clickThrough(page, { check = [], uncheck = [], press }) {
  const result = await page.eval(`(() => {
    for (const id of ${JSON.stringify(check)}) {
      const el = document.getElementById(id);
      if (!el) return 'no such control: ' + id;
      el.checked = true;
      el.dispatchEvent(new Event('change', { bubbles: true }));
    }
    for (const id of ${JSON.stringify(uncheck)}) {
      const el = document.getElementById(id);
      if (!el) return 'no such control: ' + id;
      el.checked = false;
      el.dispatchEvent(new Event('change', { bubbles: true }));
    }
    const btn = document.getElementById(${JSON.stringify(press)});
    if (!btn) return 'no such button: ' + ${JSON.stringify(press)};
    btn.click();
    return 'pressed';
  })()`);
  if (result !== 'pressed') throw new Error(result);
}

/** Every vendor text after `since` that is an acknowledgement, collected for `ms`. */
async function acks(device, since, ms, { signal }) {
  await device.sleep(ms, { signal });
  return device.reportsSince(IFACE.VENDOR, since)
    .map((r) => okmsg.text(r).trim()).filter((t) => ACK.test(t));
}

async function restoreDefaults(device, { signal }) {
  await pqc.readyForKeygen(device, { signal });
  for (const [field, value] of DEFAULTS) {
    const since = device.mark(IFACE.VENDOR);
    device.sendVendor({ msg: okmsg.MSG.OKSETSLOT, slot: 1, field, payload: Buffer.from([value]) });
    await device.waitHid(IFACE.VENDOR, { since, match: ACK, timeoutMs: 8000, signal });
  }
  await device.restart({ signal });
  await device.ensureUnlocked(PINS.primary, { signal });
}

/** OKCONNECT from `rpId`; null session if refused. */
async function handshake(ctap, rpId, { signal }) {
  const ours = transit.keypair();
  try {
    const reply = await tunnel.send(ctap, {
      cmd: okmsg.MSG.OKCONNECT, data: transit.connectPayload(ours.publicKey),
    }, { rpId, timeoutMs: 30000, signal });
    if (!reply || !reply.data || reply.data.length < 32) return null;
    return transit.session(transit.transitKey(reply.data.subarray(0, 32), ours.privateKey));
  } catch {
    return null;
  }
}

describe('App: user input modes and Webcrypt access', {
  state: 'initialized',
  requires: ['client-access', 'display', 'nwjs', 'crypto'],
  timeoutMs: 300000,
}, () => {
  it('the forms write the fields they show, and the key then behaves that way',
    async ({ device, assert, signal, log, skip }) => {
      const s = session.get();
      try {
        /* ---- write, in config mode, through the App ---------------------- */
        /* Let the App hold a connection BEFORE the config-mode restart, so it
         * sees the removal and the re-add (see 15-app-advanced for the
         * measured failure the other order produces). */
        await device.ensureUnlocked(PINS.primary, { signal });
        const page = await s.attach('app');
        let modes; let policy;
        try {
          await s.waitForDevice(page, device, { signal, log });
          await pqc.readyForKeygen(device, { signal });
          await s.waitForDevice(page, device, { signal, log });
          await showPanel(page, 'show-pref-panel');

          let since = device.mark(IFACE.VENDOR);
          await clickThrough(page, {
            check: ['derivedKeyBtnPress', 'storedKeyBtnPress', 'webAgentDeriveNoInput'],
            press: 'userInputModesSaveBtn',
          });
          modes = await acks(device, since, 4000, { signal });
          log(`user input modes: ${JSON.stringify(modes)}`);

          since = device.mark(IFACE.VENDOR);
          await clickThrough(page, {
            check: ['webAllowStoredKey'], uncheck: ['webDisableExtension'],
            press: 'webcryptPolicySaveBtn',
          });
          policy = await acks(device, since, 3000, { signal });
          log(`webcrypt access: ${JSON.stringify(policy)}`);
        } finally {
          page.close();
        }

        for (const want of ['Successfully set derived key challenge mode',
          'Successfully set stored key challenge mode',
          'Successfully set web and agent derived key mode']) {
          assert.ok(modes.includes(want),
            `"${want}" never came back - submitUserInputModes() sends three writes back to ` +
            `back and this one did not land (got ${JSON.stringify(modes)})`);
        }
        assert.ok(!modes.some((m) => /^Error/.test(m)), `an input-mode write was refused: ${JSON.stringify(modes)}`);
        assert.equal(policy.length, 1, `expected one acknowledgement for Webcrypt access, got ${JSON.stringify(policy)}`);
        assert.equal(policy[0], 'Successfully set webcrypt policy', 'the Webcrypt access write');

        /* ---- effect, out of config mode ---------------------------------- */
        await device.restart({ signal });
        await device.ensureUnlocked(PINS.primary, { signal });

        /* Open the CTAPHID channel FIRST, before any vendor traffic of our own.
         * The first FIDO packet after an unlock is where the firmware picks the
         * interface FIDO answers go out on (okcore.cpp, the `!useinterface`
         * Android workaround): it waits 100 ms, reads ONE MORE report from any
         * interface, and if there is one it replaces the FIDO packet with it
         * and answers on that report's interface. With the App open, the App
         * answers our decapsulation reply with vendor traffic of its own, and
         * an INIT sent right after it was replaced by the App's packet and
         * never answered (measured 2026-09-23: lost in all 7 runs that sent it
         * right after the decap, answered in every run that sent it first or
         * 5 s later). See the FINDING in TODO.md. */
        const ctap = new Ctap2(device, { signal });
        await ctap.init();
        log('CTAPHID channel open');

        /* Field 30 = none: decapsulation answers without a press. */
        let since = device.mark(IFACE.VENDOR);
        for (let off = 0; off < PAYLOAD.length; off += 57) {
          const part = PAYLOAD.subarray(off, off + 57);
          const last = off + 57 >= PAYLOAD.length;
          device.sendVendor({ msg: okmsg.MSG.OKDECRYPT, slot: 128, field: last ? part.length : 0xFF, payload: part });
        }
        const reply = await device.waitHid(IFACE.VENDOR,
          { since, match: (b) => okmsg.text(b) !== 'INITIALIZED', timeoutMs: 8000, signal })
          .catch(() => null);
        const said = reply ? okmsg.text(reply) : '(nothing within 8 s)';
        log(`derived decapsulation answered: ${reply ? `${reply.length} bytes, "${said.slice(0, 40)}"` : said}`);
        assert.ok(reply && !/^(Error|Timeout)/.test(said),
          `with "No confirmation" chosen in the App, a derived decapsulation did not answer ` +
          `unattended: ${said}`);

        /* Field 31 bit 0: a trusted origin's stored-slot OKSIGN is not refused. */
        if (await handshake(ctap, 'example.com', { signal })) {
          log('this build admits an untrusted origin (DEBUG trust-all): the policy effect cannot be seen here');
          return;
        }
        const sess = await handshake(ctap, 'apps.onlykey.io', { signal });
        assert.control('a trusted origin completes the handshake', !!sess);
        const r = await tunnel.send(ctap, {
          cmd: okmsg.MSG.OKSIGN, opt1: 2, opt2: 1, opt3: 1,
          data: transit.seal(sess, Buffer.alloc(32, 0xA5)),
        }, { rpId: 'apps.onlykey.io', timeoutMs: 30000, signal }).catch((e) => ({ error: e.message }));
        log(`stored-slot OKSIGN answered: ${r.error || r.status}`);
        assert.absent(!REFUSED.test(r.error || ''),
          'with "Allow Webcrypt to use my stored keys (PGP)" ticked in the App, the device still ' +
          'refused a stored-key request - the checkbox did not set field 31 bit 0');
      } finally {
        await restoreDefaults(device, { signal });
      }
    });
});
