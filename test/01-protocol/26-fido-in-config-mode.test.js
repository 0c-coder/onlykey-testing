/*
 * The FIDO2 interface does not answer while the device is in CONFIG MODE.
 *
 * That is this file's claim and it is PINNED, not merely observed - see the
 * assertions in the third test. WebAuthn and U2F are both unavailable to a user
 * who has put the device in config mode, which means a login that would
 * otherwise work simply does not, with no error from the device: the endpoint
 * is silent rather than refusing. Written up in
 * FINDING-fido-silent-in-config-mode.md.
 *
 * By source-read it should be the opposite: `configmode` appears nowhere in
 * `libraries/fido2/` at all, and okcore.cpp's config-mode allow-list at line
 * 347 filters the RAW-HID dispatch (`process_packets`), which is a different
 * entry point from `bridge_to_onlykey()`. The source read was wrong, which is
 * the reason to measure rather than reason about this firmware's cross-path
 * globals - `pending_operation` and `packet_buffer_details[3]` are both
 * rewritten by the raw-HID pipeline while a FIDO2 request is in flight.
 *
 * It also settles a design question that is now parked: a browser cannot load a
 * key onto the device, because loading needs config mode and config mode has no
 * WebAuthn. That holds regardless of which command the bridge might grow.
 *
 * TWO LAYERS, because they can fail separately and only one of them is the
 * interesting answer:
 *
 *   1. plain CTAP2 (init / getInfo / getAssertion) - is the FIDO stack alive?
 *   2. the OnlyKey BRIDGE (OKCONNECT through onlykey-api.js) - is
 *      `bridge_to_onlykey()` reachable, which is the path a load would use?
 *
 * A pass at layer 1 and a failure at layer 2 would be the finding; a failure at
 * layer 1 makes layer 2 moot.
 *
 * This file asserts CAPABILITY, not that anything should be loaded. It writes
 * no keys and leaves config mode by reboot, which is the only way out of it.
 *
 * SURFACE: FIDO (0xF1D0) throughout, plus the keyboard surface to enter config
 * mode. Both survive into a production walk.
 */
'use strict';

const crypto = require('crypto');

const { describe, it } = require('../../lib/harness');
const { PINS } = require('../../lib/config');
const { Ctap2 } = require('../../lib/device/ctap2');
const { IFACE, okmsg } = require('../../lib/device');
const webenv = require('../../lib/webenv');

const RP_ID = 'okt.test';

describe('the FIDO2 path in config mode', {
  state: 'initialized',
  requires: ['crypto'],
  timeoutMs: 180000,
}, () => {
  /*
   * BEFORE / DURING / AFTER, in one session, and the structure is the point.
   *
   * A bare "CTAPHID INIT timed out in config mode" has too many causes to be a
   * finding - an unattached FIDO interface, a device still busy from the long
   * press, a harness fault. Measuring the same call on the same device
   * immediately before and immediately after removes all three: if it answers,
   * then stops answering, then answers again, the only variable left is config
   * mode.
   */
  const ctaphidAnswers = async (device) => {
    const ctap = new Ctap2(device, {});
    try {
      const cid = await ctap.init();
      return cid.length === 4 && cid.toString('hex') !== 'ffffffff';
    } catch {
      return false;
    }
  };

  let before = null;
  let during = null;
  let duringBridge = null;
  let after = null;

  it('answers CTAPHID before config mode - the instrument works',
    async ({ device, assert, signal, log }) => {
      await device.unlock(PINS.primary, { signal });
      before = await ctaphidAnswers(device);
      log(`CTAPHID INIT before config mode: ${before ? 'answered' : 'no reply'}`);

      assert.control('the FIDO interface answers this device in this session', before);
      assert.ok(before,
        'CTAPHID INIT does not answer even outside config mode - this file cannot '
        + 'measure anything until that is fixed');
    });

  it('stops answering once the device is in config mode',
    async ({ device, assert, signal, log }) => {
      await device.enterConfigMode(PINS.primary, { signal });

      during = await ctaphidAnswers(device);
      log(`CTAPHID INIT in config mode: ${during ? 'answered' : 'no reply'}`);

      /*
       * The bridge layer too, for completeness - though if CTAPHID itself is
       * silent this cannot succeed either, and its value is in saying so
       * explicitly rather than leaving the reader to infer it.
       */
      duringBridge = await (async () => {
        try {
          /*
           * The web app's connect, as it runs now: node-onlykey-lib's browser
           * stack (the web app's own in-repo library is gone) doing a plain
           * OKCONNECT over the tunnel.
           */
          const { okcrypto } = await webenv.browserLib(device, { signal, connect: false });
          /*
           * BOUNDED, and it has to be. A WebAuthn assertion on a device whose
           * FIDO endpoint is silent simply never arrives; left unbounded it does
           * not fail, it hangs, and the run dies on the inactivity watchdog with
           * no result recorded. Measured: exactly that, for 30s, the first time
           * this test ran (against the web app's former library).
           */
          const handshake = okcrypto.connectTunnel({ timeoutMs: 8000 })
            .then((answer) => Boolean(answer && answer.status), () => false);

          return await Promise.race([
            handshake,
            device.sleep(8000, { signal }).then(() => false),
          ]);
        } catch {
          return false;
        }
      })();
      log(`OKCONNECT over the bridge in config mode: ${duringBridge ? 'handshook' : 'no reply'}`);

      /*
       * PINNED, not merely recorded. This asserts CURRENT firmware behaviour:
       * the FIDO2 endpoint does not answer in config mode. The question this
       * file was written to answer is closed, so leaving it green either way
       * would mean a firmware change that made FIDO live in config mode passed
       * silently - and that change would be worth noticing, both because it
       * would revive in-app key loading and because it would widen what the
       * device exposes in its most privileged state.
       *
       * Same convention as 02-cli/14-cli-fido: where the outcome is
       * deterministic, pin the wording, and let the test fail on the day the
       * behaviour changes. If that day comes, this failure is the notification
       * rather than a regression - update the file and FINDING-fido-silent-in-
       * config-mode.md together.
       */
      assert.equal(during, false,
        'CTAPHID now answers in config mode - firmware behaviour has changed. '
        + 'This test pinned the opposite; see FINDING-fido-silent-in-config-mode.md');
      assert.equal(duringBridge, false,
        'the OnlyKey WebAuthn bridge now handshakes in config mode - firmware '
        + 'behaviour has changed. This test pinned the opposite');
    });

  it('answers CTAPHID again after rebooting out of config mode',
    async ({ device, assert, signal, log }) => {
      /* A reboot is the only exit from config mode. */
      await device.restart({ signal });
      await device.unlock(PINS.primary, { signal });

      after = await ctaphidAnswers(device);
      log(`CTAPHID INIT after leaving config mode: ${after ? 'answered' : 'no reply'}`);

      assert.ok(after,
        'CTAPHID INIT does not answer after leaving config mode either, so the '
        + 'silence measured above was not caused by config mode');
    });

  it('reports what the three measurements mean together',
    async ({ assert, log }) => {
      log(`before=${before}  during=${during}  duringBridge=${duringBridge}  after=${after}`);

      log('the FIDO2 path is NOT serviced in config mode: it answers before and '
        + 'after and is silent in between. WebAuthn and U2F are therefore both '
        + 'unavailable to a user while the device is in config mode.');

      /*
       * The controls, restated as an assertion so the file cannot report its
       * finding on the strength of a measurement that meant nothing. `during`
       * is pinned in the test above; what is checked here is that the pin was
       * worth making - a `during === false` sitting between two other failures
       * would say nothing about config mode at all.
       */
      assert.ok(before && after,
        'the before/after controls did not both pass, so the config-mode '
        + 'measurement between them says nothing');

      void crypto;
      void RP_ID;
      void IFACE;
      void okmsg;
    });
});
