/*
 * The vendor interface (RawHID2, usage page 0xFFAB) - the one the app, the CLI
 * and lib-agent all speak, driven here from Node with no kernel device node
 * anywhere in the path.
 *
 * The device has three quite different behaviours depending on its state, and
 * anything that reads its status has to know which one it is looking at:
 *
 *   locked        answers nothing, but broadcasts "INITIALIZED" once a second
 *                 whether anyone asked or not
 *   unlocked      answers OKCONNECT, and printed the model string on unlock
 *   uninitialized broadcasts nothing at all - there is no HID task for it
 */
'use strict';

const { describe, it } = require('../../lib/harness');
const { IFACE, okmsg } = require('../../lib/device');
const { PINS } = require('../../lib/config');
const { deviceModel, isDuo, MODEL_LETTER } = require('../../lib/model');

describe('vendor interface', { state: 'initialized', requires: ['crypto'] }, () => {
  it('broadcasts INITIALIZED while locked, unprompted', async ({ device, assert, signal }) => {
    const since = device.mark(IFACE.VENDOR);

    /*
     * Nothing is sent here. taskInitialized(1000) is a firmware task that
     * broadcasts purely because the device is locked, which is why a short read
     * window can miss it entirely - not a latency problem, a "did my window
     * overlap the next broadcast" problem. Waiting for two spans a full
     * interval regardless of phase.
     */
    const first = await device.waitHid(IFACE.VENDOR, { since, timeoutMs: 2500, signal });
    /* HW_MODEL-style suffix on a DUO only: sendInitialized() says INITIALIZED-D there. */
    assert.equal(okmsg.text(first), isDuo() ? 'INITIALIZED-D' : 'INITIALIZED', 'a locked device should announce itself');

    const second = await device.waitHid(IFACE.VENDOR,
      { since: since + 1, timeoutMs: 2500, signal });
    assert.ok(second, 'the broadcast should repeat');
  });

  it('does not read the vendor interface at all while locked',
    async ({ device, assert, signal, skip }) => {
      if (isDuo()) skip('a DUO does read RawHID while locked (sendInitialized() polls it) - this pins the classic');
      /*
       * Worth pinning down, because the firmware source suggests otherwise.
       * okcore.cpp's OKGETLABELS case has an "Error device locked" branch, so a
       * locked device looks like it should answer with a refusal - but on this
       * hardware model recvmsg() is only reached from `if (unlocked)` in the
       * main loop (OnlyKey.ino:485). Only the DUO polls RawHID while locked,
       * from sendInitialized(). So a locked Classic/Color key does not refuse
       * the message: it never reads it.
       *
       * A host that waits for a refusal therefore waits forever. That is the
       * behaviour being asserted, and it is why status() reads the periodic
       * broadcast rather than asking a question.
       */
      const since = device.mark(IFACE.VENDOR);
      device.sendVendor({ msg: okmsg.MSG.OKGETLABELS });

      await assert.rejects(
        () => device.waitHid(IFACE.VENDOR, {
          since, match: /Error|labels/i, timeoutMs: 4000, signal,
        }),
        /timed out/,
        'a locked device answered a vendor message'
      );

      /* And the broadcast carries on regardless, which is what distinguishes
       * "ignoring messages" from "wedged". */
      const alive = await device.waitHid(IFACE.VENDOR,
        { since, match: /^INITIALIZED/, timeoutMs: 2500, signal });
      assert.ok(alive, 'the device stopped broadcasting too - it is not just ignoring us');
    });

  it('reports its model and version once unlocked', async ({ device, assert, signal }) => {
    const model = await device.unlock(PINS.primary, { signal });

    /*
     * HW_MODEL() appends one character for the hardware variant: 'c' for
     * LQFP/BGA with dual LEDs, 'p'/'n' for DUO, 'o' for the discontinued
     * original. Which one is expected is the model under test (lib/model.js).
     */
    const want = MODEL_LETTER[deviceModel()];
    assert.match(model, new RegExp(`^UNLOCKED.*${want.source}`), `unexpected model string for a ${deviceModel()}: ${model}`);
  });

  it('answers OKGETLABELS once unlocked', async ({ device, assert, signal }) => {
    const since = device.mark(IFACE.VENDOR);
    device.sendVendor({ msg: okmsg.MSG.OKGETLABELS });

    const reply = await device.waitHid(IFACE.VENDOR, { since, timeoutMs: 5000, signal });
    const text = okmsg.text(reply);
    assert.ok(!/Error/.test(text), `an unlocked device refused OKGETLABELS: ${text}`);
  });

  it('takes the time, which is RAM-only and rebased every boot',
    async ({ device, assert, signal }) => {
      /* Nothing counter or TOTP derived works without this after a reboot -
       * snapshot or not, the clock does not survive. */
      device.setTime();
      await device.sleep(200, { signal });
      assert.ok(!device.fatal, 'setting the time killed the device');
    });
});
