'use strict';
/*
 * RC FIX 0012 - the 20 s user timer stops when a request is decided (node-onlykey-emulator
 * scripts/versions/patches-3.1.0/0012-libraries-okcore-stop-user-timer: the patch and its README).
 * Until 2026-10-26 this was the emulator plugin fix_usertimeout and its side-loaded test; the fix is
 * now a maintainer patch, staged on 3.1.0 by default (fixes-3.1.0.js), so its test lives here.
 *
 * The firmware started its 20 s user timer (Usertimeout -> fadeoffafter20sec) at every confirmation
 * prime and did not stop it when the request finished. The timer then ran out 20 s after the LAST
 * prime, whatever was happening by then. If the next request's packets were still arriving at that
 * moment - its first OKSIGN packet had already set pending_operation, its prime had not run yet - the
 * old timer answered "Timeout occured while waiting for confirmation on OnlyKey" for the new request,
 * which the host read as a refusal.
 *
 * The test makes that moment happen on purpose: request A is primed and pressed; request B's first
 * packet is sent just before A's 20 s mark and its last packet just after the timer has run out (the
 * DEBUG console says when). Emulator only (it reads the console's timer line), and only on a build
 * that records fix 0012 (`fixes` in .stage/build.json): without it this is the bug, not a regression.
 */
const fs = require('node:fs');
const path = require('node:path');
const { describe, it } = require('../../lib/harness');
const { emulatorRoot } = require('../../lib/paths');
const { pluginCtx } = require('../../lib/plugin-ctx');

function stagedFixes() {
  try {
    const built = JSON.parse(fs.readFileSync(path.join(emulatorRoot().dir, '.stage', 'build.json'), 'utf8'));
    return { fixes: Array.isArray(built.fixes) ? built.fixes : [], debug: built.debug === true };
  } catch (_) {
    return { fixes: [], debug: false };
  }
}
const crypto = require('crypto');

const sha256 = (b) => crypto.createHash('sha256').update(b).digest();
/* the console line the firmware prints when a confirmation is primed, and when the 20 s timer runs out */
const PRIMED = /Encrypted Buffer/g;
const TIMER_RAN_OUT = /wipe buffers after 20 sec/g;
/* an agent-derived P-256 sign (OKSIGN code 222): 64 bytes, so two packets */
const SLOT = 222;

function register({ it }, ctx) {
  const MSG = ctx.okmsg.MSG.OKSIGN;
  const payload = (text) => Buffer.concat([sha256(Buffer.from(text)), sha256(Buffer.from('okt fix_usertimeout identity'))]);
  const packets = (p) => {
    const out = [];
    for (let i = 0; i < p.length; i += 57) {
      const chunk = p.subarray(i, i + 57);
      out.push({ msg: MSG, slot: SLOT, field: chunk.length < 57 ? chunk.length : 0xff, payload: chunk });
    }
    return out;
  };
  const texts = (device, since) => device.reportsSince(ctx.IFACE.VENDOR, since).map((r) => ctx.okmsg.text(r).trim());

  it('a sign whose packets arrive as the previous request\'s 20 s timer runs out is not answered "Timeout occured"',
    async ({ device, assert, signal, log }) => {
      await device.ensureUnlocked(ctx.PINS.primary, { signal });

      /* A: primed, pressed, answered - its prime starts the 20 s timer */
      let primed = device.log.count(PRIMED);
      let since = device.mark(ctx.IFACE.VENDOR);
      for (const p of packets(payload('request A'))) device.sendVendor(p);
      await device.log.waitForCount(PRIMED, primed + 1, { timeoutMs: 20000, signal });
      const primedA = Date.now();
      await device.sleep(500, { signal });
      device.press(1);
      await device.waitHid(ctx.IFACE.VENDOR, { since, timeoutMs: 8000, signal });
      log(`A answered: ${texts(device, since).join(' | ').slice(0, 60)}`);

      /* B: its first packet just before A's 20 s mark */
      const [first, last] = packets(payload('request B'));
      await device.sleep(Math.max(0, primedA + 19000 - Date.now()), { signal });
      const ranOut = device.log.count(TIMER_RAN_OUT);
      primed = device.log.count(PRIMED);
      since = device.mark(ctx.IFACE.VENDOR);
      device.sendVendor(first);
      /*
       * its last packet only once A's 20 s are past: when the old timer runs out (it does without
       * the fix - the DEBUG console says so), or 21.5 s after A's prime when it was stopped
       */
      const fired = await device.log.waitForCount(TIMER_RAN_OUT, ranOut + 1, { timeoutMs: Math.max(0, primedA + 21500 - Date.now()), signal })
        .then(() => true, () => false);
      log(fired
        ? `the old 20 s timer ran out ${Date.now() - primedA} ms after A was primed, between B's two packets`
        : `no timer ran out by ${Date.now() - primedA} ms after A was primed: it stopped when A was decided`);
      device.sendVendor(last);

      await device.log.waitForCount(PRIMED, primed + 1, { timeoutMs: 5000, signal }).catch(() => {});
      await device.sleep(1500, { signal });
      const before = texts(device, since);
      log(`B before its press: ${before.join(' | ').slice(0, 120) || '(nothing)'}`);
      assert.ok(!before.some((t) => /Timeout occured/i.test(t)), `B was answered "Timeout occured" before anyone could press: ${before.join(' | ')}`);

      /* and B still completes: pressed, it is signed */
      const signedSince = device.mark(ctx.IFACE.VENDOR);
      device.press(1);
      await device.waitHid(ctx.IFACE.VENDOR, { since: signedSince, timeoutMs: 8000, signal });
      const after = texts(device, signedSince);
      assert.ok(!after.some((t) => /Timeout occured|^Error/i.test(t)), `B was not signed after its press: ${after.join(' | ')}`);
    });
}

const { fixes, debug } = stagedFixes();
describe('the 20 s user timer stops when a request is decided (RC fix 0012)', { state: 'initialized', timeoutMs: 300000, requires: ['emulated'] }, () => {
  if (fixes.includes('0012')) register({ it }, pluginCtx({ debug }));
  else it('the 20 s user timer stops when a request is decided', async ({ skip }) => skip('this emulator build does not carry RC fix 0012 (.stage/build.json fixes: ' + (fixes.join(', ') || 'none') + ')'));
});
