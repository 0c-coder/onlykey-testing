/*
 * What a host can tell about config mode, and what OKWIPEPRIV says when it says no.
 *
 * WHY THIS FILE EXISTS. A user reported "unable to wipe key, says to put into
 * config mode even when it is in config mode". The App shows that refusal while
 * the key really is in config mode with the red LED going. This file measures
 * the wire underneath that report, because the App's account of what happened
 * is not evidence about the device.
 *
 * THE FIRST THING IT ESTABLISHES IS THAT THE DEVICE IS INNOCENT of the reported
 * symptom: OKWIPEPRIV is ACCEPTED in config mode (the last test). Whatever
 * refused the user, it was not the firmware refusing a wipe - so a client that
 * never put the message on the wire is where that goes next, and it is not this
 * file's business.
 *
 * THREE PROPERTIES:
 *
 *   1. the device accepts a private-key wipe in config mode
 *   2. a host can determine whether it is in config mode
 *   3. a refusal for lack of config mode SAYS lack of config mode
 *
 * (3) WAS THE ONE REAL DEFECT ON THIS SURFACE and is why the file was written.
 * okcore.cpp's OKWIPEPRIV case had no `configmode == false` branch where
 * OKSETPRIV's did, so it fell through to a shared else and answered "Error
 * device locked" - on a device that was unlocked. The two key commands, in one
 * state, blamed different things, and any client relaying that string told the
 * user to unlock an already-unlocked key. This file failed on it, the branch
 * was added, and it now passes: from here it is the REGRESSION GUARD, and its
 * seventh test failing again means that branch has been lost.
 *
 * THE TWO TESTS AROUND IT ARE THE SECURITY CONTROLS for that change, and they
 * matter more than the wording does. The sixth proves the wipe is still REFUSED
 * outside config mode AND that the key is still there afterwards; the eighth
 * proves it is still ACCEPTED inside and the key is really gone. A patch that
 * "fixed" the message by widening what is accepted would pass the seventh and
 * fail those two. They passed identically either side of the change, which is
 * the evidence it touched wording only.
 *
 * (2) IS THE INTERESTING ONE AND IT IS NOT WHAT THE STATUS STRING SUGGESTS.
 * set_time() prints the same HW_MODEL(UNLOCKED) in config mode as out of it -
 * okcore.cpp:1350 vs :1361, differing only by a #ifdef DEBUG line - so status
 * alone cannot tell them apart, and the second test pins exactly that. But
 * status is not the only channel: okcore.cpp:347 SILENTLY DROPS every vendor
 * message in config mode except an allow-list, and OKGETPUBKEY is not on it.
 * So the pair "OKCONNECT answers, OKGETPUBKEY does not" is a positive
 * discriminator, and config mode turns out to be knowable after all. The third
 * and fifth tests measure both halves of that.
 *
 * THE DEBUG CONSOLE IS NOT AN ORACLE HERE, and it is an easy mistake: the
 * Serial.println("UNLOCKED") at OnlyKey.ino:707 is unconditional even though
 * the hidprint() on the line above it is guarded by !configmode. The console
 * therefore says UNLOCKED in a state where the HID wire says nothing. Every
 * assertion below is on the wire.
 *
 * ORDER IS LOAD-BEARING. Config mode is left only by rebooting, so the sequence
 * is arranged around two reboots rather than one per question. The key written
 * in config mode survives them - it is in flash - which is what lets the later
 * tests prove a refused wipe left it alone and an accepted one did not.
 *
 * OUTSIDE --isolate AND --reverse BY CONSTRUCTION. This is one long operation
 * with several assertions about it, which README lists as the case that is
 * deliberately not expected to pass --isolate: config mode is entered in the
 * second test, the key is written in the fourth, and the refusal the seventh
 * judges is the one the sixth captured under its security control. Reversed or
 * run singly the later tests have no device state to speak about, and --isolate
 * naming them is the tool saying exactly that rather than that something is
 * broken. 7 of 9 are so reported, and that is the expected result.
 *
 * SURFACE: the vendor interface throughout, plus the keyboard surface that
 * enterConfigMode() uses. Both survive into a production walk.
 */
'use strict';

const crypto = require('crypto');

const { describe, it } = require('../../lib/harness');
const { PINS } = require('../../lib/config');
const { IFACE, okmsg } = require('../../lib/device');

/** A user ECC slot, and the type byte for Curve25519/Ed25519. */
const SLOT = 101;
const ECC_TYPE_ED25519 = 1;

/** Written in config mode, read back either side of a refused wipe. */
const KEY = crypto.randomBytes(32);

const NO_KEY = /no ECC Private Key set/i;

describe('what a host can tell about config mode', {
  state: 'initialized',
  requires: ['crypto'],
  timeoutMs: 180000,
}, () => {
  /* Carried between tests so the last one can report them together, and so the
   * refusal measured under a security control is the same string the wording
   * test judges - rather than a second wipe attempt that might differ. */
  let unlockedStatus = null;
  let configStatus = null;
  let wipeRefusal = null;
  let setPrivRefusal = null;

  /**
   * One vendor request and its reply, raw.
   *
   * The mark is taken BEFORE the send, which is the whole reason this is a
   * helper: waits are retroactive by default, so a mark taken afterwards can be
   * satisfied by a report that predates the request.
   */
  async function askRaw(device, spec, { signal, timeoutMs = 6000, match } = {}) {
    const since = device.mark(IFACE.VENDOR);
    device.sendVendor(spec);
    return device.waitHid(IFACE.VENDOR, { since, match, timeoutMs, signal });
  }

  /** As askRaw, decoded. Only for replies that really are text. */
  async function ask(device, spec, opts) {
    return okmsg.text(await askRaw(device, spec, opts)).trim();
  }

  /** Did anything at all come back? Absence is the measurement in one test. */
  async function answers(device, spec, { signal, timeoutMs = 4000 } = {}) {
    try {
      await askRaw(device, spec, { signal, timeoutMs });
      return true;
    } catch {
      return false;
    }
  }

  /*
   * CONTROL FOR THE WHOLE FILE. If status cannot tell locked from unlocked then
   * it cannot tell anything, and the next test's "these two strings are equal"
   * would be indistinguishable from a broken status read. Measure that the
   * instrument discriminates before trusting it to say two things are the same.
   */
  it('tells locked from unlocked, so the status read discriminates at all',
    async ({ device, assert, signal, log }) => {
      const locked = await device.status({ signal });
      assert.equal(locked.state, 'locked',
        `this file needs a provisioned device sitting locked, got ${locked.raw}`);

      await device.unlock(PINS.primary, { signal });
      const unlocked = await device.status({ signal });
      unlockedStatus = unlocked.raw;

      log(`locked   -> ${locked.raw}`);
      log(`unlocked -> ${unlockedStatus}`);

      assert.notEqual(unlockedStatus, locked.raw,
        'status reports the same thing locked and unlocked - the instrument is '
        + 'broken and nothing else in this file can be believed');
    });

  /*
   * PINNED, not merely recorded, same convention as 26-fido-in-config-mode.
   * This asserts CURRENT firmware behaviour. The day set_time() distinguishes
   * config mode, this failing is the NOTIFICATION - a host would then have a
   * cheap positive signal and every client guessing at it could stop.
   */
  it('reports the SAME status in config mode as it does merely unlocked',
    async ({ device, assert, signal, log }) => {
      await device.enterConfigMode(PINS.primary, { signal });

      const cfg = await device.status({ signal });
      configStatus = cfg.raw;

      log(`merely unlocked -> ${unlockedStatus}`);
      log(`in config mode  -> ${configStatus}`);

      assert.equal(configStatus, unlockedStatus,
        'the status string now distinguishes config mode - firmware behaviour '
        + 'has changed. This test pinned the opposite; a host no longer has to '
        + 'infer or probe, so update this file and anything that probes');
    });

  /*
   * The other channel, and the one that makes config mode knowable.
   *
   * okcore.cpp:347 drops every vendor message in config mode except
   * OKCONNECT OKFWUPDATE OKGETLABELS OKPIN OKPINSD OKPINSEC OKRESTORE
   * OKSETPRIV OKSETSLOT OKWIPEPRIV OKWIPESLOT. OKGETPUBKEY is not among them.
   *
   * Both halves go in ONE test on purpose: the claim is a DIFFERENCE between
   * two messages on the same interface in the same state, and the allow-listed
   * one answering is precisely the control that makes the other one's silence
   * mean something. assert.absent() enforces that mechanically.
   */
  it('answers an allow-listed message in config mode and drops a non-listed one',
    async ({ device, assert, signal, log }) => {
      const alive = await ask(device, {
        msg: okmsg.MSG.OKCONNECT,
        payload: okmsg.setTimePayload(Date.now()),
      }, { signal, match: /UNLOCKED|INITIALIZED/, timeoutMs: 6000 });

      log(`OKCONNECT   in config mode -> ${alive}`);
      assert.control(
        'the vendor interface answers an allow-listed message while in config mode',
        /UNLOCKED/.test(alive));

      const heard = await answers(device,
        { msg: okmsg.MSG.OKGETPUBKEY, slot: SLOT }, { signal, timeoutMs: 4000 });
      log(`OKGETPUBKEY in config mode -> ${heard ? 'answered' : 'no reply'}`);

      assert.absent(!heard,
        'OKGETPUBKEY answered in config mode - okcore.cpp:347 excludes it, so '
        + 'either the allow-list changed or this is not config mode. The '
        + 'answered/silent pair is what lets a host detect config mode at all');
    });

  /* The subject the later security controls need. Loading a key is one of the
   * things config mode exists FOR, so this doubles as evidence the device is in
   * it rather than merely appearing to be. */
  it('accepts a private key while in config mode', async ({ device, assert, signal, log }) => {
    const reply = await ask(device, {
      msg: okmsg.MSG.OKSETPRIV,
      slot: SLOT,
      payload: Buffer.concat([Buffer.from([ECC_TYPE_ED25519]), KEY]),
    }, { signal, timeoutMs: 10000 });

    log(`OKSETPRIV slot ${SLOT} in config mode -> ${reply}`);
    assert.match(reply, /Successfully set ECC Key/i,
      `the device refused a key load in config mode: ${reply}`);
  });

  /*
   * The second half of the discriminator, and it needs the reboot anyway -
   * rebooting is the only way out of config mode.
   */
  it('answers OKGETPUBKEY once out of config mode, completing the discriminator',
    async ({ device, assert, signal, log }) => {
      await device.restart({ signal });
      await device.unlock(PINS.primary, { signal });

      const heard = await answers(device,
        { msg: okmsg.MSG.OKGETPUBKEY, slot: SLOT }, { signal, timeoutMs: 6000 });
      log(`OKGETPUBKEY outside config mode -> ${heard ? 'answered' : 'no reply'}`);

      assert.ok(heard,
        'OKGETPUBKEY is silent outside config mode too, so the silence measured '
        + 'in config mode was not caused by config mode and says nothing');
    });

  /*
   * THE SECURITY CONTROL. Everything the fix touches is a refusal path, so this
   * is the assertion that must hold identically before and after it: outside
   * config mode the wipe is REFUSED, and the key is STILL THERE afterwards.
   *
   * Checking the key rather than only the message is the point. A refusal that
   * wipes anyway would still print an error, and the message alone cannot tell
   * the two apart.
   */
  it('refuses the wipe outside config mode, and the key survives it',
    async ({ device, assert, signal, log }) => {
      wipeRefusal = await ask(device,
        { msg: okmsg.MSG.OKWIPEPRIV, slot: SLOT }, { signal, timeoutMs: 8000 });
      log(`OKWIPEPRIV outside config mode -> ${wipeRefusal}`);

      assert.match(wipeRefusal, /^Error/,
        `the device performed a private-key wipe OUTSIDE config mode: ${wipeRefusal}`);

      const after = okmsg.text(await askRaw(device,
        { msg: okmsg.MSG.OKGETPUBKEY, slot: SLOT }, { signal, timeoutMs: 6000 }));
      assert.ok(!NO_KEY.test(after),
        'the refused wipe erased the key anyway - the refusal is not a refusal');
    });

  /*
   * THE DEFECT. Same device, same state, same instant: OKSETPRIV names config
   * mode and OKWIPEPRIV blames a lock. okcore.cpp gives OKSETPRIV a
   * `configmode == false` branch and OKWIPEPRIV none, so the latter falls
   * through to the shared "Error device locked".
   *
   * RED until that branch exists. It is asserted rather than pinned because,
   * unlike the two pinned tests above, this is not behaviour worth preserving -
   * it is behaviour worth changing, and the test is the thing that says so.
   */
  it('says WHY it refused - lack of config mode, not a lock',
    async ({ device, assert, signal, log }) => {
      setPrivRefusal = await ask(device, {
        msg: okmsg.MSG.OKSETPRIV,
        slot: SLOT,
        payload: Buffer.concat([Buffer.from([ECC_TYPE_ED25519]), KEY]),
      }, { signal, timeoutMs: 8000 });

      log(`OKSETPRIV  outside config mode -> ${setPrivRefusal}`);
      log(`OKWIPEPRIV outside config mode -> ${wipeRefusal}`);

      assert.match(setPrivRefusal, /not in config mode/i,
        `OKSETPRIV stopped naming config mode: ${setPrivRefusal}`);

      assert.match(wipeRefusal, /not in config mode/i,
        'OKWIPEPRIV blames a LOCK on a device that is unlocked, where OKSETPRIV '
        + `in the same state names config mode. Got: ${wipeRefusal}`);
    });

  /*
   * Property 1, and the other half of the security control: the accept path is
   * untouched. A change that fixed the wording by widening what is accepted
   * would pass the wording test and fail here.
   *
   * The read-back has to cross a reboot because OKGETPUBKEY cannot be asked in
   * config mode - which the third test is what establishes.
   */
  it('accepts the wipe in config mode, and the key is gone afterwards',
    async ({ device, assert, signal, log }) => {
      await device.enterConfigMode(PINS.primary, { signal });

      const reply = await ask(device,
        { msg: okmsg.MSG.OKWIPEPRIV, slot: SLOT }, { signal, timeoutMs: 10000 });
      log(`OKWIPEPRIV in config mode -> ${reply}`);
      assert.match(reply, /Successfully wiped/i,
        `the device refused a wipe IN config mode - this is the state the user `
        + `reported being in, and the wire says it works: ${reply}`);

      await device.restart({ signal });
      await device.unlock(PINS.primary, { signal });

      const after = okmsg.text(await askRaw(device,
        { msg: okmsg.MSG.OKGETPUBKEY, slot: SLOT }, { signal, timeoutMs: 6000 }));
      log(`OKGETPUBKEY after the wipe -> ${after.slice(0, 60)}`);
      assert.match(after, NO_KEY,
        'the wipe reported success but the key is still readable');
    });

  it('reports what the measurements mean together', async ({ assert, log }) => {
    log(`status unlocked      : ${unlockedStatus}`);
    log(`status config mode   : ${configStatus}`);
    log(`OKSETPRIV  refusal   : ${setPrivRefusal}`);
    log(`OKWIPEPRIV refusal   : ${wipeRefusal}`);
    log('');
    log('The status string cannot tell config mode from merely unlocked, but the '
      + 'allow-list at okcore.cpp:347 can: OKCONNECT answers in config mode and '
      + 'OKGETPUBKEY does not. Config mode IS detectable by a host - by probing, '
      + 'not by reading status.');
    log('The device ACCEPTS a private-key wipe in config mode, so the firmware is '
      + 'not what refused the user. Outside config mode it refuses, and the key '
      + 'survives - but it blames a lock rather than config mode, which is the '
      + 'one defect on this surface.');

    assert.ok(unlockedStatus && configStatus,
      'the earlier tests did not record their measurements');
  });
});
