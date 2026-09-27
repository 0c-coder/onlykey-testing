/*
 * The trusted-origin gate and the webcrypt policy - the three controls a DEBUG
 * build skips.
 *
 * WHY THIS FILE EXISTS. `webcryptcheck()` (fido2/device.cpp) decides what a web
 * origin may do over the FIDO2 extension, and on a DEBUG build it opens with:
 *
 *     #ifdef DEBUG
 *     ...
 *     return 2; // Trust all origins for debug firmware
 *     #endif
 *
 * That return is BEFORE the origin comparison and before the policy byte is
 * read. `#define DEBUG` is on in onlykey.h for every build this kit normally
 * runs, so the origin table, `OKWC_ALLOW_STORED_KEY` and `OKWC_DISABLE_EXT` are
 * switched off at the top of the function - three security controls with no
 * coverage anywhere else in the kit.
 *
 * THE GATE IS THE BEHAVIOUR, NOT THE VERSION STRING. The first draft of this
 * file skipped unless the device reported `-prod`, which turned out to be
 * unrunnable: a `-prod` build has no DEBUG console, and the kit presses buttons
 * and enters PINs through that console, so it cannot unlock such a device at
 * all. What this file needs is not a production build but a build where the
 * trust-all return is gone - and the only way to know which one is in front of
 * it is to ask. So every device test starts by attempting a handshake from an
 * origin that is NOT in the table:
 *
 *   refused               the table is being enforced; run the file.
 *   admitted, `-test`     the DEBUG trust-all return; skip, and say so.
 *   admitted, `-prod`     a production build admitting an untrusted origin -
 *                         that is the defect this file exists to catch, and it
 *                         FAILS rather than skips.
 *
 * An "enforcing" emulator is the normal DEBUG build with that one line removed
 * in a build copy (never in the repo): the audit of all 405 `#ifdef DEBUG`
 * blocks on 2026-09-22 found it is the only one that changes control flow, so
 * DEBUG-minus-that-line runs the production logic for everything this file
 * touches, with the kit's instrumentation intact. Point the kit at it with
 * OKEMU_ROOT.
 *
 * WHAT THIS DOES NOT NEED is the console. Every refusal here is a `hidprint()`
 * that lands in the FIDO answer (outputmode WEBAUTHN), or an absent handshake.
 *
 * THE STORED-KEY GATE FIRES BEFORE ANY CRYPTO (ok_extension.cpp):
 *
 *     if (wc_level < 2 && opt1 != RESERVED_KEY_WEB_AGENT_DERIVATION) {
 *         hidprint("Error stored key use over FIDO2 not enabled");
 *
 * It does not look at the slot's contents, so naming a slot is enough to drive
 * it and no key has to be loaded. The allowed case is therefore the ABSENCE of
 * that string, which makes this a negative-assertion file: `negative: true`,
 * and every test proves its instrument before believing an absence.
 *
 * SURFACES - see PRODUCTION.md. FIDO for the requests and the refusals; vendor
 * for the field 31 writes.
 */
'use strict';

const { describe, it } = require('../../lib/harness');
const { IFACE, okmsg } = require('../../lib/device');
const { Ctap2 } = require('../../lib/device/ctap2');
const tunnel = require('../../lib/device/tunnel');
const transit = require('../../lib/device/transit');
const { PINS } = require('../../lib/config');
const pqc = require('../../lib/pqc');

/* The two origins compiled into webcryptcheck()'s table (device.cpp). */
const TRUSTED = 'apps.crp.to';
const TRUSTED_ALT = 'apps.onlykey.io';
/* Not in the table - any origin that is not one of the two will do. */
const UNTRUSTED = 'example.com';

const FIELD_WEBCRYPT_POLICY = 31;
const OKWC_ALLOW_STORED_KEY = 0x01;
const OKWC_DISABLE_EXT = 0x02;

const SLOT_SIGN = 2;
const REFUSED = /stored key use over FIDO2 not enabled/;

describe('the trusted-origin gate and the webcrypt policy', {
  state: 'initialized',
  requires: ['crypto'],
  negative: true,
  timeoutMs: 600000,
}, () => {
  /** OKCONNECT over the tunnel from `rpId`; `session` is null if refused. */
  async function handshake(device, ctap, rpId, { signal }) {
    const ours = transit.keypair();
    let reply = null;
    try {
      reply = await tunnel.send(ctap, {
        cmd: okmsg.MSG.OKCONNECT,
        data: transit.connectPayload(ours.publicKey),
      }, { rpId, timeoutMs: 30000, signal });
    } catch (err) {
      return { session: null, model: null, why: err.message };
    }
    if (!reply || !reply.data || reply.data.length < 32) {
      return { session: null, model: null, why: (reply && reply.error) || 'no data' };
    }
    return {
      model: okmsg.text(reply.data.subarray(32)),
      session: transit.session(
        transit.transitKey(reply.data.subarray(0, 32), ours.privateKey)),
    };
  }

  /**
   * Is the origin table being enforced on this device? See the header for the
   * three outcomes. Returns only when it is; otherwise skips or throws.
   */
  async function enforcing(device, { signal, skip, assert, log }) {
    const { raw } = await device.status({ signal });
    const ctap = new Ctap2(device, { signal });
    await ctap.init();
    const probe = await handshake(device, ctap, UNTRUSTED, { signal });
    log(`device ${raw}; ${UNTRUSTED} ${probe.session ? 'ADMITTED' : 'refused'}`);
    if (probe.session) {
      assert.ok(!/-prod/.test(raw),
        `a PRODUCTION build (${raw}) completed a handshake from ${UNTRUSTED}, which is ` +
        'not in the origin table - webcryptcheck() is admitting origins it should refuse');
      skip(`${raw} admitted ${UNTRUSTED}: this is the DEBUG trust-all return in ` +
        'webcryptcheck(), so nothing in this file would test anything. Build an ' +
        'enforcing emulator (the header says how) and point OKEMU_ROOT at it');
    }
    return { raw, ctap };
  }

  /** Write field 31 in config mode, and leave config mode. */
  async function setPolicy(device, value, { signal }) {
    await pqc.readyForKeygen(device, { signal });
    const since = device.mark(IFACE.VENDOR);
    device.sendVendor({
      msg: okmsg.MSG.OKSETSLOT, slot: 1, field: FIELD_WEBCRYPT_POLICY,
      payload: Buffer.from([value]),
    });
    const ack = await device.waitHid(IFACE.VENDOR,
      { since, match: /Success|Error/, timeoutMs: 8000, signal });
    const said = okmsg.text(ack).trim();
    await device.restart({ signal });
    await device.ensureUnlocked(PINS.primary, { signal });
    return said;
  }

  /**
   * A sealed stored-slot OKSIGN, and everything the device said about it - the
   * FIDO answer to the request itself plus anything on the vendor interface.
   * The payload never reaches signing code on the refusing path - the gate
   * returns first - so what is asserted is the gate's own message, present or
   * absent, not the outcome of a signature.
   *
   * The refusal is read from the FIDO answer. Until libraries 6ddc82b it was
   * sent nowhere at all: the webcrypt block runs with outputmode = DISCARD and
   * the gate did not switch it back, so the browser got an empty answer and
   * timed out. This file is what found that. The vendor text is still
   * collected so a build that regresses to printing it there is visible in
   * the log rather than silently passing or failing for the wrong reason.
   */
  async function trySign(device, ctap, session, { signal }) {
    const since = device.mark(IFACE.VENDOR);
    const reply = await tunnel.send(ctap, {
      cmd: okmsg.MSG.OKSIGN, opt1: SLOT_SIGN, opt2: 1, opt3: 1,
      data: transit.seal(session, Buffer.alloc(32, 0xA5)),
    }, { rpId: TRUSTED, timeoutMs: 30000, signal }).catch((err) => ({ error: null, thrown: err.message }));
    await device.sleep(2500, { signal });
    const vendor = device.reportsSince(IFACE.VENDOR, since)
      .map((r) => okmsg.text(r).trim()).filter(Boolean).join(' | ');
    const fido = (reply && (reply.error || reply.thrown || reply.status)) || '(no answer)';
    return { fido, vendor, said: [reply && reply.error, vendor].filter(Boolean).join(' | ') };
  }

  it('an origin that is not in the table gets no extension at all',
    async ({ device, assert, signal, log, skip }) => {
      await device.ensureUnlocked(PINS.primary, { signal });
      const { ctap } = await enforcing(device, { signal, skip, assert, log });

      /* CONTROL: a trusted origin answers in this same session, so the refusal
       * enforcing() just saw is about the origin and not a broken tunnel. */
      const good = await handshake(device, ctap, TRUSTED, { signal });
      log(`${TRUSTED}: ${good.model || good.why}`);
      assert.control('a trusted origin completes the OKCONNECT handshake',
        !!good.session && /UNLOCKED/.test(good.model || ''));

      const bad = await handshake(device, ctap, UNTRUSTED, { signal });
      assert.absent(!bad.session,
        `${UNTRUSTED} completed the handshake, so webcryptcheck() admitted an origin ` +
        'that is not in its table');
    });

  it('the second table entry is trusted too, which is what makes the table a table',
    async ({ device, assert, signal, log, skip }) => {
      await device.ensureUnlocked(PINS.primary, { signal });
      const { ctap } = await enforcing(device, { signal, skip, assert, log });

      const one = await handshake(device, ctap, TRUSTED, { signal });
      assert.control('the first table entry completes the handshake', !!one.session);

      const two = await handshake(device, ctap, TRUSTED_ALT, { signal });
      log(`${TRUSTED_ALT}: ${two.model || two.why}`);
      assert.ok(two.session && /UNLOCKED/.test(two.model || ''),
        `${TRUSTED_ALT} was refused - the second origin table entry does not match`);
    });

  it('a key that never wrote field 31 allows stored-slot operations, as v3.0.4 did',
    async ({ device, assert, signal, log, skip }) => {
      /*
       * Decided 2026-09-23: keys upgraded from v3.0.4 keep web PGP, which that
       * firmware allowed by default. An unwritten field 31 reads OKWC_UNSET and
       * okcore_webcrypt_policy() answers ALLOW_STORED_KEY. Runs before any test
       * in this file writes field 31 - the fixture never writes it.
       */
      await device.ensureUnlocked(PINS.primary, { signal });
      const { ctap } = await enforcing(device, { signal, skip, assert, log });
      const { session, model, why } = await handshake(device, ctap, TRUSTED, { signal });
      assert.control('the trusted origin completes the handshake', !!session && /UNLOCKED/.test(model || ''));
      if (!session) throw new Error(`handshake from ${TRUSTED} failed: ${why}`);

      const { fido, vendor, said } = await trySign(device, ctap, session, { signal });
      log(`FIDO answer: ${fido}; vendor: ${vendor || '(nothing)'}`);
      assert.absent(!REFUSED.test(said),
        'a never-configured key refused a stored-slot request - upgraded v3.0.4 keys would lose web PGP');
    });

  it('a trusted origin gets DERIVED keys only once field 31 is written without bit 0',
    async ({ device, assert, signal, log, skip }) => {
      await device.ensureUnlocked(PINS.primary, { signal });
      await enforcing(device, { signal, skip, assert, log });

      /* Written rather than assumed, so this tests the value and not the fixture. */
      const wrote = await setPolicy(device, 0, { signal });
      assert.match(wrote, /Successfully set webcrypt policy/, `writing policy 0: ${wrote}`);

      const ctap = new Ctap2(device, { signal });
      await ctap.init();
      const { session, model, why } = await handshake(device, ctap, TRUSTED, { signal });
      assert.control('the trusted origin still completes the handshake at policy 0',
        !!session && /UNLOCKED/.test(model || ''));
      if (!session) throw new Error(`handshake from ${TRUSTED} failed: ${why}`);

      const { fido, vendor, said } = await trySign(device, ctap, session, { signal });
      log(`FIDO answer: ${fido}; vendor: ${vendor || '(nothing)'}`);
      assert.match(fido, REFUSED,
        'a stored-slot OKSIGN was NOT refused to the browser at policy 0 - "derived keys ' +
        'yes, PGP no" is what 0 means, and bit 0 is what changes it');
    });

  it('field 31 bit 0 promotes the same origin to stored-slot operations',
    async ({ device, assert, signal, log, skip }) => {
      await device.ensureUnlocked(PINS.primary, { signal });
      await enforcing(device, { signal, skip, assert, log });

      const wrote = await setPolicy(device, OKWC_ALLOW_STORED_KEY, { signal });
      assert.match(wrote, /Successfully set webcrypt policy/, `writing policy 1: ${wrote}`);

      const ctap = new Ctap2(device, { signal });
      await ctap.init();
      const { session, model, why } = await handshake(device, ctap, TRUSTED, { signal });
      assert.control('the extension is live for the trusted origin, so an absent ' +
        'refusal is about the policy bit', !!session && /UNLOCKED/.test(model || ''));
      if (!session) throw new Error(`handshake from ${TRUSTED} failed: ${why}`);

      const { fido, vendor, said } = await trySign(device, ctap, session, { signal });
      log(`FIDO answer: ${fido}; vendor: ${vendor || '(nothing)'}`);
      assert.absent(!REFUSED.test(said),
        'the stored-key refusal is still sent with OKWC_ALLOW_STORED_KEY set, so the ' +
        'opt-in does not opt in');

      await setPolicy(device, 0, { signal });
    });

  it('field 31 bit 1 turns the extension off for trusted origins too',
    async ({ device, assert, signal, log, skip }) => {
      await device.ensureUnlocked(PINS.primary, { signal });
      const { ctap } = await enforcing(device, { signal, skip, assert, log });

      const before = await handshake(device, ctap, TRUSTED, { signal });
      assert.control('the handshake from a trusted origin completes before the kill ' +
        'switch is set', !!before.session);

      const wrote = await setPolicy(device, OKWC_DISABLE_EXT, { signal });
      assert.match(wrote, /Successfully set webcrypt policy/, `writing policy 2: ${wrote}`);

      const again = new Ctap2(device, { signal });
      await again.init();
      const after = await handshake(device, again, TRUSTED, { signal });
      log(`after OKWC_DISABLE_EXT: ${after.model || after.why}`);
      assert.absent(!after.session,
        'a trusted origin still completed the handshake with OKWC_DISABLE_EXT set - the ' +
        'kill switch does not kill anything');

      /* Put it back, so a file-order run does not leave the device mute. */
      await setPolicy(device, 0, { signal });
    });

  it('an undefined policy bit is refused rather than masked away',
    async ({ device, assert, signal, log }) => {
      /*
       * NOT enforcement-gated: this lives in set_slot(), which DEBUG does not
       * touch - and refusing instead of masking is what lets a host that means
       * something this firmware does not understand find out.
       */
      await device.ensureUnlocked(PINS.primary, { signal });
      const ok = await setPolicy(device, 0, { signal });
      assert.control('a defined policy value is accepted, so a refusal below is about ' +
        'the value', /Successfully set webcrypt policy/.test(ok));

      const said = await setPolicy(device, 0x04, { signal });
      log(`policy 0x04: ${said}`);
      assert.match(said, /Error invalid webcrypt policy/,
        `an undefined bit was accepted (${said}) - OKWC_VALID_MASK rejects rather than ` +
        'masks, so a host does not silently get a policy it did not ask for');
    });
});
