/*
 * device/index.js - the one device API every test is written against.
 *
 * There is one API with two adapters behind it, and the differences between
 * them are hidden HERE rather than pushed onto test code:
 *
 *   Report ID. The proven hardware client always prepends a zero byte, but the
 *   emulator's delivery path pads to 64 and does not strip a leading report ID
 *   - so identical test code would put different bytes on the wire in each
 *   mode. Payloads carry no report ID and the hardware adapter adds it.
 *
 *   Chunking and zero-padding. The firmware already emits exactly 64 bytes for
 *   RawHID and already flushes SEREMU at 64 bytes or at a newline; the bridges
 *   re-chunk and pad only because a hidraw reader must read the descriptor's
 *   declared count. The emulated path replicates none of that, and the hardware
 *   adapter strips the padding on the way in, so both normalise to the same
 *   line stream.
 *
 * A test never constructs this. The runner builds it, prepares the device state
 * the file's metadata asks for, and injects it.
 */
'use strict';

const { LogBuffer } = require('./logbuf');
const { KeystrokeDecoder } = require('./keyboard');
const { PendingSet, tracked, sleep, anySignal, TimeoutError } = require('./waits');
const okmsg = require('./okmsg');
const gadget = require('../gadget');
const { isDuo, pinPresses } = require('../model');

/* usb_desc.h's interface numbers, which the firmware and the descriptors use. */
const IFACE = { KEYBOARD: 0, FIDO: 1, VENDOR: 2, SEREMU: 3 };

/*
 * The firmware's own debug button harness (okcore.cpp, touch_sense_loop): a
 * line of ASCII digits selects the buttons, '!' per hold tier modifies the digit
 * before it, and newline commits the line. This - not the analog touch pads -
 * is the supported way to drive buttons, and it exists only in DEBUG builds.
 */
const HOLD_MODIFIER = { tap: '', hold: '!', long: '!!', longest: '!!!' };

/*
 * OKT_NATIVE_PRESSES=yes: on the emulated adapter, press buttons (and restart) through the
 * emulator's own API instead of the DEBUG console. Releases before 3.1.0 have NO console press or
 * command interface - v3.0.4's okcore.cpp has neither "I received from DEBUG" nor the press queue -
 * so a console line presses nothing there and the 'initialized' fixture waited for PIN digits that
 * never landed. The emulator's bands: tap <= 20 ticks, press 21..71, hold >= 72 (the gesture:
 * backup on 1, config mode on 6), and the DUO's long holds: long >= 180 (config mode on its
 * button 1), longest >= 360 (factory default). An emulator without those modes refuses them.
 */
const NATIVE_PRESSES = process.env.OKT_NATIVE_PRESSES === 'yes';
const nativeMode = ({ hold, ticks }) => {
  if (ticks !== undefined) {
    return ticks <= 20 ? 'tap' : ticks <= 71 ? 'press' : ticks < 180 ? 'hold' : ticks < 360 ? 'long' : 'longest';
  }
  if (!hold || hold === 'tap') return 'tap';
  if (hold === 'hold' || hold === 'long' || hold === 'longest') return hold;
  throw new RangeError(`the emulator has no '${hold}' press (OKT_NATIVE_PRESSES): tap, press, hold, long or longest`);
};
const DBG_QUEUE_MAX = 16;   // firmware queue depth; past it the tail is dropped
const DBG_LINE_MAX = 32;    // firmware raw line buffer, one SEREMU OUT report

const HID_HISTORY = 64;     // reports kept per interface, for retroactive waits

class Device {
  /**
   * @param {object} transport an EmulatedTransport (or, later, a hardware one)
   * @param {object} [opts] {capabilities, signals}
   */
  constructor(transport, opts = {}) {
    this.transport = transport;
    this.capabilities = opts.capabilities || null;
    /* Extra cancellation sources the runner owns - the inactivity budget and
     * the run maximum. A watchdog that cannot cut a wait short is a watchdog
     * that reports a stall after the run has already stopped mattering. */
    this.externalSignals = opts.signals || [];

    this.pending = new PendingSet();
    this.log = new LogBuffer({ pending: this.pending });
    this.keys = new KeystrokeDecoder();
    this.led = [];

    this.hid = { [IFACE.FIDO]: [], [IFACE.VENDOR]: [], [IFACE.KEYBOARD]: [] };
    this._hidSubscribers = new Set();

    /*
     * How many reports each interface has evicted from its ring.
     *
     * mark() hands out an ABSOLUTE sequence number, not an array index,
     * because the array is bounded and shifts. Measured the hard way: after a
     * restore's burst of traffic the vendor ring was full, a mark taken at 64
     * pointed one past the end of a 64-entry array, and the scan that followed
     * matched nothing at all - so status() timed out and reported a locked,
     * happily broadcasting device as uninitialized. An index into a ring that
     * moves is not a cursor.
     */
    this.hidDropped = {};

    /*
     * When the device last said ANYTHING, on any interface.
     *
     * The inactivity watchdog used to read only the debug console, which is
     * wrong in one important case: typing a backup is 46 seconds of keyboard
     * reports with nothing at all on the console. That is a device working
     * hard, and the budget would have called it a stall.
     */
    this.lastTrafficAt = 0;

    /*
     * A device that has died must not be waited on. Every wait below is
     * cancellable from two directions - the test's own deadline and the device
     * disappearing underneath it - because without the second one a firmware
     * crash mid-wait surfaces as an ordinary timeout seconds later, with the
     * crash nowhere near the failure it caused.
     */
    this._fatalController = new AbortController();

    transport.on('log', (text) => this.log.append(text));
    transport.on('led', (pixels) => { this.led = pixels; });
    transport.on('keyboard', (data) => {
      this._recordHid(IFACE.KEYBOARD, data);
      this.keys.feed(data);
    });
    transport.on('hid', (iface, data) => this._recordHid(iface, data));
    transport.on('fatal', (info) => {
      this._fatalController.abort(new Error(info.reason));
    });
  }

  get generation() { return this.transport.generation; }
  /** Where flash.bin and eeprom.bin live for this run - they are ordinary
   *  files, which is what makes device state snapshottable at all. */
  get storageDir() { return this.transport.storageDir; }
  get restarts() { return this.transport.restarts; }
  get fatal() { return this.transport.fatal; }
  get keystrokes() { return this.keys.text; }

  /** Options every wait shares: device-death cancellation folded in. */
  _opts(opts = {}) {
    return {
      ...opts,
      pending: this.pending,
      signal: anySignal([opts.signal, this._fatalController.signal, ...this.externalSignals]),
    };
  }

  _recordHid(iface, data) {
    this.lastTrafficAt = Date.now();
    const list = this.hid[iface] || (this.hid[iface] = []);
    list.push(Buffer.from(data));
    if (list.length > HID_HISTORY) {
      list.shift();
      this.hidDropped[iface] = (this.hidDropped[iface] || 0) + 1;
    }
    for (const fn of [...this._hidSubscribers]) {
      try { fn(iface); } catch { /* a waiter must not break the feed */ }
    }
  }

  /* ---- raw traffic ------------------------------------------------------ */

  /**
   * Host -> device. No report ID, no padding: see the note at the top.
   * @param {number} iface IFACE.*
   * @param {Buffer|number[]|string} data  string is taken as latin1
   */
  send(iface, data) {
    const buf = typeof data === 'string' ? Buffer.from(data, 'latin1') : Buffer.from(data);
    this.transport.writeHid(buf, iface);
    return buf;
  }

  /** Build and send one client-protocol message on the vendor interface. */
  sendVendor(spec) {
    return this.send(IFACE.VENDOR, okmsg.build(spec));
  }

  /**
   * How many reports this interface has already produced.
   *
   * Take a mark BEFORE sending a request, then wait with {since: mark}, so the
   * wait cannot be satisfied by a report that arrived before the request. Waits
   * are otherwise retroactive by design - the device broadcasts its status once
   * a second whether anyone asked or not, and a wait armed a millisecond late
   * would sit through a whole broadcast interval for no reason.
   */
  /*
   * THE KEYBOARD INTERFACE'S CONTROL-TRANSFER CHANNEL, WHICH IS A THIRD COMMAND
   * PATH AND NOT REACHABLE WITH send().
   *
   * `device.send(IFACE.KEYBOARD, ...)` puts an interrupt OUT report on the
   * wire. `process_setreport()` (okcore.cpp:7638) is reached by HID control
   * transfers instead - SET_REPORT 0x0921 and GET_REPORT 0x01a1 - so it is a
   * different door with different guards, and until these two verbs existed the
   * kit could not knock on it at all.
   *
   * Emulated only: the hardware adapter would need hidraw's feature-report
   * ioctls, which is a separate piece of work, so it throws rather than
   * silently doing something else.
   */
  /**
   * Run something that is expected to KILL the device, and get the evidence.
   *
   * Emulated only - a physical key does not die in a way this can capture, and
   * the hardware adapter says so rather than pretending. See the transport's
   * expectFatal() for what it captures and why a crash outside the armed window
   * still ends the run.
   */
  expectFatal(fn, opts = {}) {
    if (typeof this.transport.expectFatal !== 'function') {
      throw new Error(
        'expectFatal() is emulated-only: a crash is captured from the device ' +
        'host\'s exit status, and a physical key is not a child process');
    }
    return this.transport.expectFatal(fn, this._opts(opts));
  }

  kbdSetReport(buffer) {
    return this.transport.kbdSetReport(buffer);
  }

  kbdGetReport(opts = {}) {
    return this.transport.kbdGetReport(this._opts(opts));
  }

  mark(iface) {
    return (this.hidDropped[iface] || 0) + (this.hid[iface] || []).length;
  }

  /** Every report on `iface` since a mark, oldest first. */
  reportsSince(iface, since) {
    const list = this.hid[iface] || [];
    return list.slice(Math.max(0, since - (this.hidDropped[iface] || 0)));
  }

  /**
   * Wait for a report on `iface`.
   * @param {number} iface
   * @param {object} [opts] {match, since, timeoutMs, signal}
   *   match  RegExp tested against the report as text, or (buf) => boolean
   *   since  index from mark(); defaults to 0, i.e. retroactive
   * @returns {Promise<Buffer>}
   */
  waitHid(iface, opts = {}) {
    const { match, since = 0 } = opts;
    const test = matcherFor(match);
    const list = () => this.hid[iface] || [];

    const scan = () => {
      const reports = list();
      /* `since` is a sequence number; translate it into a position in the ring
       * as it stands now. Anything evicted since the mark is unreachable, and
       * starting at 0 is the honest answer for it. */
      const start = Math.max(0, since - (this.hidDropped[iface] || 0));
      for (let i = start; i < reports.length; i++) {
        if (test(reports[i])) return reports[i];
      }
      return null;
    };

    const already = scan();
    if (already) return Promise.resolve(already);

    const what = match instanceof RegExp ? ` matching /${match.source}/` : '';
    return tracked(
      `a report on ${ifaceName(iface)}${what}`,
      this._opts({ timeoutMs: 5000, ...opts }),
      (resolve) => {
        const fn = () => { const hit = scan(); if (hit) resolve(hit); };
        this._hidSubscribers.add(fn);
        return () => this._hidSubscribers.delete(fn);
      }
    );
  }

  /** Wait for the next keyboard report, raw. */
  waitKeyboard(opts = {}) {
    return this.waitHid(IFACE.KEYBOARD, opts);
  }

  /**
   * Wait until the device has TYPED something matching.
   *
   * The debug console announces the keybuffer before the keystrokes go out -
   * the typing is paced by a separate task at TYPESPEED - so waiting on the log
   * and then reading the keystrokes reads them too early, measured as an empty
   * string a second before "hello123" showed up. This waits on the keystrokes
   * themselves, which is the thing under test anyway.
   */
  waitKeystrokes(matcher, opts = {}) {
    const re = matcher instanceof RegExp
      ? matcher
      : new RegExp(String(matcher).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));

    if (re.test(this.keystrokes)) return Promise.resolve(this.keystrokes);

    return tracked(
      `the device to type /${re.source}/`,
      this._opts({ timeoutMs: 15000, ...opts }),
      (resolve) => {
        const fn = () => { if (re.test(this.keystrokes)) resolve(this.keystrokes); };
        this._hidSubscribers.add(fn);
        return () => this._hidSubscribers.delete(fn);
      }
    );
  }

  /* ---- buttons ---------------------------------------------------------- */

  /**
   * One press. n is 1..6.
   * @param {number} n
   * @param {object} [opts] {hold: 'tap'|'hold'|'long'|'longest', ticks}
   */
  press(n, opts = {}) {
    return this.pressLine([{ button: n, ...opts }]);
  }

  /**
   * A sequence of presses in ONE write.
   *
   * The firmware paces the replay itself, so this is the reliable way to enter
   * a PIN: there is no host-side delay between digits to get wrong. A 7-digit
   * PIN sent as seven separate writes is how the old kit ended up with the
   * "store" message landing mid-burst and the firmware seeing a 5-digit PIN.
   *
   * @param {Array<number|string|object>} presses
   */
  pressLine(presses) {
    const items = normalisePresses(presses);
    if (items.length > DBG_QUEUE_MAX) {
      throw new RangeError(
        `at most ${DBG_QUEUE_MAX} presses per line (the firmware's queue depth), ` +
        `got ${items.length}`
      );
    }

    const duo = isDuo();
    const parts = items.map(({ button, hold, ticks }) => {
      if (!Number.isInteger(button) || button < 1 || button > 6) {
        throw new RangeError(`button must be 1..6, got ${button}`);
      }
      /* A DUO has buttons 1..3. The debug console would take a 4 anyway - it
       * sets the firmware's button variable directly - but no finger can, so a
       * test that presses one is testing a device that does not exist. PIN
       * digits 4..6 are holds of 1..3: model.js pinPresses(). */
      if (duo && button > 3) {
        throw new RangeError(`a DUO has buttons 1..3, got ${button} (PIN digits go through pinPresses())`);
      }
      if (ticks !== undefined) {
        if (!Number.isInteger(ticks) || ticks < 1) {
          throw new RangeError(`ticks must be a positive integer, got ${ticks}`);
        }
        return `${button}#${ticks}`;
      }
      const tier = hold || 'tap';
      if (!(tier in HOLD_MODIFIER)) {
        throw new RangeError(
          `hold must be one of ${Object.keys(HOLD_MODIFIER).join(', ')}, got ${tier}`
        );
      }
      return `${button}${HOLD_MODIFIER[tier]}`;
    });
    const line = parts.join('');

    /*
     * A '#ticks' press ENDS its line. dbg_run_presses() (okcore.cpp) reads the
     * digits after '#' greedily, and the next press starts with a digit too:
     * "3#403#40" is button 3 for 403 ticks and then a '#' with no button, and
     * the whole line is ignored ("'#' is not a button 1-6"). The firmware's
     * press queue outlives a line, so splitting keeps the order. Measured: a
     * DUO's self-destruct PIN, seven 3#40 holds, did nothing as one line.
     */
    const lines = [];
    let cur = '';
    for (const part of parts) {
      cur += part;
      if (part.includes('#')) { lines.push(cur); cur = ''; }
    }
    if (cur) lines.push(cur);

    /* The modifiers can exhaust the firmware's line buffer before the queue
     * does - sixteen 'longest' holds is 64 bytes. */
    for (const l of lines) {
      if (l.length > DBG_LINE_MAX) {
        throw new RangeError(
          `press line is ${l.length} bytes, the firmware accepts ${DBG_LINE_MAX}: ${l}`
        );
      }
    }

    if (NATIVE_PRESSES && typeof this.transport.pressNative === 'function') {
      const presses = items.map((p) => ({ button: p.button, mode: nativeMode(p) }));
      this.transport.pressNative(presses);
      /*
       * The emulator queues these and returns at once; nothing reports when the
       * firmware has taken the last one. The console's 'p' echo used to give that
       * order for free. So readiness waits out the queue: about 250ms a press,
       * measured from a seven-digit PIN, and a hold, which the firmware times
       * against its own clock, given longer.
       */
      const ms = presses.reduce((t, p) => t + (p.mode === 'tap' ? 300 : 1500), 500);
      this._nativeBusyUntil = Math.max(this._nativeBusyUntil || 0, Date.now()) + ms;
      return line;
    }
    for (const l of lines) this.sendDebugLine(l);
    return line;
  }

  /** One line of the firmware's DEBUG protocol. Return is the only terminator. */
  sendDebugLine(text) {
    return this.send(IFACE.SEREMU, `${text}\n`);
  }

  /* ---- lifecycle -------------------------------------------------------- */

  /** Resolve once the current generation has booted AND is listening. */
  async waitReady(opts = {}) {
    await this.transport.waitForBoot(this._opts({ timeoutMs: 20000, ...opts }));
    await this.waitResponsive(opts);
    return this.generation;
  }

  /**
   * Wait until the firmware is actually draining its debug input.
   *
   * The boot banner says setup() finished; it does not say loop() is reading.
   * The firmware drops debug-console input while it is busy - it has no queue
   * for it - and it is busy for a surprisingly long time in two places: right
   * after boot, and right after an unlock, both of which run LED fades.
   * Measured: a PIN entered immediately after boot produced not one
   * acknowledgement in fifteen seconds, and a restart requested immediately
   * after an unlock produced no output at all for twenty-four.
   *
   * So probe rather than assume. An unrecognised command path is deliberately
   * silent beyond the per-line echo every line gets, which makes it exactly the
   * readiness probe the firmware's own comment says it is. Counting echoes
   * rather than matching one keeps a stale echo from a previous probe - the
   * accumulator is never cleared behind a test's back - from answering for a
   * device that has since stopped listening.
   */
  async waitResponsive(opts = {}) {
    const { timeoutMs = 15000, probeEveryMs = 500 } = opts;
    /*
     * With native presses the console is not the way in, and a release without
     * console commands (v3.0.4) never echoes 'p' - so every probe would time out.
     * The emulator's presses go through its API, not a console line the firmware
     * might drop, so its own boot signal is the readiness that matters.
     */
    if (NATIVE_PRESSES && typeof this.transport.pressNative === 'function' && this.transport.ready) {
      const busy = (this._nativeBusyUntil || 0) - Date.now();
      if (busy > 0) await this.sleep(busy, opts);
      return this.generation;
    }
    const re = /I received from DEBUG: 112(?!\d)/g;      // 'p', not a command path
    const deadline = Date.now() + timeoutMs;

    for (;;) {
      const before = this.log.count(re);
      const echoed = this.log.waitForCount(re, before + 1, this._opts({
        ...opts,
        timeoutMs: Math.min(probeEveryMs, Math.max(50, deadline - Date.now())),
      }));
      this.sendDebugLine('p');

      try {
        return await echoed;
      } catch (err) {
        if (!(err instanceof TimeoutError)) throw err;
        if (Date.now() >= deadline) {
          throw new TimeoutError(
            `the device to start reading its debug console (generation ${this.generation})`,
            timeoutMs
          );
        }
      }
    }
  }

  /**
   * Reboot, and come back.
   *
   * The restart itself has no observable acknowledgement: okcore.cpp prints
   * "'8' restart requested" and calls CPU_RESTART() on the next line, which does
   * not return - so the device resets before the SEREMU buffer is flushed and
   * neither that print nor the byte echo before it ever reaches the host. The
   * real acknowledgement is the next generation booting.
   *
   * From a test's point of view this is also exactly what USB re-enumeration
   * looks like, which is why the same call covers both transports.
   */
  restart(opts = {}) {
    return this._commandThatReboots('8', 'restart', opts);
  }

  /**
   * Wipe, using the firmware's own path.
   *
   * NOT the addon's factoryReset(): that erases the backing store behind the
   * firmware's back, so none of the firmware's bookkeeping happens and nothing
   * is printed; it sets an internal restart flag that no code anywhere reads,
   * so it never fires the restart sink and never reboots; and it erases only
   * from the first MAPPED byte upward, which means on any host with a non-zero
   * vm.mmap_min_addr the low region of flash.bin survives the "factory reset"
   * entirely. '0C' and '9C' do the real thing and end in CPU_RESTART().
   *
   * @param {object} [opts] {full} - full also erases the firmware hash
   */
  wipe(opts = {}) {
    /* The trailing 'C' is the confirmation, and the firmware only acts on a
     * complete path within one line - so no single stray byte can erase the
     * device, and there is no arm/confirm handshake to sequence. Which also
     * means a resent line is harmless: wiping an already-wiped device is the
     * same device. */
    if (opts.full && this.capabilities && !this.capabilities.has('full-wipe')) {
      throw new Error(`refusing a full wipe: ${this.capabilities.why('full-wipe')}`);
    }
    return this._commandThatReboots(opts.full ? '9C' : '0C', 'wipe', opts);
  }

  /**
   * Send a debug-console command whose only acknowledgement is the reboot it
   * causes, and keep sending it until the device actually reboots.
   *
   * The retry is not belt-and-braces. The debug console drops input while the
   * firmware is busy - measured: a restart requested within a second of an
   * unlock produced no echo, no reboot and no output of any kind for the next
   * 24 seconds, because the device was still running its unlock animations and
   * never drained the report. The old kit hit the same thing from the other
   * side and gave up with "device never left the USB bus after 3 restart
   * presses"; three attempts is that same number, and the wording below is
   * deliberately close so the two kits' failures read alike.
   */
  async _commandThatReboots(line, what, opts = {}) {
    const { attempts = 3, perAttemptMs = 10000 } = opts;
    const target = this.generation + 1;

    for (let attempt = 1; attempt <= attempts; attempt++) {
      /*
       * Wait for the console to be DRAINING before sending, rather than sending
       * into a device that is not reading.
       *
       * Sending blind wastes the whole attempt, because the line is dropped
       * rather than queued and the next ten seconds are then spent waiting for
       * a reboot that was never asked for. On a physical key that is enough to
       * exhaust all three attempts: measured after 09-fido-ctaphid, whose last
       * act is an unlock, the key does not read its console for the best part
       * of half a minute - so attempts at 0s, 10s and 20s all landed inside the
       * window and the run aborted on a device that was working perfectly.
       *
       * Tolerated rather than required: if the probe times out the send still
       * happens, because a device that will not answer 'p' might still act on
       * '8', and one wasted attempt is better than refusing to try.
       */
      try {
        await this.waitResponsive({ ...opts, timeoutMs: perAttemptMs });
      } catch (err) {
        if (!(err instanceof TimeoutError)) throw err;
      }

      /* Armed BEFORE the send, so a fast reboot cannot land between the two. */
      const rebooted = this._waitForGeneration(target, {
        ...opts,
        timeoutMs: perAttemptMs,
      });
      if (line === '8' && NATIVE_PRESSES && typeof this.transport.restartNative === 'function') {
        this.transport.restartNative();               // a release with no console commands
      } else {
        this.sendDebugLine(line);
      }

      try {
        await rebooted;
        /* Booted is not the same as listening - see waitResponsive(). Returning
         * on the banner alone hands the next test a device that will silently
         * drop its first few commands. */
        await this.waitResponsive(opts);
        return this.generation;
      } catch (err) {
        if (err instanceof TimeoutError && attempt < attempts) continue;
        if (err instanceof TimeoutError) {
          throw new TimeoutError(
            `the device to ${what} - it never rebooted after ${attempts} '${line}' requests ` +
            `(generation still ${this.generation})`,
            perAttemptMs * attempts
          );
        }
        throw err;
      }
    }
    return this.generation;
  }

  /**
   * Wait for the device to reboot on its own, without asking it to.
   *
   * Some commands reboot as their completion - the restore is one - and on
   * hardware that reboot is a real USB re-enumeration with a window where the
   * device is simply gone. Probing across that window reads a stale "ready"
   * and then finds nothing: measured as "locked" on the emulator, where the
   * reboot is instant, and as "unreachable" on a key, where it is not. Both
   * are the same race.
   *
   * @param {object} [opts] {from, timeoutMs, signal}
   */
  waitForReboot(opts = {}) {
    const from = opts.from === undefined ? this.generation : opts.from;
    return this._waitForGeneration(from + 1, { timeoutMs: 60000, ...opts });
  }

  _waitForGeneration(target, opts = {}) {
    if (this.generation >= target && this.transport.ready) {
      return Promise.resolve(this.generation);
    }
    return tracked(
      `device generation ${target} to boot`,
      this._opts({ timeoutMs: 30000, ...opts }),
      (resolve) => {
        const onBoot = ({ generation }) => { if (generation >= target) resolve(generation); };
        this.transport.on('boot', onBoot);
        return () => this.transport.removeListener('boot', onBoot);
      }
    );
  }

  /* ---- protocol conveniences -------------------------------------------- */

  /** OKCONNECT with the host's clock. Time is RAM-only and rebased every boot,
   *  so anything counter or TOTP derived needs this again after every reboot. */
  setTime(when = Date.now()) {
    return this.sendVendor({ msg: okmsg.MSG.OKCONNECT, payload: okmsg.setTimePayload(when) });
  }

  /**
   * What state is the device in?
   *
   * Three sources, because the firmware has three behaviours:
   *   unlocked      answers OKCONNECT, and printed HW_MODEL(UNLOCKED) on unlock
   *   locked        answers nothing, but taskInitialized broadcasts
   *                 "INITIALIZED" over the vendor interface once a second
   *   uninitialized broadcasts nothing at all - there is no HID task for it -
   *                 so the debug console's "UNLOCKED, NO PIN SET" is the only
   *                 evidence, and it is printed once, at boot
   *
   * @returns {Promise<{state:string, raw:string|null}>}
   */
  async status(opts = {}) {
    const since = this.mark(IFACE.VENDOR);
    try { this.setTime(); } catch { /* fall through to the console evidence */ }

    try {
      /* Comfortably longer than the 1000ms broadcast interval, so one call
       * spans at least one full broadcast regardless of phase. */
      await this.waitHid(IFACE.VENDOR, {
        since,
        match: /UNLOCKED|INITIALIZED/,
        timeoutMs: 2500,
        ...opts,
      });
    } catch (err) {
      if (!(err instanceof TimeoutError)) throw err;
    }

    /*
     * Read the whole window, and let UNLOCKED win.
     *
     * Not the first match: the locked device broadcasts INITIALIZED once a
     * second, so on a device that has just unlocked, a broadcast can easily
     * land after the mark and before the OKCONNECT reply. Taking the first
     * match then reports 'locked' for a device that answered UNLOCKED half a
     * second later - measured, immediately after a restore. The firmware
     * removes taskInitialized the moment it unlocks, so any INITIALIZED in
     * this window necessarily predates the UNLOCKED beside it.
     */
    const texts = this.reportsSince(IFACE.VENDOR, since).map((r) => okmsg.text(r));
    const raw = texts.find((t) => /^UNLOCKED/.test(t))
      || texts.find((t) => /^INITIALIZED/.test(t))
      || null;

    if (raw && /^UNLOCKED/.test(raw)) return { state: 'unlocked', raw };
    if (raw && /^INITIALIZED/.test(raw)) return { state: 'locked', raw };

    /*
     * Silence on the vendor interface is not the same as a dead device, and
     * telling those apart cannot rely on having seen the boot.
     *
     * An uninitialized device broadcasts nothing at all - there is no HID task
     * for it - so the only positive evidence is the debug console answering.
     * On the emulator the boot banner is also there, because the runner has
     * been attached since generation zero; on hardware the key booted long
     * before this process started and that banner is gone forever. Probing is
     * the rule that works on both.
     */
    if (/UNLOCKED, NO PIN SET/.test(this.transport.genLog || '')) {
      return { state: 'uninitialized', raw: 'UNLOCKED, NO PIN SET' };
    }

    try {
      await this.waitResponsive({ timeoutMs: 5000, ...opts });
      return { state: 'uninitialized', raw: 'silent on the vendor interface, answering on the debug console' };
    } catch {
      return { state: 'unknown', raw };
    }
  }

  /**
   * Enter the primary PIN and wait for the device to say it is unlocked.
   *
   * The wait is on the vendor interface's HW_MODEL(UNLOCKED) print rather than
   * on the debug console, because "UNLOCKED, NO PIN SET" - what an
   * uninitialized device prints at boot - also matches /UNLOCKED/ and would
   * make an unprovisioned device look unlocked.
   *
   * It is deliberately generous: profile1hashevaluate() runs a Curve25519 +
   * SHA256 computation on every digit once the guess reaches 7, and the digits
   * arrive in one burst.
   */
  async unlock(pin, opts = {}) {
    const since = this.mark(IFACE.VENDOR);
    this.pressLine(pinPresses(pin));   /* taps on a classic; 4..6 as holds of 1..3 on a DUO */

    /*
     * In CONFIG MODE the firmware does not announce the unlock (payload():
     * `if (!configmode) hidprint(HW_MODEL(UNLOCKED))`); set_time() does, with
     * the same string. A classic got that reply anyway, by accident: status()'s
     * OKCONNECT, sent while it was locked, sits unread until the unlock and is
     * answered by the "process waiting messages" loop right after it. A DUO
     * reads RawHID while locked, so nothing is left waiting and the unlock went
     * unheard - so ask, once the PIN has had time to land, and again until the
     * deadline. Asking a locked key is harmless: it is the same OKCONNECT
     * status() sends.
     */
    const poke = setInterval(() => {
      try { this.setTime(); } catch { /* the wait below reports the real failure */ }
    }, 3000);
    let report;
    try {
      report = await this.waitHid(IFACE.VENDOR, {
        since,
        match: /^UNLOCKED/,
        timeoutMs: 30000,
        ...opts,
      });
    } finally {
      clearInterval(poke);
    }

    /* The unlock announcement is sent BEFORE the firmware finishes unlocking -
     * fadeon(), fadeoff(85) and the profile setup all follow it - and during
     * that window the device drops everything sent to it. Callers that unlock
     * and immediately do something are the normal case, so pay the wait here
     * once rather than in every test that unlocks. */
    await this.waitResponsive(opts);
    return okmsg.text(report);
  }

  /**
   * Unlock, unless it is already unlocked.
   *
   * unlock() cannot be called twice, and the reason is worth stating because
   * the failure is silent and destructive rather than loud: it works by
   * PRESSING THE PIN DIGITS, and on a device that is already unlocked those
   * are not PIN digits, they are slot presses. The device then TYPES whatever
   * those slots hold on the keyboard interface, and the call times out waiting
   * for an UNLOCKED that will never come again.
   *
   * That is a problem for any file whose tests are meant to be runnable one at
   * a time with `okt run <file> --test <name>`. Each test has to bring the
   * device to the state it needs, but the one before it may already have done
   * so - which makes "unlock if it is not unlocked" the only shape that works
   * both alone and in sequence.
   *
   * Costs one status() - a set-time and a read of the broadcast - when the
   * device is already open, which is cheaper than the boot it saves.
   *
   * @returns {Promise<string>} the model string, as unlock() returns
   */
  async ensureUnlocked(pin, opts = {}) {
    const state = await this.status(opts);
    if (state.state === 'unlocked') return state.raw;
    if (state.state === 'uninitialized') {
      throw new Error('the device is uninitialized - this file needs a provisioned fixture');
    }
    return this.unlock(pin, opts);
  }

  /**
   * Enter config mode.
   *
   * A long press of button 6, and it is not a simple one: the press forces
   * unlocked=false so the device re-authenticates, which means the sequence is
   * press -> device relocks -> unlock again. Passing THROUGH 'locked' is what
   * proves the press registered as a long press rather than being silently
   * ignored, so it is checked rather than assumed.
   *
   * Retried, and preceded by a settle, for the same reason every other press in
   * this kit is: a press that lands mid-fade is discarded. The device is also
   * genuinely busy for two to three seconds after the press - PIN
   * re-evaluation, profile-key derivation, CTAP2 housekeeping, all visible on
   * the debug console - so the responsiveness probe comes before the status
   * read, or the read lands in that window and comes back empty.
   *
   * This gates more than it looks: OKSETPRIV (so the backup passphrase),
   * OKRESTORE, and the slot settings guarded by mod_keys_enabled all answer
   * "Error not in config mode" outside it. There is no positive reply that
   * says "you are in config mode" - the proof is that the next gated message
   * is accepted, which is the caller's business.
   */
  async enterConfigMode(pin, opts = {}) {
    const { attempts = 4, settleMs = 2500 } = opts;
    let last = null;

    for (let attempt = 1; attempt <= attempts; attempt++) {
      await this.sleep(settleMs, opts);
      /* A classic takes config mode from button 6 held >= 72 rounds; a DUO, which
       * has no button 6, from button 1 held >= 180 (payload(), OnlyKey.ino). */
      this.pressLine([isDuo() ? { button: 1, hold: 'long' } : { button: 6, hold: 'hold' }]);

      try {
        await this.waitResponsive(opts);

        const { state, raw } = await this.status(opts);
        if (state !== 'locked') {
          throw new Error(
            `expected the device to relock for config mode's re-auth, got ${state} (${raw})`
          );
        }

        await this.unlock(pin, opts);
        return true;
      } catch (err) {
        last = err;
      }
    }

    throw new Error(
      `could not enter config mode after ${attempts} long presses of button 6: ${last && last.message}`
    );
  }

  /* ---- the cable -------------------------------------------------------- */

  /**
   * Take the device off the USB bus, or put it back, WITHOUT powering it down.
   *
   * Unbinding the gadget from its UDC is a real bus-level disconnect: the host
   * tears down its hidraw nodes, so every client - python-onlykey, a browser,
   * anything using hidapi - sees a genuine unplug. The firmware thread keeps
   * running with its RAM intact, which is what makes this different from a
   * restart, and different again from what a hand on the cable does: an OnlyKey
   * is bus-powered, so pulling it cuts power too.
   *
   * Waits for the nodes to actually go, rather than for the write to return.
   * The unbind is asynchronous on the kernel side and a client that enumerates
   * in that window still finds a device - which is the whole thing a
   * "no device attached" test is trying to arrange, so it cannot be raced.
   */
  async setPlugged(plugged, opts = {}) {
    if (this.capabilities && !this.capabilities.has('bus-detach')) {
      throw new Error(`refusing to change the bus: ${this.capabilities.why('bus-detach')}`);
    }
    if (typeof this.transport.setPlugged !== 'function') {
      throw new Error('this adapter cannot detach the device from the bus');
    }

    this.transport.setPlugged(plugged);

    const { timeoutMs = 10000, pollMs = 100 } = opts;
    const deadline = Date.now() + timeoutMs;

    for (;;) {
      const nodes = gadget.inspect().hidraw.gadget.length;
      if (plugged ? nodes > 0 : nodes === 0) return plugged;
      if (Date.now() >= deadline) {
        throw new TimeoutError(
          `the gadget to ${plugged ? 'appear on' : 'leave'} the USB bus ` +
          `(${nodes} hidraw node(s) still ${plugged ? 'missing' : 'present'})`,
          timeoutMs
        );
      }
      await this.sleep(pollMs, opts);
    }
  }

  /** Off the bus. The firmware keeps running. */
  unplug(opts = {}) { return this.setPlugged(false, opts); }

  /** Back on the bus, with the same RAM it had. */
  plug(opts = {}) { return this.setPlugged(true, opts); }

  /** A sleep the test's deadline can cut short. Prefer waiting on the device. */
  /**
   * Run fn - a CLI on the same key - with the key's client interfaces handed
   * over. A physical key lends them (the hardware adapter's lend()); the
   * emulator needs nothing, since the gadget gives a client nodes of its own.
   */
  async lendToClient(fn) {
    if (typeof this.transport.lend !== 'function') return fn();
    this.transport.lend();
    try { return await fn(); } finally { this.transport.reclaim(); }
  }

  sleep(ms, opts = {}) {
    return sleep(ms, this._opts(opts));
  }

  /* ---- for failure blocks ----------------------------------------------- */

  snapshot() {
    return {
      generation: this.generation,
      restarts: this.restarts,
      mapRetries: this.transport.mapRetries,
      pending: this.pending.list(),
      lastOutputAt: Math.max(this.log.lastAppendAt || 0, this.lastTrafficAt) || null,
      recentOutput: this.log.tail(1500),
      keystrokes: this.keys.text.slice(-200),
      fatal: this.fatal,
    };
  }
}

/* ---- helpers ------------------------------------------------------------ */

function normalisePresses(presses) {
  const list = Array.isArray(presses) ? presses : [presses];
  return list.map((p) => {
    if (typeof p === 'number') return { button: p };
    if (typeof p === 'string') return { button: parseInt(p, 10) };
    return p;
  });
}

function matcherFor(match) {
  if (!match) return () => true;
  if (typeof match === 'function') return match;
  if (match instanceof RegExp) return (buf) => match.test(okmsg.text(buf));
  throw new TypeError('match must be a RegExp or a function');
}

function ifaceName(iface) {
  return Object.keys(IFACE).find((k) => IFACE[k] === iface) || `iface ${iface}`;
}

module.exports = { Device, IFACE, okmsg };
