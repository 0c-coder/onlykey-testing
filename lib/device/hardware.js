/*
 * hardware.js - the same test files, against a physical key.
 *
 * This is the other side of the seam described in lib/device/index.js. Three
 * differences are hidden here so that no test has to know which device it is
 * driving:
 *
 *   Report ID. hidraw takes the report ID as the first byte of every write and
 *   the proven client always prepends a zero. Payloads carry no report ID, so
 *   this adapter adds it. The emulator's delivery path pads to 64 and does not
 *   strip a leading report ID, so sending one there would put a different first
 *   byte on the wire from identical test code.
 *
 *   Padding. A hidraw reader must read the descriptor's declared count, so
 *   every SEREMU report arrives as a full 64 bytes with the tail zeroed. The
 *   emulated path emits exactly what the firmware wrote. So the NULs are
 *   stripped HERE and nowhere else - doing it on the emulated path would
 *   destroy legitimate NUL bytes in a binary report.
 *
 *   Restart as disappearance. A reboot on hardware is the device leaving the
 *   USB bus and coming back, not a child process exiting. Both present to a
 *   test as "the generation advanced".
 *
 * Selecting the right device is not a formality here. The emulator's USB
 * gadget presents 1d50:60fc, manufacturer CRYPTOTRUST, product ONLYKEY, serial
 * 1000000000 - byte for byte what a physical key presents, because that is the
 * entire point of the gadget. Nothing in the HID descriptors can tell them
 * apart. So selection is by sysfs: the gadget hangs off dummy_hcd and a real
 * key does not. Without that check a "hardware" run can quietly drive the
 * emulator and report a pass for a device that was never tested.
 */
'use strict';

const EventEmitter = require('events');
const fs = require('fs');
const path = require('path');

const { tracked } = require('./waits');

const VENDOR_IDS = [0x1d50, 0x16c0];
const IFACE = { KEYBOARD: 0, FIDO: 1, VENDOR: 2, SEREMU: 3 };

/* How often to notice that the device left the bus or came back. */
const ENUMERATION_POLL_MS = 250;

/*
 * How many consecutive misses count as "gone".
 *
 * One does not. Enumeration is read from sysfs, and a single sample can miss a
 * device that is perfectly present - udev re-probing a freshly plugged key,
 * rules being applied, a node being recreated. Measured: a key plugged in
 * seconds before a run produced one missed poll, which was read as a reboot,
 * and 00-boot failed on `generation === 0` for a device that had never
 * restarted. A genuine re-enumeration keeps the device away for a second or
 * more, so three quarters of a second of absence is still prompt and no longer
 * jumps at a glitch.
 */
const MISSES_BEFORE_GONE = 3;

/* Windows only: every node-hid object ever closed, kept from the garbage collector (see _closeHandles). */
const RETAINED = [];

function loadHid() {
  try {
    return require('node-hid');
  } catch (err) {
    throw new Error(
      'the hardware adapter needs node-hid, which is an optional dependency: ' +
      `npm install node-hid  (${err.message})`
    );
  }
}

/**
 * Every OnlyKey interface currently enumerated, grouped by physical device.
 *
 * @returns {Array<{usbPath:string, gadget:boolean, interfaces:Object}>}
 */
function discover(hid) {
  if (process.platform === 'win32') return discoverWindows(hid);
  const groups = new Map();

  for (const dev of hid.devices()) {
    if (!VENDOR_IDS.includes(dev.vendorId)) continue;
    if (!dev.path) continue;

    /*
     * /dev/hidrawN -> the USB interface it belongs to -> the USB device above
     * it. The resolved path is also what says whether this is the gadget: a
     * gadget interface resolves under /sys/devices/platform/dummy_hcd.N.
     */
    let sysfs;
    try {
      sysfs = fs.realpathSync(`/sys/class/hidraw/${path.basename(dev.path)}/device`);
    } catch {
      continue;                        // vanished between enumerating and now
    }

    /* .../usbX/X-Y/X-Y:1.Z/0003:VVVV:PPPP.NNNN -> .../usbX/X-Y */
    const usbPath = path.dirname(path.dirname(sysfs));
    const gadget = /dummy_hcd/.test(sysfs);

    /* The bus's number for this enumeration: a reboot re-enumerates with a new one, a stall keeps it. */
    let devnum = null;
    try { devnum = fs.readFileSync(path.join(usbPath, 'devnum'), 'utf8').trim(); } catch { /* gone */ }

    if (!groups.has(usbPath)) groups.set(usbPath, { usbPath, gadget, devnum, interfaces: {} });
    groups.get(usbPath).interfaces[dev.interface] = dev.path;
  }

  return [...groups.values()];
}

/* The interface each usage page is (usbDescriptors.js in the lib: identified by page, not position). */
const IFACE_BY_PAGE = { 0x0001: IFACE.KEYBOARD, 0xf1d0: IFACE.FIDO, 0xffab: IFACE.VENDOR, 0xffc9: IFACE.SEREMU };

/*
 * WINDOWS has no sysfs, so nothing groups a key's interfaces by the USB device
 * above them - hidapi lists interfaces, and each one's path is its own instance.
 * What tells the two kinds apart instead: a physical key's interfaces carry
 * their USB interface numbers, while the emulator's okvhid devices (lib/gadget.js)
 * are software devices that hidapi reports with interface -1. Those are the
 * gadget's counterpart here, excluded unless OKT_ALLOW_GADGET asks for them.
 *
 * Two physical keys list the same interface twice. That is NOT merged: the
 * second one opens a second group, so select() refuses with "2 OnlyKeys" rather
 * than drive a mixture of two keys.
 *
 * Windows also keeps FIDO (usage page 0xf1d0) from programs that are not
 * elevated - the WebAuthn service owns it - so a non-elevated run has no
 * interface 1 at all.
 *
 * THE KEYBOARD IS LEFT OUT. hidapi lists it (a "\KBD" path) and even opens it,
 * but Windows owns keyboards and every read fails "Access is denied"; that read
 * error closed every handle from inside the read thread and took node down with
 * a native crash (measured 2026-10-22, the first hardware run on Windows). Not
 * listing it makes the keyboard tests skip with the adapter's usual
 * interface-unavailable path instead.
 */
function discoverWindows(hid) {
  const groups = [];
  for (const dev of hid.devices()) {
    if (!VENDOR_IDS.includes(dev.vendorId) || !dev.path) continue;
    const gadget = !(dev.interface >= 0);
    const iface = dev.usagePage in IFACE_BY_PAGE ? IFACE_BY_PAGE[dev.usagePage] : dev.interface;
    if (!(iface >= 0) || iface === IFACE.KEYBOARD) continue;
    let group = groups.find((g) => g.gadget === gadget && !(iface in g.interfaces));
    if (!group) {
      const kind = gadget ? 'okvhid' : 'usb';
      const n = groups.filter((g) => g.gadget === gadget).length;
      group = { usbPath: `win32:${kind}${n ? `#${n + 1}` : ''}`, gadget, interfaces: {} };
      groups.push(group);
    }
    group.interfaces[iface] = dev.path;
  }
  return groups;
}

/*
 * Windows takes a write only at the report's exact size, report ID included:
 * 64 bytes for vendor and FIDO, 32 for SEREMU (its out-report is half its
 * in-report). A console line longer than one report goes as several; the
 * firmware reads the console as a byte stream and skips the zero padding.
 * hidraw accepts any length, so Linux writes stay as they were.
 */
const OUT_REPORT = { [IFACE.SEREMU]: 32 };
function windowsReports(buffer, iface) {
  const size = OUT_REPORT[iface] || 64;
  const bytes = Buffer.from(buffer);
  const out = [];
  for (let at = 0; at < Math.max(bytes.length, 1); at += size) {
    const report = Buffer.alloc(size);
    bytes.copy(report, 0, at, at + size);
    out.push([0x00, ...report]);
  }
  return out;
}

/**
 * Pick the device to drive, or explain why it cannot.
 * @param {object} opts {allowGadget, usbPath}
 */
function select(hid, opts = {}) {
  const all = discover(hid);
  const candidates = all.filter((d) => {
    if (opts.usbPath) return d.usbPath.endsWith(opts.usbPath);
    return opts.allowGadget ? true : !d.gadget;
  });

  if (!candidates.length) {
    const seen = all.length
      ? all.map((d) => `${d.usbPath}${d.gadget ? ' (emulator gadget)' : ''}`).join(', ')
      : 'nothing';
    throw new Error(
      `no OnlyKey found on the USB bus. Enumerated: ${seen}. ` +
      (all.some((d) => d.gadget)
        ? 'The emulator\'s gadget is present but is excluded - set ' +
          'OKT_ALLOW_GADGET=yes to target it deliberately, which is a useful ' +
          'way to exercise this adapter without a physical key.'
        : 'Is the key plugged in, and do the udev rules grant access?')
    );
  }

  if (candidates.length > 1) {
    throw new Error(
      `${candidates.length} OnlyKeys are attached (${candidates.map((d) => d.usbPath).join(', ')}). ` +
      'Set OKT_USB_PATH to the one to drive - guessing would be worse than stopping.'
    );
  }

  const chosen = candidates[0];
  for (const iface of [IFACE.VENDOR, IFACE.SEREMU]) {
    if (!chosen.interfaces[iface]) {
      throw new Error(
        `the device at ${chosen.usbPath} is missing interface ${iface}. ` +
        (iface === IFACE.SEREMU
          ? 'Interface 3 is the DEBUG console, and it only exists in DEBUG ' +
            'firmware builds - this kit drives buttons, PINs and reboots ' +
            'through it, so a production build cannot be tested unattended.'
          : 'Interface 2 is the client protocol interface.')
      );
    }
  }

  return chosen;
}

class HardwareTransport extends EventEmitter {
  /**
   * @param {object} [opts]
   * @param {boolean} [opts.allowGadget] target the emulator's gadget on purpose
   * @param {string}  [opts.usbPath]     disambiguate when several are attached
   */
  constructor(opts = {}) {
    super();
    this.hid = loadHid();
    this.allowGadget = opts.allowGadget !== undefined
      ? opts.allowGadget
      : process.env.OKT_ALLOW_GADGET === 'yes';
    this.usbPath = opts.usbPath || process.env.OKT_USB_PATH || null;

    this.generation = 0;
    this.restarts = 0;
    this.mapRetries = 0;              // no mapping to fail; kept for one shape
    this.fatal = null;
    this.ready = false;
    this.stderr = '';                 // no child process; kept for one shape
    this.storageDir = null;           // flash lives on the key, not in a file

    this.device = null;               // the selected {usbPath, interfaces}
    this.handles = new Map();         // iface -> node-hid HID
    this._lent = false;               // lend(): only the console stays open
    this._genLog = '';
    this._bootWaiters = new Set();
    this._poll = null;
    this._stopping = false;
    this._present = false;
    this._misses = 0;
  }

  get kind() { return 'hardware'; }
  get attached() { return this.handles.size > 0; }
  get genLog() { return this._genLog; }

  /* ---- lifecycle -------------------------------------------------------- */

  async start() {
    this.device = select(this.hid, { allowGadget: this.allowGadget, usbPath: this.usbPath });
    this.emit('selected', {
      usbPath: this.device.usbPath,
      gadget: this.device.gadget,
      interfaces: Object.keys(this.device.interfaces).map(Number).sort(),
    });

    this._open();
    this._present = true;
    this._startPolling();

    /*
     * There is no boot to wait for: the key has been running since it was
     * plugged in, and its banner was printed long before this process started.
     * Readiness on hardware means the interfaces are open - and the caller
     * then probes the debug console, which is the only thing that proves the
     * firmware is reading rather than merely enumerated.
     */
    this.ready = true;
    return this;
  }

  /*
   * OPENING IS ALL-OR-NOTHING, AND THAT IS NOT TIDINESS - IT IS CORRECTNESS.
   *
   * This used to open each interface in turn and throw out of the middle of the
   * loop, leaving every handle it had already opened live and listening. Its
   * callers then retry - `_checkEnumeration()` sets `_present = false` and comes
   * back on the next tick, `writeHid()` reopens inline - and the retry called
   * `handles.set(iface, ...)` straight over a handle nobody had closed. The
   * orphan keeps its `data` listener, so SEREMU is delivered TWICE, and
   * `_genLog` accumulates two interleaved copies of the console.
   *
   * That is not hypothetical and it is not rare. A re-enumerating key races
   * udev: the new /dev/hidrawN nodes exist before the rules granting access to
   * them have been applied, so a reopen a few milliseconds too early fails with
   * EACCES *part way through the loop*.
   *
   * Measured 2026-08-06, run `20260806-124136`: 105 interface errors, 32 of them
   * EACCES, and console output arriving with whole blocks spliced into the
   * middle of other lines. `23-rsa-tunnel` read a 32-byte digest as 54 bytes and
   * failed. That is the one failure this explains, and the splice in that run's
   * failure block is the evidence for it.
   *
   * IT IS TIMING-DEPENDENT, NOT VOLUME-DEPENDENT, which is worth knowing before
   * anyone tries to predict it from a count: run `20260806-123045` logged 83
   * errors and 26 denials and passed everything. What matters is whether one
   * denial lands mid-loop, not how many land in a run.
   *
   * OPEN, AND NEITHER RULED IN NOR RULED OUT: `10-backup-restore` failed in the
   * EARLIER run `20260806-122122` - a different run, an hour before, and it
   * passed on a rerun. Its shape was different too: a 90s timeout waiting for a
   * generation, against a device that was alive and broadcasting INITIALIZED,
   * rather than a corrupted read. So this fix is not known to address it.
   *
   * It is also RETROACTIVELY UNTESTABLE, which is the part to respect. The
   * runner only began subscribing to 'interface-error' at 12:30:34Z, after that
   * run had finished, so that run's zero error count is an absent LOGGER, not an
   * absent fault - the leaked handle could have been active and would have left
   * no trace. Its failure block shows no splice, but a repeating identical
   * INITIALIZED broadcast is precisely the payload in which doubled delivery is
   * invisible, so that narrows nothing. Do not treat either as evidence, and do
   * not conclude from a correlation table whose early rows predate the logging.
   * Only a reproduction with the instrumentation present can settle it.
   *
   * So: close whatever is open before opening anything, and if any required
   * interface fails, close what this call opened before rethrowing. A retry
   * then starts from nothing, which is the only state it can start from safely.
   */
  _open() {
    const { interfaces } = this.device;

    /* A reopen must not stack on top of the previous open. */
    this._closeHandles();
    const opened = [];

    /*
     * PRE-FLIGHT THE REQUIRED NODES, so a udev denial fails BEFORE anything is
     * open rather than in the middle of the loop.
     *
     * The unwind below makes a mid-loop failure safe; this makes it rare, and
     * the two are worth having together because they fail differently. Ordering
     * is what decides whether a denial can do damage at all: SEREMU is opened
     * first, so a denial on IT throws with nothing open and is harmless, while a
     * denial on VENDOR throws with SEREMU already listening. Measured across the
     * two sweeps on 2026-08-06 - 30 SEREMU denials in each, all harmless, and
     * 2 then 4 VENDOR denials, which are the only ones that could leak. Checking
     * every required node up front collapses that distinction.
     *
     * Not a blocking retry loop: `writeHid()` calls this synchronously, so
     * sleeping here would stall the event loop and every wait hanging off it.
     * The retry already exists and is `_checkEnumeration()`'s 250ms tick - this
     * just makes each attempt cheap and side-effect-free until the rules land.
     * Rate, so the cost is known rather than guessed: 34 denials across an
     * 840-second sweep, all self-healing within a tick or two.
     */
    for (const iface of [IFACE.SEREMU, IFACE.VENDOR, IFACE.FIDO]) {
      const devPath = interfaces[iface];
      if (!devPath) continue;
      /* a Windows HID path is not a file to check: the open below says what it needs to */
      if (process.platform === 'win32') continue;
      try {
        fs.accessSync(devPath, fs.constants.R_OK | fs.constants.W_OK);
      } catch (err) {
        throw new Error(
          `interface ${iface} at ${devPath} is not accessible yet: ${err.code || err.message}` +
          (err.code === 'EACCES'
            ? ' - a re-enumerating key races udev, so the node exists before the ' +
              'rules granting access to it have been applied. Retrying.'
            : ''));
      }
    }

    /* While lent, a reboot reopens the console only: the client still owns the rest. */
    const wanted = this._lent ? [IFACE.SEREMU] : [IFACE.SEREMU, IFACE.VENDOR, IFACE.FIDO, IFACE.KEYBOARD];
    for (const iface of wanted) {
      const devPath = interfaces[iface];
      if (!devPath) continue;

      let handle;
      try {
        handle = new this.hid.HID(devPath);
      } catch (err) {
        /*
         * The keyboard interface is the one most likely to be refused, since
         * reading it means reading every keystroke the device sends. Losing it
         * costs the keyboard-capture tests and nothing else, so it degrades
         * rather than aborting - but it says so.
         */
        if (iface === IFACE.KEYBOARD) {
          this.emit('interface-unavailable', { iface, path: devPath, reason: err.message });
          continue;
        }
        /* Unwind what this call opened, so the retry starts from nothing. */
        for (const h of opened) { try { h.close(); } catch { /* already gone */ } }
        this.handles.clear();
        throw new Error(`could not open interface ${iface} at ${devPath}: ${err.message}`);
      }

      handle.on('data', (buf) => this._onReport(iface, buf));
      handle.on('error', (err) => this._onHandleError(iface, err));
      this.handles.set(iface, handle);
      opened.push(handle);
    }
  }

  _closeHandles() {
    if (process.platform === 'win32') {
      /*
       * WINDOWS: closed on a later tick, and kept referenced for a while. Closing
       * a node-hid device inside its own 'error' callback - which is where a
       * reboot's "device not connected" arrives - while its read thread is still
       * finishing aborted node natively ("Check failed: array_buffer_allocator
       * != nullptr", 2026-10-22, twice: 23-rsa-tunnel's relock reboot, and the
       * keyboard read error). Listeners go now, so nothing more is delivered;
       * the close waits until the callback has returned.
       *
       * AND THE OBJECT IS NEVER LET GO. The third crash (33-lib-xwing's relock
       * reboot, after a cap of 16 kept references) had its stack on a V8
       * garbage-collection worker: a node-hid object whose device had vanished
       * was finalized off the main thread. So every handle this process ever
       * opened stays referenced until it exits - a few objects per reboot.
       */
      for (const handle of this.handles.values()) {
        handle.removeAllListeners('data');
        handle.removeAllListeners('error');
        handle.on('error', () => { /* closing: a late read error is expected */ });
        RETAINED.push(handle);
        setImmediate(() => { try { handle.close(); } catch { /* already gone */ } });
      }
      this.handles.clear();
      return;
    }
    for (const handle of this.handles.values()) {
      try { handle.close(); } catch { /* already gone */ }
    }
    this.handles.clear();
  }

  /**
   * Hand the key's client interfaces to another program for a while - a CLI on
   * the same key - and keep only the DEBUG console.
   *
   * A physical key has one set of HID nodes, and two programs both reading and
   * writing the vendor channel fail intermittently and look like the firmware
   * (see 'client-access'). The console is the kit's alone - no client opens
   * it - and it is all the kit needs while a client works: presses, challenge
   * digits and the firmware's own log. reclaim() opens the rest again.
   */
  lend() {
    this._lent = true;
    for (const iface of [IFACE.VENDOR, IFACE.FIDO, IFACE.KEYBOARD]) {
      const handle = this.handles.get(iface);
      if (!handle) continue;
      this.handles.delete(iface);
      handle.removeAllListeners('data');
      handle.removeAllListeners('error');
      handle.on('error', () => { /* closing: a late read error is expected */ });
      if (process.platform === 'win32') {
        RETAINED.push(handle);                 // see _closeHandles: closed on a later tick, kept referenced
        setImmediate(() => { try { handle.close(); } catch { /* already gone */ } });
      } else {
        try { handle.close(); } catch { /* already gone */ }
      }
    }
  }

  reclaim() {
    this._lent = false;
    if (this._present) this._open();
  }

  async stop() {
    this._stopping = true;
    if (this._poll) { clearInterval(this._poll); this._poll = null; }
    this._closeHandles();
  }

  /* ---- reports ---------------------------------------------------------- */

  _onReport(iface, buf) {
    if (iface === IFACE.SEREMU) {
      /*
       * Strip the NUL padding, and only here. hidraw hands back the
       * descriptor's full 64 bytes with the tail zeroed; the firmware wrote a
       * short line. Leaving them in puts NULs through every regex the test
       * suite matches against.
       */
      const text = buf.toString('latin1').replace(/\0+$/, '');
      if (!text) return;
      this._genLog = (this._genLog + text).slice(-65536);
      this.emit('log', text);
      return;
    }

    if (iface === IFACE.KEYBOARD) {
      this.emit('keyboard', Buffer.from(buf));
      return;
    }

    /* FIDO and vendor reports stay the descriptor's full 64 bytes: their
     * readers index by offset, and okmsg.text() trims the padding when a
     * report is being read as a string. */
    this.emit('hid', iface, Buffer.from(buf));
  }

  _onHandleError(iface, err) {
    if (this._stopping || this.fatal) return;
    /* A handle error is usually the device leaving the bus - which on hardware
     * is what a reboot looks like. The poll loop decides which it was. */
    this.emit('interface-error', { iface, reason: err && err.message });
    this._closeHandles();

    /*
     * ON WINDOWS a read that fails ERROR_DEVICE_NOT_CONNECTED (0x48F) IS the
     * device leaving the bus. The key re-enumerates there faster than the poll's
     * debounce (MISSES_BEFORE_GONE x ENUMERATION_POLL_MS), so the poll never
     * saw it absent and read every '8' reboot as a stalled handle: 07-unlock
     * failed "never rebooted after 3 '8' requests" while each request had
     * printed "The device is not connected" (2026-10-22). Linux keeps the
     * debounce - there a flash stall errors a read with the key still present.
     */
    if (process.platform === 'win32' && this._present
      && /0x0000048F|not connected/i.test(String(err && err.message))) {
      this._present = false;
      this._misses = 0;
      this.ready = false;
      this.emit('bus-detach', { generation: this.generation });
    }
  }

  /* ---- enumeration ------------------------------------------------------ */

  /*
   * A reboot is the device DISAPPEARING and coming back, so both edges have to
   * be seen. Polling rather than reacting to handle errors alone, because a
   * fast re-enumeration can complete before the read thread notices anything,
   * and because the old kit's failure - "device never left the USB bus after 3
   * restart presses" - is precisely the case where the disappearance never
   * happened and the run must not pretend otherwise.
   */
  _startPolling() {
    this._poll = setInterval(() => this._checkEnumeration(), ENUMERATION_POLL_MS);
    this._poll.unref();
  }

  _checkEnumeration() {
    if (this._stopping || this.fatal) return;

    let present = false;
    let renumbered = false;
    try {
      const found = discover(this.hid).find((d) => d.usbPath === this.device.usbPath);
      present = !!(found && found.interfaces[IFACE.SEREMU]);
      if (found) this.device.interfaces = found.interfaces;
      /*
       * A NEW USB DEVICE NUMBER IS A REBOOT, even one the poll never saw absent.
       * A key that restarts faster than the debounce below (three misses) came
       * back with the same sysfs path, and the stalled-handle branch reopened it
       * without counting a restart: 10-backup-restore and 35's restore timed out
       * "waiting for device generation N to boot" on Linux (2026-10-22) while
       * the console had shown the key leave and return. The device number is
       * the kernel's per-enumeration id - a flash stall keeps it - so it tells
       * the two apart without a timing guess.
       */
      if (found && found.devnum && this.device.devnum && found.devnum !== this.device.devnum) {
        renumbered = true;
        this.device.devnum = found.devnum;
      }
    } catch {
      present = false;
    }

    if (renumbered && this._present) {
      this._present = false;
      this._misses = 0;
      this.ready = false;
      this._closeHandles();
      this.emit('bus-detach', { generation: this.generation });
    }

    /*
     * Handles dropped, but the device never left: reopen, and do NOT count it
     * as a reboot.
     *
     * A read error closes every handle, because a half-open device is worse
     * than a closed one. Nothing reopened them unless the device also vanished
     * from sysfs - and it does not have to. Measured: the firmware erasing a
     * flash sector during a PIN commit stalled USB long enough to error a read,
     * the handles closed, and the very next write failed with "interface 3 is
     * not open" against a device that was present the whole time.
     *
     * Distinguishing this from a reboot matters. Bumping the generation here
     * would invent a restart that never happened, and every test that counts
     * generations would quietly be measuring the wrong thing.
     */
    if (present && this._present && !this.handles.size) {
      try {
        this._open();
        this.ready = true;
        this.emit('interfaces-reopened', { generation: this.generation });
      } catch (err) {
        this.emit('interface-error', { iface: null, reason: err.message });
      }
      return;
    }

    if (this._present && !present) {
      /* Debounced: a miss is a suspicion, not a verdict. */
      this._misses++;
      if (this._misses < MISSES_BEFORE_GONE) return;

      this._present = false;
      this._misses = 0;
      this.ready = false;
      this._closeHandles();
      this.emit('bus-detach', { generation: this.generation });
      return;
    }

    if (present) this._misses = 0;

    if (!this._present && present) {
      this._present = true;
      this._genLog = '';
      try {
        this._open();
      } catch (err) {
        /* Enumerated but not openable yet - udev may not have applied its
         * rules to the new nodes. Try again on the next tick. */
        this._present = false;
        this.emit('interface-error', { iface: null, reason: err.message });
        return;
      }

      this.restarts++;
      this.generation++;
      this.ready = true;
      this.emit('restart', { generation: this.generation, restarts: this.restarts });
      this.emit('boot', { generation: this.generation });
      for (const waiter of [...this._bootWaiters]) waiter.resolve(this.generation);
      this._bootWaiters.clear();
    }
  }

  /* ---- commands --------------------------------------------------------- */

  /** Host -> device. The report ID goes on HERE; payloads never carry one. */
  writeHid(buffer, iface) {
    let handle = this.handles.get(iface);

    /*
     * Reopen here rather than waiting for the next enumeration poll.
     *
     * _checkEnumeration() already knows how to recover dropped handles on a
     * device that never left the bus, but it only runs on its timer - so a
     * write landing between the read error that closed the handles and the next
     * tick fails with "interface 3 is not open" against a working device. The
     * poll's own comment describes exactly that sequence; this closes the gap
     * it leaves.
     *
     * Measured on a physical key: a restart requested straight after
     * 09-fido-ctaphid aborted the run this way, on a device that answered
     * normally a second later.
     *
     * As in the poll, this deliberately does NOT bump the generation. Nothing
     * restarted, and inventing a reboot would corrupt every test that counts
     * them.
     */
    if (!handle && this._present && !this._stopping && !this.fatal) {
      try {
        this._open();
        this.ready = true;
        this.emit('interfaces-reopened', { generation: this.generation });
        handle = this.handles.get(iface);
      } catch (err) {
        this.emit('interface-error', { iface, reason: err.message });
      }
    }

    if (!handle) {
      throw new Error(`interface ${iface} is not open` +
        (this._present ? '' : ' - the device is off the bus'));
    }
    if (process.platform === 'win32') {
      for (const report of windowsReports(buffer, iface)) handle.write(report);
      return;
    }
    handle.write([0x00, ...Buffer.from(buffer)]);
  }

  /*
   * The keyboard control-transfer pair is NOT implemented on hardware yet, and
   * says so rather than doing something else.
   *
   * hidraw reaches SET_REPORT/GET_REPORT through HIDIOCSFEATURE/HIDIOCGFEATURE,
   * which node-hid exposes as sendFeatureReport/getFeatureReport - so this is a
   * real seam rather than an impossibility, but it is untested and reading every
   * keystroke on a workstation's keyboard interface is a permissions
   * conversation of its own. Throwing keeps a file that needs it skipping
   * honestly instead of passing against the wrong channel.
   */
  kbdSetReport() {
    throw new Error(
      'SET_REPORT on the keyboard interface is not implemented on the hardware ' +
      'adapter - it would need node-hid sendFeatureReport and the udev access ' +
      'to go with it');
  }

  kbdGetReport() {
    throw new Error(
      'GET_REPORT on the keyboard interface is not implemented on the hardware ' +
      'adapter - see kbdSetReport');
  }

  /** No bus to detach from that this process controls. */
  setPlugged() {
    throw new Error(
      'a bus-only detach is not available on hardware - unplug it, or run the ' +
      'emulated adapter where the bus is software'
    );
  }

  waitForBoot(opts = {}) {
    if (this.fatal) return Promise.reject(new Error(this.fatal.reason));
    if (this.ready) return Promise.resolve(this.generation);

    return tracked(
      `the key to re-enumerate (generation ${this.generation + 1})`,
      { timeoutMs: 30000, ...opts },
      (resolve, reject) => {
        const waiter = { resolve, reject };
        this._bootWaiters.add(waiter);
        return () => this._bootWaiters.delete(waiter);
      }
    );
  }
}

module.exports = { HardwareTransport, discover, discoverWindows, windowsReports, select, IFACE };
