/*
 * capabilities.js - what this host can actually reach.
 *
 * One host setting decides how much of the device is reachable, and it has to
 * be stated up front because it silently changes what a run even means. The
 * firmware reads its own storage through raw pointers, so the emulator maps
 * flash.bin at its real MK20DX256 addresses, and vm.mmap_min_addr decides how
 * low that mapping can start. Three rungs:
 *
 *   0x0000  everything, including fw_hash()'s walk from fwstartadr. Needs
 *           vm.mmap_min_addr=0 or CAP_SYS_RAWIO - nobody should run this.
 *   0x1000  the setting to use. certified_hw (enckeysectoradr+432 = 0x5BB0) is
 *           mapped, so crypto works, and page zero stays unmapped so a genuine
 *           NULL dereference still faults exactly as it should.
 *   0x10000 the unprivileged default. Storage at 0x3A800 is reachable and the
 *           device boots and enumerates - but okcrypto_split_sundae()
 *           dereferences certified_hw on every AES-GCM operation, so the device
 *           segfaults the moment it encrypts anything, storing a PIN included.
 *
 * That last rung is the dangerous one, because it looks like it is working
 * right up until the first test that stores a PIN. A run that lands there must
 * SAY so rather than reporting a pile of crashes, so the rung is read back and
 * treated as a capability, the same way as everything else the run cannot do.
 */
'use strict';

const fs = require('fs');

const gadget = require('./gadget');
const agePqc = require('./age-pqc');

const MMAP_MIN_ADDR = '/proc/sys/vm/mmap_min_addr';

/* The address okcrypto_split_sundae() dereferences on every AES-GCM op. */
const CERTIFIED_HW = 0x5BB0;

function readMmapMinAddr() {
  try {
    return parseInt(fs.readFileSync(MMAP_MIN_ADDR, 'utf8').trim(), 10);
  } catch {
    return null;   // not Linux, or /proc not mounted
  }
}

function rungOf(minAddr) {
  /*
   * WINDOWS HAS NO RUNGS.
   *
   * The rung is not really about vm.mmap_min_addr - it is about how much of
   * the 256 KB flash array the emulator managed to map, and on Linux that
   * sysctl is the thing that decides it. The Windows HAL answers the same
   * question differently: it cannot use address 0 at all (the bottom 64 KB of
   * every Win32 process is the reserved null-pointer guard), so it maps the
   * whole array relocatably below 4 GB and rewrites the firmware's four
   * address literals to match. That either succeeds completely or fails with
   * an error - there is no partial mapping to degrade into, so certified_hw
   * at 0x5BB0 and fwstartadr at 0x6060 are always present.
   *
   * Without this the /proc read fails, the rung reads 'unknown', and crypto
   * and fw-hash are withheld - which would matter quietly rather than loudly,
   * because this kit SKIPS rather than fails. A green run would have meant
   * the RSA and AES-GCM tests never executed at all.
   *
   * See node-onlykey-emulator/emulator/src/ok_hal.cpp, the _WIN32 branch of
   * the flash mapping, and ok-rn/FINDING-64bit-pointer-narrowing.md for why
   * the sub-4GB placement is required rather than merely convenient.
   *
   * 'crypto' rather than 'full': the whole array is mapped, so certified_hw
   * is present and AES-GCM works - but FSEC cannot latch on a host where it
   * is ordinary memory, so the Windows HAL reports the device as already
   * provisioned and the firmware's one-time branch never runs. That is the
   * same trade Linux makes at this rung, and it is what fw-hash and
   * attestation are gated on. Claiming 'full' here made the firmware
   * re-provision after every restart, which wiped the PINs a fixture had
   * just set.
   */
  if (process.platform === 'win32') return { name: 'crypto', minAddr: 0 };

  if (minAddr === null) return { name: 'unknown', minAddr };
  if (minAddr === 0) return { name: 'full', minAddr };
  if (minAddr <= CERTIFIED_HW) return { name: 'crypto', minAddr };
  return { name: 'hid-only', minAddr };
}

/*
 * A capability is a name, whether it is available, and - when it is not - one
 * sentence saying why, in terms of the thing that would have to change. That
 * sentence is what a skipped file reports, so it has to stand on its own in a
 * log read hours later by somebody who did not configure this machine.
 */
function detect({ adapter = 'emulated' } = {}) {
  const minAddr = readMmapMinAddr();
  const rung = rungOf(minAddr);
  const bus = gadget.inspect();
  const caps = new Map();

  const add = (name, ok, why) => caps.set(name, { name, ok, why: ok ? null : why });

  const emulated = adapter === 'emulated';

  add('device', true, null);

  /*
   * A blunt "never against a physical key" gate, for tests whose subject can
   * destroy one.
   *
   * Every other capability here describes something the host CAN do. This one
   * exists to describe something a test must NOT be allowed to do, and it is
   * deliberately the adapter name rather than anything inferred - a gate whose
   * condition can be satisfied by accident is not a gate.
   *
   * The case it was added for is `OKFWUPDATE`. On a physical key that message
   * needs the special bootloader, and running it LOCKS THE BOOTLOADER AND
   * PERMANENTLY CONVERTS A DEVELOPER KEY INTO A PRODUCTION KEY. That is not
   * "needs a reflash" - the key is gone as a dev key, and no amount of
   * reflashing brings it back. Anything that sends that message, or drives a
   * client that could, requires this.
   */
  add('emulated', emulated,
    'this file must never run against a physical key - see its header for what ' +
    'the message it drives does to one');

  /*
   * The emulated device's flash and EEPROM are ordinary files, which is what
   * makes state snapshottable at all. A physical key's are inside the key, so
   * anything that inspects or pushes an image belongs to the emulator.
   */
  add('storage-files', emulated,
    'a physical key keeps its flash inside the key - there is no file to read');

  add('image-snapshots', emulated,
    'device state cannot be pushed into a physical key as an image; hardware ' +
    'fixtures run their real setup flow instead');

  /*
   * The two-process arrangement and its restart markers are how the emulated
   * device reboots. A key reboots by leaving the USB bus.
   */
  add('device-host', emulated,
    'a physical key is not a child process, so there is no exit status or ' +
    'restart marker to classify - a reboot is a re-enumeration');

  add('crypto', rung.name === 'crypto' || rung.name === 'full' || !emulated,
    rung.name === 'unknown'
      ? `could not read ${MMAP_MIN_ADDR}, so the flash mapping's low bound is unknown`
      : `vm.mmap_min_addr is ${minAddr} (0x${(minAddr || 0).toString(16)}), so ` +
        `certified_hw at 0x${CERTIFIED_HW.toString(16)} is not mapped and any AES-GCM ` +
        `operation segfaults - run  sudo sysctl -w vm.mmap_min_addr=4096`);

  add('fw-hash', rung.name === 'full' || !emulated,
    `fw_hash() walks from fwstartadr, which needs the flash mapped at 0x0 ` +
    `(vm.mmap_min_addr=0 or CAP_SYS_RAWIO); this host is at ${minAddr}`);

  /*
   * The X-Wing maths, which is the one thing in this kit node:crypto cannot do:
   * there is no ML-KEM-768 in the standard library, so lib/age-pqc.js needs
   * three @noble packages. They are optional dependencies so that the kit stays
   * installable with nothing, and this is what turns their absence into a
   * stated skip instead of a module-not-found three frames down.
   *
   * Nothing about the device is involved, so it does not depend on the adapter.
   */
  const pqc = agePqc.probe();
  add('xwing-math', pqc.ok, pqc.why);

  /*
   * The web app's own device library, for section 3's headless tier. It is a
   * sibling checkout rather than a dependency, so a tree that does not have it
   * skips those files rather than failing to load them - the same treatment
   * every other missing checkout gets. Nothing about the device is involved.
   */
  const webapp = require('./webenv').probe();
  add('webapp-lib', webapp.ok, webapp.why);

  /*
   * A browser to open the web app in. Separate from `display` because they fail
   * for different reasons and only one of them is fixable by installing
   * something: no nw.js SDK binary is a missing download, no DISPLAY is a
   * missing screen.
   */
  const browser = require('./gui').probe();
  add('nwjs', browser.ok, browser.why);

  /*
   * Not a bug list entry. FSEC is not in flash.bin - it lives in an anonymous
   * peripheral mapping written fresh every boot, and what gets written depends
   * on whether the flash mapping landed at address zero. It does not, on any
   * host configured the way this project recommends, so FSEC latches to the
   * already-provisioned value, the one-time provisioning branch never runs, and
   * there is no factory key derivation, no firmware hash in EEPROM and no
   * security lock bits.
   */
  add('attestation', !emulated,
    'emulated mode never runs the firmware\'s one-time provisioning branch: FSEC ' +
    'latches to already-provisioned unless the flash maps at 0x0, and that ' +
    'configuration (vm.mmap_min_addr=0) is one nobody should run');

  /*
   * The emulator exposes the keyboard as an event rather than a device node to
   * be read with elevated privileges - which is what finally makes backup and
   * restore testable at all.
   */
  add('keyboard-capture', true, null);

  /*
   * usb-bus is about the ADAPTER: the in-process bus is not enumerable, full
   * stop. A gadget in front of the emulator does not change that - it is a
   * second, separate path to the same firmware.
   */
  add('usb-bus', !emulated,
    'emulated mode has no USB bus - the in-process HID bus is not enumerable');

  /*
   * kernel-hid is DETECTED, not assumed from the adapter name.
   *
   * The old rule was `!emulated`, which is wrong the moment the USB gadget is
   * up: /dev/hidraw is then the emulator, and python-onlykey can open it like
   * any other client. That assumption is what kept the CLI section looking
   * like it needed a physical key when it only ever needed a kernel node.
   *
   * The gadget is a singleton, though, so existing is not the same as being
   * ours - see lib/gadget.js. A run that provisions PINs inside the
   * developer's own daemon is not an isolated test run, it is vandalism with
   * a progress bar.
   */
  if (emulated) {
    const opted = process.env.OKT_USE_RUNNING_GADGET === 'yes';
    add('kernel-hid', bus.usable || (opted && bus.bound && bus.hidg.length > 0),
      bus.why || 'no kernel HID device is reachable from emulated mode');
  } else {
    add('kernel-hid', bus.hidraw.physical.length > 0,
      'no physical OnlyKey is enumerated - anything reaching the device through ' +
      'hidapi (python-onlykey, lib-agent, node-hid) needs one');
  }

  /*
   * The full wipe erases the firmware hash and drops a physical key into the
   * bootloader, which needs a reflash to recover from. On the emulator it is a
   * file being erased. The kit's own fixtures never need it - the userspace
   * wipe ('0C') returns a device to uninitialized, which is what 'blank' means
   * - so this stays off unless somebody asks for it out loud.
   */
  /*
   * A kernel HID node that a SEPARATE client can drive while the kit is also
   * talking to the device.
   *
   * kernel-hid alone is not enough to run section 2, and the difference is not
   * academic. With the gadget, the two ends of the link are different nodes:
   * the kit's device host holds /dev/hidg* and python-onlykey opens
   * /dev/hidraw*, so both work at once. Against a physical key there is only
   * one set of nodes, and the kit's own adapter is holding them - a CLI would
   * be reading the reports the kit was waiting for and vice versa, which does
   * not fail cleanly, it fails intermittently and blames the firmware.
   */
  add('client-access', emulated && bus.usable,
    emulated
      ? `no gadget for a second client to reach: ${bus.why || 'the USB gadget is not up'}`
      : 'the hardware adapter holds the same /dev/hidraw nodes a CLI needs; ' +
        'section 2 against a physical key would have two clients fighting over ' +
        'one device node');

  /*
   * Taking the device off the bus WITHOUT powering it down, from software.
   *
   * Only the gadget can do this: unbinding the UDC removes the interfaces while
   * the firmware keeps running with its RAM intact. A physical key needs a hand
   * on the cable, which is why the old kit's "fails cleanly when the device is
   * unplugged" test carried a skip and mostly did not run. It is also NOT what
   * the GUI's Unplug button does - an OnlyKey is bus-powered, so pulling the
   * cable cuts power too.
   */
  add('bus-detach', emulated && bus.usable,
    emulated
      ? `no gadget to detach from: ${bus.why || 'the USB gadget is not up'}`
      : 'a physical key leaves the bus when somebody pulls it out; software cannot');

  /*
   * A screen for a browser to open a window on.
   *
   * Section 3 splits on this, and the split is the point: the web app's own
   * device library (onlykey.github.io/src/onlykey-fido2) is ordinary JavaScript
   * and needs no display and no USB - only a browser surface to be shimmed and
   * something to send CTAP2 at, both of which this kit has. So the library half
   * of section 3 runs anywhere, including CI, and only the half that actually
   * opens nw.js requires this.
   */
  add('display', !!(process.env.DISPLAY || process.env.WAYLAND_DISPLAY),
    'no DISPLAY or WAYLAND_DISPLAY - nothing that opens a browser window can run here');

  add('full-wipe', emulated || process.env.OKT_ALLOW_FULL_WIPE === 'yes',
    "'9C' erases the firmware hash and forces the bootloader on real " +
    'hardware; set OKT_ALLOW_FULL_WIPE=yes if you can reflash the key');

  /*
   * Free on the emulator, opt-in on hardware - and deliberately NOT the blunt
   * `emulated` gate that OKFWUPDATE carries, because the two costs are
   * different in kind.
   *
   * OKFWUPDATE on a key is IRREVERSIBLE: it locks the bootloader and turns a
   * developer key into a production one permanently, so there is nothing to opt
   * into and the gate is absolute. A FIDO2 reset is destructive but RECOVERABLE
   * - the key still works afterwards, it has simply forgotten things - so
   * gating it on the adapter forever would mean CTAP2's PIN handling never gets
   * tested on real silicon, which it should be eventually.
   *
   * What opting in costs, so that nobody has to read a test file to find out:
   * EVERY RESIDENT CREDENTIAL ON THE KEY IS WIPED, and the key is left with a
   * FIDO2 client PIN set. Anything registered with that authenticator - every
   * site the key is enrolled at as a discoverable credential - stops working.
   */
  add('fido-reset',
    emulated
      || process.env.OKT_ALLOW_FIDO_RESET === '1'
      || process.env.OKT_ALLOW_FIDO_RESET === 'yes',
    'setting a CTAP2 client PIN cannot be undone without a FIDO2 reset, which ' +
    'WIPES EVERY RESIDENT CREDENTIAL on the key and leaves it with a PIN set. ' +
    'Set OKT_ALLOW_FIDO_RESET=1 to run this against hardware you are willing to ' +
    'clear');

  return {
    adapter,
    rung,
    /* The bus picture, for a runner that wants to say WHY rather than just
     * that a section was skipped. */
    gadget: bus,
    /** @returns {boolean} */
    has: (name) => !!(caps.get(name) && caps.get(name).ok),
    /** @returns {string|null} why `name` is unavailable, or null if it is */
    why: (name) => {
      const c = caps.get(name);
      if (!c) return `unknown capability '${name}'`;
      return c.ok ? null : c.why;
    },
    /**
     * First unmet requirement, as a sentence, or null if all are met.
     * @param {string[]} required
     */
    missing: (required = []) => {
      for (const name of required) {
        const c = caps.get(name);
        if (!c) return `requires unknown capability '${name}'`;
        if (!c.ok) return `requires ${name}: ${c.why}`;
      }
      return null;
    },
    list: () => [...caps.values()],
  };
}

module.exports = { detect, rungOf, readMmapMinAddr, CERTIFIED_HW, MMAP_MIN_ADDR };
