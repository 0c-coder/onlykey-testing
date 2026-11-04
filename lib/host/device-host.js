#!/usr/bin/env node
/*
 * device-host.js - the process the firmware actually runs in.
 *
 * This is the emulator's own bin/daemon.js with the gadget bridge and the
 * stdout tee taken out: require the emulator, start it against a storage dir,
 * run the existing IPC peer as the whole body, and write a restart marker
 * before dying.
 *
 * It is a separate process because it has to be. CPU_RESTART() ends the
 * firmware thread and start() cannot be called a second time in the same
 * process: okemu_hal_shutdown() never unmaps, so the second okemu_hal_init()
 * collides on MAP_FIXED_NOREPLACE; re-arming the restart trap saves its own
 * handler as the "previous" one, which turns any later genuine crash into a
 * fault loop; the ThreadSafeFunctions leak; and the firmware's C++ globals were
 * constructed once at dlopen and never reconstruct. These tests reboot
 * constantly, so the test code cannot live here.
 *
 * Nothing is written to stdout in normal operation. The firmware is chatty in
 * DEBUG builds, and stdout is a pipe: if the parent ever stopped reading, this
 * process would block in write(), its event loop would stop, commands would go
 * unanswered, and the run would "hang" for a reason no watchdog could name.
 * Device output goes over IPC. stdout and stderr carry only this process's own
 * fatal reports - and the addon's segfault handler, which writes
 * "[okemu] FATAL: segfault at" plus a backtrace to stderr.
 *
 * Usage:
 *   node device-host.js --socket PATH --storage DIR --markers DIR --generation N
 */
'use strict';

const fs = require('fs');
const path = require('path');

const { emulatorRoot } = require('../paths');

/*
 * Exit codes the parent classifies on. Only MAPFAIL is really "ours": an
 * expected restart is a SIGKILL with a marker file, and a firmware crash is a
 * SIGSEGV, neither of which can carry an exit code.
 */
const EXIT_OK = 0;
const EXIT_FATAL = 1;
const EXIT_MAPFAIL = 7;   // could not map the emulated flash - retry, not a crash

function parseArgs(argv) {
  const out = { socket: null, storage: null, markers: null, generation: 0, gadget: false };
  for (let i = 2; i < argv.length; i++) {
    switch (argv[i]) {
      case '--socket': out.socket = argv[++i]; break;
      case '--storage': out.storage = argv[++i]; break;
      case '--markers': out.markers = argv[++i]; break;
      case '--generation': out.generation = parseInt(argv[++i], 10) || 0; break;
      case '--gadget': out.gadget = true; break;
      default:
        console.error(`[okt-host] unknown argument: ${argv[i]}`);
        process.exit(EXIT_FATAL);
    }
  }
  for (const required of ['socket', 'storage', 'markers']) {
    if (!out[required]) {
      console.error(`[okt-host] --${required} is required`);
      process.exit(EXIT_FATAL);
    }
  }
  return out;
}

const args = parseArgs(process.argv);

function main() {
  const root = emulatorRoot();
  const emu = require(root.index);
  const IpcPeer = require(path.join(root.dir, 'lib', 'ipc-peer'));

  /*
   * A mapping failure is not a device crash and must not be reported as one.
   * A run legitimately produces hundreds of restarts, and even a small
   * per-boot failure rate becomes a run-killer at that count - so the parent
   * retries this, and counts the retries so it stops being invisible if the
   * rate ever changes.
   */
  try {
    emu.start({ storageDir: args.storage });
  } catch (err) {
    console.error(`[okt-host] could not start the emulator: ${err.message}`);
    process.exit(EXIT_MAPFAIL);
  }

  /*
   * Optionally put the device on the USB bus.
   *
   * Section 1 never wants this: it reaches the firmware over the in-process
   * bus, which is what lets it run where there is no kernel at all. Section 2
   * needs it, because python-onlykey and lib-agent find the device through
   * hidapi like every other real client - and a gadget in front of the emulator
   * is a kernel device node that behaves like a key.
   *
   * Raising it HERE rather than pointing the tests at a long-running daemon is
   * what preserves the property that makes this kit worth having: the device
   * this process owns is one nothing else is using, restored from a fixture,
   * thrown away afterwards. The parent has already checked the gadget is free -
   * see lib/gadget.js - so a failure here is a real failure and is fatal.
   */
  /*
   * On Windows the "gadget" is okvhid, as in the emulator's own bin/daemon.js:
   * Windows has no USB gadget, and okvhid is the only way to add a HID device
   * there. lib/gadget.js has already checked its devices and pipes are free.
   */
  let bridge = null;
  if (args.gadget) {
    const kind = process.platform === 'win32' ? 'okvhid-bridge' : 'gadget-bridge';
    const Bridge = require(path.join(root.dir, 'lib', kind));
    bridge = new Bridge(emu);
    bridge.start();
    muteDesktopKeyboard();
    console.error(`[okt-host] ${kind} up - the device is visible to the OS`);
  }

  /*
   * ON WINDOWS THE KEY'S TYPING NEVER REACHES THE DESKTOP.
   *
   * okvhid's keyboard collection is a real Windows keyboard: whatever the
   * device types lands in the focused window. Measured 2026-09-29 - a sweep's
   * 04-app/11 typed its slot password, and 13 a whole backup block, line by
   * line with Enter, into the owner's chat box; a terminal would have run it.
   * The tests never needed the OS to receive it: they read what the device
   * types from the emulator's own stream (the keyboard-capture capability).
   * So the keyboard pipe (okvhid-0) stays disconnected for a kit run - its
   * output is dropped by the bridge, the device and every other interface are
   * unaffected. plug() reconnects every link, so it is muted again after one.
   * Linux's gadget types into the VM's own desktop and is left as it is.
   */
  function muteDesktopKeyboard() {
    if (!bridge || process.platform !== 'win32' || !bridge.links) return;
    const keyboard = bridge.links.get(0);
    if (keyboard) keyboard.close();
  }

  /*
   * Leave the bus. The gadget unbinds its UDC, so the device disappears from
   * the bus. okvhid cannot remove its devices without an elevated token, so it
   * closes the data pipes and the collections stay enumerated but silent until
   * the next host connects. That is the closest Windows gets without elevation;
   * windows-driver\hotplug.ps1 is the real removal.
   */
  const leaveBus = () => {
    if (!bridge) return;
    if (typeof bridge.detachBus === 'function') bridge.detachBus();
    else bridge.stop();
  };

  const ipc = new IpcPeer(emu, { socketPath: args.socket });
  ipc.on('error', (err) => console.error(`[okt-host] ipc: ${err && err.message}`));

  ipc.on('set-plugged', (want) => {
    if (!bridge) return ipc.publishPlugged(false);
    const changed = want ? bridge.plug() : bridge.unplug();
    if (want) muteDesktopKeyboard();
    if (changed) console.error(`[okt-host] ${want ? 'plugged in' : 'unplugged'}`);
    return ipc.publishPlugged(bridge.plugged);
  });

  ipc.start();

  let exiting = false;

  /*
   * Shutting down threads the same needle daemon.js documents. The restart path
   * arrives from inside the native restart callback, which runs as a
   * ThreadSafeFunction call: calling emu.stop() from within that callback waits
   * for the callback to return, which is a deadlock. But skipping the release
   * is not an option either - an unreleased TSFN keeps the environment
   * referenced and process.exit() then blocks in teardown forever. So defer to
   * setImmediate, by which point the callback has unwound, and SIGKILL rather
   * than exit(). This is a device reboot; an abrupt exit is the honest model,
   * and it loses nothing - eeprom writes are pwrite()n as they happen and the
   * flash mapping is MAP_SHARED file-backed, so the kernel flushes it however
   * the process dies.
   */
  const die = (why) => {
    if (exiting) return;
    exiting = true;

    /*
     * The marker is the whole point of this file.
     *
     * An expected restart and an OOM kill are byte-identical to the parent:
     * both arrive as code:null, signal:'SIGKILL'. So the marker is written
     * SYNCHRONOUSLY, before anything else, and stamped with this generation.
     * Marker present means "the firmware asked for this"; marker absent means
     * something killed us, and the run aborts rather than quietly respawning
     * into a machine that is out of memory.
     */
    try {
      fs.writeFileSync(
        path.join(args.markers, `restart-${args.generation}`),
        JSON.stringify({ generation: args.generation, why, pid: process.pid, at: Date.now() })
      );
    } catch (err) {
      console.error(`[okt-host] could not write the restart marker: ${err.message}`);
    }

    /*
     * Leave the bus before leaving. CPU_RESTART() re-enumerates on hardware and
     * clients depend on seeing the device DISAPPEAR; staying bound while the
     * parent respawns us presents a device that looks present and answers
     * nothing, so a client both mis-detects the restart and sends into the void.
     */
    try { leaveBus(); }
    catch (err) { console.error(`[okt-host] leaving the bus threw: ${err.message}`); }

    try { ipc.close(); } catch { /* going away anyway */ }
    setImmediate(() => process.kill(process.pid, 'SIGKILL'));
  };

  emu.on('restart', () => die('firmware requested restart'));

  /*
   * SIGTERM is the parent asking us to stop. It writes no marker: the parent
   * knows it asked, and a marker here would make a deliberate stop look like a
   * firmware restart to any later reader of the run directory.
   */
  process.on('SIGTERM', () => {
    if (exiting) return;
    exiting = true;
    try { leaveBus(); } catch { /* going away anyway */ }
    try { ipc.close(); } catch { /* ignore */ }
    setImmediate(() => process.kill(process.pid, 'SIGKILL'));
  });

  /* Nothing else keeps this alive: the firmware runs on its own native thread
   * and holds no libuv handle. The peer's reconnect timer is referenced (see
   * ipc-peer.js), which is what keeps the loop ticking. */
  process.exitCode = EXIT_OK;
}

try {
  main();
} catch (err) {
  console.error(`[okt-host] fatal: ${err && (err.stack || err.message)}`);
  process.exit(EXIT_FATAL);
}
