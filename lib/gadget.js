/*
 * gadget.js - is there a kernel HID device, and whose is it?
 *
 * Section 1 needs no kernel device node; that is what lets it run in CI. Every
 * later section needs one, because python-onlykey, lib-agent and the browser
 * all find the key through hidapi. On a workstation that node can come from two
 * places - a physical key, or the emulator's USB gadget - and the difference
 * between them is invisible to any client, by design.
 *
 * The part that matters, and the reason this file is not a one-line existence
 * check: the gadget is a SINGLETON. Section 1 gives every test file its own
 * device host, its own storage and its own snapshot, because the in-process bus
 * is per-process. There is exactly one USB gadget on the machine, and whoever
 * holds /dev/hidg* open owns it - normally the developer's pm2-supervised
 * daemon, with their own device state in it.
 *
 * So a CLI run against a gadget somebody else owns is not an isolated test run.
 * It provisions PINs, writes slots and wipes things inside a device the
 * developer is using. This file exists so the kit can tell that situation apart
 * and refuse it, rather than discovering it by having trashed something.
 */
'use strict';

const fs = require('fs');
const path = require('path');

const CONFIGFS = '/sys/kernel/config/usb_gadget';
const SYSFS_HIDRAW = '/sys/class/hidraw';
const ONLYKEY_VID = 0x1D50;
const ONLYKEY_PID = 0x60FC;

/** Every /dev/hidgN the gadget presents, device side. */
function hidgNodes() {
  try {
    return fs.readdirSync('/dev')
      .filter((n) => /^hidg\d+$/.test(n))
      .sort()
      .map((n) => `/dev/${n}`);
  } catch {
    return [];
  }
}

/**
 * Which process holds those nodes open.
 *
 * Read out of /proc rather than shelled out to fuser or lsof: no dependency, no
 * sudo, and it works for our own user's processes - which is the case that
 * matters, since the daemon this is looking for is the developer's own.
 * @returns {{pid:number, command:string, nodes:string[]}|null}
 */
function findOwner(nodes = hidgNodes()) {
  if (!nodes.length) return null;
  const wanted = new Set(nodes);

  let pids;
  try {
    pids = fs.readdirSync('/proc').filter((d) => /^\d+$/.test(d));
  } catch {
    return null;
  }

  for (const pid of pids) {
    let fds;
    try { fds = fs.readdirSync(`/proc/${pid}/fd`); } catch { continue; }

    const held = [];
    for (const fd of fds) {
      try {
        const target = fs.readlinkSync(`/proc/${pid}/fd/${fd}`);
        if (wanted.has(target)) held.push(target);
      } catch { /* the fd closed under us */ }
    }

    if (held.length) {
      let command = '';
      try {
        command = fs.readFileSync(`/proc/${pid}/cmdline`, 'utf8').replace(/\0/g, ' ').trim();
      } catch { /* gone already */ }
      return { pid: Number(pid), command, nodes: held };
    }
  }

  return null;
}

/** The OnlyKey hidraw nodes on the host side, split by what is behind them. */
function hidrawNodes() {
  const out = { gadget: [], physical: [] };
  let nodes;
  try { nodes = fs.readdirSync(SYSFS_HIDRAW); } catch { return out; }

  for (const node of nodes) {
    let sysfs;
    let uevent;
    try {
      sysfs = fs.realpathSync(path.join(SYSFS_HIDRAW, node, 'device'));
      uevent = fs.readFileSync(path.join(SYSFS_HIDRAW, node, 'device', 'uevent'), 'utf8');
    } catch { continue; }

    const want = `:${ONLYKEY_VID.toString(16).toUpperCase().padStart(8, '0')}:` +
      `${ONLYKEY_PID.toString(16).toUpperCase().padStart(8, '0')}`;
    if (!uevent.toUpperCase().includes(want)) continue;

    /* dummy_hcd is the emulator's virtual bus; anything else is real silicon. */
    (/dummy_hcd/.test(sysfs) ? out.gadget : out.physical).push(`/dev/${node}`);
  }
  return out;
}

/*
 * WINDOWS: the same questions, answered by okvhid instead of a USB gadget.
 *
 * Windows has no gadget. The emulator reaches the OS through okvhid, a UMDF
 * driver whose four devices (SWD\DEVGEN\OKVHID_*) each serve a named pipe,
 * \\.\pipe\okvhid-0..3; the emulator connects to those as a CLIENT and Windows
 * enumerates four HID collections (HID\DEVGEN\...) that clients open like any
 * key. See node-onlykey-emulator/windows-driver. The mapping:
 *
 *   configured - all four OKVHID devices present and OK. They are created by
 *                devgen from an elevated shell and do not survive a reboot.
 *   bound      - their pipes exist.
 *   owner      - another process is already connected to the pipes (normally
 *                the pm2 daemon). A pipe takes one client, so a connect then
 *                answers busy; that is the question asked, the way /proc fds
 *                are on Linux. Asked from a child because inspect() is sync.
 *   ambiguous  - a physical OnlyKey is enumerated as well (HID\VID_1D50&PID_60FC
 *                instance ids; the emulated collections are HID\DEVGEN\...).
 *
 * The probe connects to each FREE pipe and closes at once. The driver takes
 * that as a client coming and going, which is what the bridge does on every
 * restart anyway.
 */
const PIPES = [0, 1, 2, 3].map((i) => `\\\\.\\pipe\\okvhid-${i}`);

const PIPE_PROBE = `
const net = require('net');
const pipes = ${JSON.stringify(PIPES)};
const out = {};
let left = pipes.length;
const done = (p, v) => { if (p in out) return; out[p] = v; if (--left === 0) { console.log(JSON.stringify(out)); process.exit(0); } };
for (const p of pipes) {
  const s = net.connect(p);
  const t = setTimeout(() => { s.destroy(); done(p, 'timeout'); }, 1500);
  s.once('connect', () => { clearTimeout(t); s.destroy(); done(p, 'free'); });
  s.once('error', (e) => { clearTimeout(t); done(p, e.code || String(e.message)); });
}`;

const PNP_QUERY = [
  "$d = @(Get-PnpDevice -PresentOnly -InstanceId 'SWD\\DEVGEN\\OKVHID*' -ErrorAction SilentlyContinue |",
  '  ForEach-Object { @{ id = $_.InstanceId; status = [string]$_.Status } })',
  "$p = @(Get-PnpDevice -PresentOnly -Class HIDClass -ErrorAction SilentlyContinue |",
  "  Where-Object { $_.InstanceId -like 'HID\\VID_1D50&PID_60FC*' } | ForEach-Object { $_.InstanceId })",
  "$n = @(Get-CimInstance Win32_Process -Filter \"Name='node.exe'\" |",
  /* bin\daemon.js, not pm2's own lib\Daemon.js (-match ignores case). pm2 runs
   * a forked app under ProcessContainerFork.js, so that names the daemon too. */
  "  Where-Object { $_.CommandLine -cmatch 'bin[\\\\/]daemon\\.js|device-host\\.js|ProcessContainerFork' } |",
  '  ForEach-Object { @{ pid = [int]$_.ProcessId; ppid = [int]$_.ParentProcessId; command = $_.CommandLine } })',
  '@{ devices = $d; physical = $p; hosts = $n } | ConvertTo-Json -Depth 3 -Compress',
].join('\n');

function inspectWindows() {
  const { spawnSync } = require('child_process');
  const out = {
    configured: false, bound: false, udc: null, hidg: [],
    hidraw: { gadget: [], physical: [] },
    owner: null, ownedByUs: false, ambiguous: false, usable: false, why: '',
  };

  let pnp = { devices: [], physical: [], hosts: [] };
  const ps = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', PNP_QUERY],
    { encoding: 'utf8', timeout: 30000, windowsHide: true });
  try { pnp = JSON.parse(ps.stdout); } catch { /* reported below as no devices */ }

  const devices = pnp.devices || [];
  const ok = devices.filter((d) => d.status === 'OK');
  out.configured = ok.length === PIPES.length;
  out.hidraw.gadget = ok.map((d) => d.id);
  out.hidraw.physical = pnp.physical || [];
  out.ambiguous = out.hidraw.physical.length > 0;

  let names = [];
  try { names = fs.readdirSync('\\\\.\\pipe\\'); } catch { /* not listable */ }
  out.hidg = PIPES.filter((p) => names.includes(p.split('\\').pop()));
  out.bound = out.hidg.length === PIPES.length;

  let pipeState = {};
  if (out.bound) {
    const probe = spawnSync(process.execPath, ['-e', PIPE_PROBE],
      { encoding: 'utf8', timeout: 10000, windowsHide: true });
    try { pipeState = JSON.parse(probe.stdout); } catch { /* treated as busy */ }
  }
  const busy = out.hidg.filter((p) => pipeState[p] !== 'free');
  if (busy.length) {
    const others = (pnp.hosts || []).filter((h) => h.pid !== process.pid && h.ppid !== process.pid);
    const first = others[0];
    out.owner = {
      pid: first ? first.pid : null,
      command: first ? first.command : 'unknown',
      nodes: busy,
    };
  }

  if (!out.configured) {
    out.why = `the okvhid devices are not all present (${ok.length}/${PIPES.length} OK) - ` +
      'they do not survive a reboot: from an elevated shell, in the emulator checkout\'s ' +
      'windows-driver folder, run install-driver.ps1 (recreates them), then hotplug.ps1 ' +
      '(enables any left disabled)';
  } else if (out.ambiguous) {
    out.why = `a physical OnlyKey is enumerated (${out.hidraw.physical.length} interfaces). ` +
      'Clients would see two identical devices and take the first match. Unplug the key.';
  } else if (!out.bound) {
    out.why = `the okvhid devices are present but only ${out.hidg.length}/${PIPES.length} ` +
      'of their pipes exist - the driver is not serving them';
  } else if (out.owner) {
    out.why = `the okvhid pipes are already in use (${busy.length} busy)` +
      (out.owner.pid ? ` - pid ${out.owner.pid} (${shortCommand(out.owner.command)})` : '') +
      '. That is another emulator with its own device state, usually the pm2 daemon: ' +
      'pm2 stop it first, or set OKT_USE_RUNNING_GADGET=yes to use it deliberately.';
  } else {
    out.usable = true;
  }
  return out;
}

/**
 * The whole picture, in one call.
 *
 * @returns {{configured:boolean, bound:boolean, udc:string|null,
 *            hidg:string[], hidraw:{gadget:string[],physical:string[]},
 *            owner:object|null, ownedByUs:boolean, usable:boolean, why:string}}
 */
function inspect() {
  if (process.platform === 'win32') return inspectWindows();

  let configured = false;
  let udc = null;
  try {
    const gadgets = fs.readdirSync(CONFIGFS);
    if (gadgets.length) {
      configured = true;
      udc = fs.readFileSync(path.join(CONFIGFS, gadgets[0], 'UDC'), 'utf8').trim() || null;
    }
  } catch { /* configfs absent, or no gadget set up */ }

  const hidg = hidgNodes();
  const hidraw = hidrawNodes();
  const owner = findOwner(hidg);
  const ownedByUs = !!(owner && owner.pid === process.pid);

  /*
   * Two OnlyKeys on one bus is not a richer test environment, it is a coin
   * toss. python-onlykey enumerates and takes the FIRST match, and a gadget is
   * byte-identical to a key in everything a client can see - so with both
   * attached, a CLI run drives whichever the kernel happened to enumerate
   * first, and says nothing about which.
   *
   * It is worse in a browser. A WebAuthn ceremony asks EVERY authenticator
   * present and completes on the first to answer, and both of these answer
   * automatically - so a GUI test would race two devices and pass or fail on
   * whichever won. One device at a time, for the whole run, is the only
   * arrangement any of the later sections can reason about.
   */
  const ambiguous = hidraw.physical.length > 0;

  let usable = false;
  let why = '';

  if (!configured) {
    why = `no USB gadget configured (${CONFIGFS} is empty) - ` +
      'run  sudo ./scripts/gadget-setup.sh  once in the emulator checkout';
  } else if (ambiguous) {
    why = `a physical OnlyKey is on the bus (${hidraw.physical.length} interfaces). ` +
      'Raising the gadget alongside it gives clients two identical devices: they take ' +
      'the first match and cannot tell them apart, and a WebAuthn ceremony would race ' +
      'both. Run one device at a time - unplug the key.';
  } else if (owner && !ownedByUs) {
    why = `the gadget is already owned by pid ${owner.pid} (${shortCommand(owner.command)}). ` +
      'That process has its own device state, and driving it would provision PINs and ' +
      'write slots inside somebody else\'s device. Stop it first, or set ' +
      'OKT_USE_RUNNING_GADGET=yes to use it deliberately.';
  } else {
    /*
     * Unbound is the FREE state, not a fault.
     *
     * A gadget with no UDC written to it has no /dev/hidg* and no host-side
     * interfaces - which is exactly what is left behind when the last owner
     * shut down cleanly, because detachBus() unbinds on the way out. The bridge
     * binds it again when it starts. Treating "not bound" as unusable meant the
     * kit refused precisely when the bus had just become available, which is
     * the one moment it should have said yes.
     */
    usable = true;
  }

  return { configured, bound: !!udc, udc, hidg, hidraw, owner, ownedByUs, ambiguous, usable, why };
}

function shortCommand(command) {
  if (!command) return 'unknown';
  const parts = command.split(/\s+/);
  return parts.map((p) => (/^([/\\]|[A-Za-z]:\\)/.test(p) ? path.basename(p) : p)).join(' ').slice(0, 60);
}

module.exports = { inspect, findOwner, hidgNodes, hidrawNodes, CONFIGFS };
