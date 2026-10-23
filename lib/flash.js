/*
 * flash.js - put a firmware image on a directly-attached key.
 *
 * A Node port of the parts of onlykey-usb-hid-passthrough/tools/halfkay_flash.py
 * this kit needs, brought over rather than depended on because the kit is its
 * own repository and must not assume its neighbours are checked out. It writes
 * to /dev/hidrawN directly, so it needs neither node-hid nor python.
 *
 * One thing is different from the original, and it is the reason this exists:
 * IT PACES THE WRITES.
 *
 * HalfKay programs a 1 KB block after acknowledging the control transfer, and
 * NAKs anything that arrives while it is busy; the kernel surfaces that as
 * EPIPE. Flashing THROUGH the Feather proxy never hits it, because the proxy
 * holds each large OUT report for up to PROXY_OUT_BLOCK_MS (4000) waiting for a
 * slot - the proxy is the thing providing back-pressure. Attached directly
 * there is no proxy and nothing paces anything, so the flash dies a few blocks
 * in. Measured, with the original tool and --no-health:
 *
 *   FAILED writing block at 0x001000 (block 4): [Errno 32] Broken pipe
 *
 * Fifteen milliseconds between blocks fixes it, and costs three seconds on a
 * 210-block image. A NAK is also retried rather than treated as fatal, because
 * "busy" and "broken" are not the same answer.
 *
 * Each block travels as a 1089-byte report (1 report ID + 3 address bytes + 61
 * pad + 1024 data). A report that size cannot go down an interrupt endpoint,
 * and HalfKay has no OUT endpoint anyway, so the kernel routes it through the
 * control pipe as SET_REPORT by itself.
 */
'use strict';

const fs = require('fs');
const path = require('path');

/* Teensy HalfKay, which is what the key enumerates as with the button held. */
const BOOTLOADER_VID = 0x16C0;
const BOOTLOADER_PID = 0x0478;

/* MK20DX256 - the part in an OnlyKey. */
const CODE_SIZE = 262144;
const BLOCK_SIZE = 1024;
const REPORT_SIZE = 1 + 64 + BLOCK_SIZE;   // report ID, header+pad, data

const SYSFS_HIDRAW = '/sys/class/hidraw';

/**
 * Find the HalfKay bootloader's hidraw node, without node-hid.
 *
 * HID_ID in each node's uevent is "bus:VVVVVVVV:PPPPPPPP", which is enough:
 * HalfKay presents a single HID interface, so the first match is the one.
 * @returns {string|null}
 */
function findBootloader() {
  /*
   * WINDOWS has no hidraw: the bootloader is found and written through node-hid, which sends the
   * same reports (report ID 0, then the block). The key's FIDO interface needs an elevated shell
   * on Windows; HalfKay does not, but the kit's Windows runs go through okt-elevated anyway.
   */
  if (process.platform === 'win32') {
    const dev = require('node-hid').devices()
      .find((d) => d.vendorId === BOOTLOADER_VID && d.productId === BOOTLOADER_PID);
    return dev ? dev.path : null;
  }
  let nodes;
  try {
    nodes = fs.readdirSync(SYSFS_HIDRAW).sort();
  } catch {
    return null;                     // not Linux, or no HID at all
  }

  const want = `:${BOOTLOADER_VID.toString(16).toUpperCase().padStart(8, '0')}:` +
    `${BOOTLOADER_PID.toString(16).toUpperCase().padStart(8, '0')}`;

  for (const node of nodes) {
    let uevent;
    try {
      uevent = fs.readFileSync(path.join(SYSFS_HIDRAW, node, 'device', 'uevent'), 'utf8');
    } catch {
      continue;
    }
    const line = uevent.split('\n').find((l) => l.startsWith('HID_ID='));
    if (line && line.toUpperCase().includes(want)) return `/dev/${node}`;
  }
  return null;
}

/**
 * Intel HEX to a flat image.
 * @returns {{mem: Buffer, used: Uint8Array}} mem is 0xFF where nothing was set
 */
function readIntelHex(file) {
  const mem = Buffer.alloc(CODE_SIZE, 0xFF);
  const used = new Uint8Array(CODE_SIZE);
  let base = 0;

  for (const raw of fs.readFileSync(file, 'utf8').split('\n')) {
    const line = raw.trim();
    if (!line.startsWith(':')) continue;

    const bytes = Buffer.from(line.slice(1), 'hex');
    if (bytes.length < 4) continue;

    const count = bytes[0];
    const addr = (bytes[1] << 8) | bytes[2];
    const type = bytes[3];
    const data = bytes.subarray(4, 4 + count);

    if (type === 0x00) {
      for (let i = 0; i < data.length; i++) {
        const off = base + addr + i;
        if (off >= 0 && off < CODE_SIZE) {
          mem[off] = data[i];
          used[off] = 1;
        }
      }
    } else if (type === 0x01) {
      break;                                        // end of file
    } else if (type === 0x02) {
      base = ((data[0] << 8) | data[1]) * 16;       // extended segment
    } else if (type === 0x04) {
      base = ((data[0] << 8) | data[1]) << 16;      // extended linear
    }
  }

  return { mem, used };
}

/** One block, retried on EPIPE - a NAK means "busy", not "broken". */
function writeBlock(fd, report, { retries, delayMs }) {
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      if (typeof fd === 'object') fd.write([...report]);   // node-hid (Windows)
      else fs.writeSync(fd, report, 0, report.length);
      return;
    } catch (err) {
      /* Windows: a write while HalfKay is still erasing fails like EPIPE does on Linux - retry it. */
      const busy = err.code === 'EPIPE' || (typeof fd === 'object' && /write|Cannot/i.test(String(err.message)));
      if (!busy || attempt === retries) {
        throw new Error(`${err.code || err.message} (attempt ${attempt})`);
      }
      /* Back off further each time rather than hammering it. */
      const until = Date.now() + delayMs * attempt;
      while (Date.now() < until) { /* busy wait - writeSync is sync anyway */ }
    }
  }
}

/**
 * Program a hex file onto an attached HalfKay bootloader.
 *
 * @param {string} hexFile
 * @param {object} [opts] {delayMs, eraseMs, retries, reboot, log}
 * @returns {{blocks:number, bytes:number, ms:number, devPath:string}}
 */
function flash(hexFile, opts = {}) {
  const {
    delayMs = 15,
    eraseMs = 3000,
    retries = 8,
    reboot = true,
    log = () => {},
  } = opts;

  /* The image first: it is the cheaper question, and answering "tap the
   * bootloader button" to somebody who mistyped a path sends them to the
   * hardware for a problem that is on disk. */
  if (!fs.existsSync(hexFile)) throw new Error(`no such hex file: ${hexFile}`);
  const { mem, used } = readIntelHex(hexFile);

  const devPath = findBootloader();
  if (!devPath) {
    throw new Error(
      'no Teensy HalfKay bootloader found (16C0:0478). Tap the button on the ' +
      'key to enter the bootloader, then run this again.'
    );
  }

  const total = used.reduce((n, u) => n + u, 0);
  log(`${path.basename(hexFile)}: ${total} bytes (${(100 * total / CODE_SIZE).toFixed(1)}% of ${CODE_SIZE})`);
  log(`writing to ${devPath}, ${delayMs}ms between blocks`);

  const fd = process.platform === 'win32'
    ? new (require('node-hid').HID)(devPath)
    : fs.openSync(devPath, 'w');
  const started = Date.now();
  let blocks = 0;

  try {
    for (let addr = 0; addr < CODE_SIZE; addr += BLOCK_SIZE) {
      /* Block 0 always goes, empty or not: it is what triggers the chip erase. */
      let any = false;
      for (let i = addr; i < addr + BLOCK_SIZE && !any; i++) if (used[i]) any = true;
      if (blocks > 0 && !any) continue;

      const report = Buffer.alloc(REPORT_SIZE);        // report ID 0 at [0]
      report[1] = addr & 0xFF;
      report[2] = (addr >> 8) & 0xFF;
      report[3] = (addr >> 16) & 0xFF;
      mem.copy(report, 1 + 64, addr, addr + BLOCK_SIZE);

      try {
        writeBlock(fd, report, { retries, delayMs });
      } catch (err) {
        throw new Error(`failed writing block ${blocks} at 0x${addr.toString(16)}: ${err.message}`);
      }

      /* The first write erases the whole chip and takes far longer than the
       * rest; everything after it just needs the device to finish programming. */
      sleepSync(blocks === 0 ? eraseMs : delayMs);
      blocks++;
    }

    if (reboot) {
      const bye = Buffer.alloc(REPORT_SIZE);
      bye[1] = bye[2] = bye[3] = 0xFF;                 // HalfKay's reboot command
      writeBlock(fd, bye, { retries, delayMs });
      log('reboot sent');
    }
  } finally {
    try { if (typeof fd === 'object') fd.close(); else fs.closeSync(fd); } catch { /* going away anyway */ }
  }

  const ms = Date.now() - started;
  log(`programmed ${blocks} blocks (${blocks * BLOCK_SIZE} bytes) in ${(ms / 1000).toFixed(2)}s`);
  return { blocks, bytes: blocks * BLOCK_SIZE, ms, devPath };
}

/* Synchronous on purpose: the whole flash is a synchronous fd write loop, and
 * an await here would let something else touch the device mid-image. */
function sleepSync(ms) {
  const until = Date.now() + ms;
  while (Date.now() < until) { /* spin */ }
}

/**
 * Wait for the key to come back on the bus after a reboot.
 *
 * The flash is only half the story - "reboot sent" says the command went out,
 * not that anything came back. Polls sysfs rather than node-hid so this stays
 * usable when the kit's optional dependency is not installed.
 * @returns {boolean} whether it reappeared in time
 */
function waitForKey(vid = 0x1D50, pid = 0x60FC, timeoutMs = 15000) {
  const want = `:${vid.toString(16).toUpperCase().padStart(8, '0')}:` +
    `${pid.toString(16).toUpperCase().padStart(8, '0')}`;
  const deadline = Date.now() + timeoutMs;

  while (Date.now() < deadline) {
    if (process.platform === 'win32') {
      if (require('node-hid').devices().some((d) => d.vendorId === vid && d.productId === pid)) return true;
      sleepSync(250);
      continue;
    }
    let nodes = [];
    try { nodes = fs.readdirSync(SYSFS_HIDRAW); } catch { /* not yet */ }
    for (const node of nodes) {
      try {
        const uevent = fs.readFileSync(path.join(SYSFS_HIDRAW, node, 'device', 'uevent'), 'utf8');
        if (uevent.toUpperCase().includes(want)) return true;
      } catch { /* raced a disappearing node */ }
    }
    sleepSync(250);
  }
  return false;
}

module.exports = {
  flash, findBootloader, readIntelHex, waitForKey,
  BOOTLOADER_VID, BOOTLOADER_PID, CODE_SIZE, BLOCK_SIZE,
};
