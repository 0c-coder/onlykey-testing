/*
 * node-onlykey-lib, composed over the kit's own device - no gadget, no okvhid,
 * no browser.
 *
 * WHY THIS EXISTS. The lib reaches a key through a transport plugin, and the
 * one meant for "a host that already holds the bytes" is transport/embedded:
 * ok-rn's soft key feeds it the in-process emulator's frames. The kit holds the
 * same thing - the emulator's four interfaces, in-process - so composing the
 * lib on it here runs the lib's real code against the real firmware with
 * nothing in between. section 2 needs the gadget (client-access) because it
 * drives a second CLIENT; this is the same process, so it does not, and it
 * runs on Windows where okvhid devices are 0/4.
 *
 * THE PIPE CONTRACT is the lib's (src/transport/pipeTransport.js): start, stop,
 * isRunning, write(iface, bytes), on('stream', fn) with {iface, dir, bytes} for
 * traffic BOTH ways. The kit's transport emits device->host reports as
 * 'hid'/'keyboard' events; host->device writes are echoed here with dir IN so
 * `dir` means what it means on the lib's other pipes.
 *
 * THE LIFECYCLE STAYS THE KIT'S. start/stop are no-ops and isRunning is true:
 * app.destroy() closes the lib's transport, and that must not halt the
 * emulator under the rest of the file. A device.restart() reboots the firmware
 * under the same kit transport, so a stack composed once survives it.
 *
 * `writes` RECORDS every host->device frame the lib sent, in order. That is the
 * instrument the G2 tests read when they claim "nothing was sent" - and why
 * each of them also proves, in the same test, that a write it DID make is
 * recorded here (assert.control): an empty list from a dead recorder would
 * read exactly like a refusal.
 */
'use strict';

const { IFACE } = require('./device');

/* The lib's DIR (src/transport/contract.js): OUT = device -> host. */
const DIR = { OUT: 0, IN: 1 };

const PLUGINS = () => [
  require('node-onlykey-lib/plugins/host'),
  require('node-onlykey-lib/plugins/transport/embedded'),
  require('node-onlykey-lib/plugins/session'),
  require('node-onlykey-lib/plugins/device'),
  require('node-onlykey-lib/plugins/okcrypto'),
];

/** A byte pipe over the kit's device handle, plus the record of what was sent. */
function kitPipe(device) {
  const listeners = new Set();
  const writes = [];
  const transport = device.transport;

  const emit = (event) => {
    for (const fn of [...listeners]) {
      try { fn(event); } catch { /* a listener must not break the feed */ }
    }
  };
  const onHid = (iface, data) => emit({ iface, dir: DIR.OUT, bytes: Uint8Array.from(data) });
  const onKeyboard = (data) => emit({ iface: IFACE.KEYBOARD, dir: DIR.OUT, bytes: Uint8Array.from(data) });

  const pipe = {
    async start() {},
    async stop() {},
    isRunning() { return true; },
    async write(iface, bytes) {
      const buf = Buffer.from(bytes);
      writes.push({ iface, data: buf, at: Date.now() });
      device.send(iface, buf);
      emit({ iface, dir: DIR.IN, bytes: Uint8Array.from(buf) });
      return buf.length;
    },
    on(name, fn) {
      if (name !== 'stream') return () => {};
      if (!listeners.size) {
        transport.on('hid', onHid);
        transport.on('keyboard', onKeyboard);
      }
      listeners.add(fn);
      return () => {
        listeners.delete(fn);
        if (!listeners.size) {
          transport.removeListener('hid', onHid);
          transport.removeListener('keyboard', onKeyboard);
        }
      };
    },
  };
  return { pipe, writes };
}

/**
 * Compose the lib's Node stack (host, embedded transport, session, device,
 * okcrypto) over the kit's device. No ctap is supplied, so okcrypto reaches
 * the FIDO interface through its own CtapHid on this transport - the hard-key
 * path, not the browser's.
 *
 * @returns {Promise<{app, services, writes, vendorWrites, fidoWrites, destroy}>}
 */
async function composeLib(device, { config = {} } = {}) {
  const Rectify = require('@bmatusiak/rectify');
  const { pipe, writes } = kitPipe(device);
  const plugins = PLUGINS();
  plugins.config = { ...config, transport: { pipe } };
  const app = await new Promise((resolve, reject) => {
    const built = Rectify.build(plugins, (err, started) => (err ? reject(err) : resolve(started)));
    built.start();
  });
  const on = (iface) => () => writes.filter((w) => w.iface === iface);
  return {
    app,
    services: app.services,
    writes,
    vendorWrites: on(IFACE.VENDOR),
    fidoWrites: on(IFACE.FIDO),
    destroy: () => app.destroy(),
  };
}

module.exports = { composeLib, kitPipe, DIR };
