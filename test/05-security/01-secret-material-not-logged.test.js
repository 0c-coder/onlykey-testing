/*
 * The web app's device code must not print secret key material to the console.
 *
 * WHAT IS SECRET HERE. The transit key established by OKCONNECT between the
 * page and the device: every sealed chunk and every sealed reply of the
 * session is under it, so anyone holding it can read and forge that traffic.
 *
 * WHY THE CONSOLE MATTERS on a page that handles private keys. The browser
 * console is not a private channel: devtools history persists, extensions with
 * debugger access read it, screen shares and pasted bug reports carry it, and
 * the nw.js harness this kit runs captures every line. A key that reaches it
 * has left the boundary the device exists to enforce.
 *
 * WHAT THE WEB APP'S DEVICE CODE IS NOW. Since the port (2026-09-29) it is
 * node-onlykey-lib's browser stack - the web app's own in-repo library, which
 * this file used to load and whose "Transit shared secret" Uint8Array it once
 * caught, is gone. The library keeps the transit key inside its session and
 * hands no handle to it out, so there is no value to search the output for.
 * This asserts the property that does not need the value: through a real
 * handshake and a real derive, the library printed NO byte buffer at all. Any
 * rendering of a key - decimal array, hex run, base64 run - trips it, and so
 * would a future line dumping a response or a handle.
 *
 * The capture is GLOBAL (the library logs, if it logs, through the global
 * console, not an injected one) and is restored afterwards whatever happens.
 */
'use strict';

const util = require('util');

const { describe, it } = require('../../lib/harness');
const { PINS } = require('../../lib/config');
const webenv = require('../../lib/webenv');

const BYTE_BUFFERISH = [
  ['a decimal byte array', /\d{1,3}(?:,\s*\d{1,3}){15,}/],
  ['a long hex run', /\b[0-9a-fA-F]{40,}\b/],
  ['a long base64 run', /\b[A-Za-z0-9+/]{40,}={0,2}\b/],
];

const CONTROL_LINE = 'okt: console capture is wired';

describe('the web app\'s device code does not log secret key material', {
  state: 'initialized',
  requires: ['crypto'],
  negative: true,
  timeoutMs: 180000,
}, () => {
  it('prints no byte buffers through a tunnel handshake and a derive',
    async ({ device, assert, signal, log }) => {
      await device.restart({ signal });
      await device.unlock(PINS.primary, { signal });

      const seen = [];
      const record = (...args) => {
        seen.push(args.map((a) => (typeof a === 'string'
          ? a
          : util.inspect(a, { depth: null, maxArrayLength: null }))).join(' '));
      };
      const METHODS = ['log', 'info', 'warn', 'error', 'debug'];
      const saved = METHODS.map((m) => console[m]);
      METHODS.forEach((m) => { console[m] = record; });
      let answer = null;
      let derived = null;
      try {
        /* CONTROL: prove the recorder is the console before trusting silence. */
        console.log(CONTROL_LINE);
        const { okcrypto } = await webenv.browserLib(device, { signal, connect: false });
        answer = await okcrypto.connectTunnel();
        derived = await okcrypto.derivePublicKey('okt:console-capture', { keytype: 1 });
      } finally {
        METHODS.forEach((m, i) => { console[m] = saved[i]; });
      }

      log(`captured ${seen.length} line(s); connect said ${String(answer && answer.status).trim()}`);
      assert.control('the capture replaced the global console', seen[0] === CONTROL_LINE);
      assert.control('the handshake completed', Boolean(answer && answer.status));
      assert.control('the derive completed', Boolean(derived && derived.publicKey));

      /* CONTROL: the matchers fire on something buffer-shaped, so a clean result cannot be a broken regex. */
      const probe = util.inspect(new Uint8Array(32).fill(7), { depth: null, maxArrayLength: null });
      assert.control('the byte-buffer matchers detect a real 32-byte buffer',
        BYTE_BUFFERISH.some(([, rx]) => rx.test(probe)));

      for (const [what, rx] of BYTE_BUFFERISH) {
        const hit = seen.find((line) => rx.test(line));
        assert.absent(!hit,
          `the library printed ${what}: ${String(hit).slice(0, 120)}. A handshake `
          + 'derives a transit key and a derive returns key material; nothing '
          + 'buffer-shaped should reach the console from either.');
      }
    });
});
