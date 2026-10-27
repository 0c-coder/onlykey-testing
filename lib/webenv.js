/*
 * webenv.js - the browser, as node-onlykey-lib sees it in a web page, with
 * this kit's device behind it instead of a USB stack.
 *
 * The web app (apps.onlykey.io 4.0.0, ported to node-onlykey-lib on the bm-ok
 * branch use-node-onlykey-lib) reaches the key through ONE call:
 * navigator.credentials.get(). Everything the pages do on the device - the
 * tunnel, the derivations, PGP - funnels through it, via the library's browser
 * stack (node-onlykey-lib/browser). So this points that one function at
 * lib/device/ctap2.js, and the library reaches the emulated device over the
 * in-process bus. No USB, no kernel node, no display, no browser - which is why
 * the web app's device path can be tested in CI.
 *
 * WHAT CHANGED (2026-09-29). This used to load the web app's OWN in-repo
 * library (src/onlykey-fido2/onlykey/*: onlykey-api, onlykey-3rd-party,
 * onlykey-pgp, age_pqc, composite_pgp, with kbpgp/forge/nacl) and drive it.
 * The port deleted that library - every page runs on node-onlykey-lib - so
 * what is left to fake is only the browser: create() is the window and
 * navigator.credentials, browserLib() composes the library on it exactly as
 * the web app's okLib plugin does, and webappModule() loads a module of the
 * app's own (its classic PGP engine) from the checkout under test.
 *
 * The earlier ancestors (test-api's window_replacements, the old kit's
 * browser_env.js) wired credentials.get to @vincss-public-projects/fido2-client
 * over node-hid and needed a real device node; this does not.
 */
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { EventEmitter } = require('events');

const { Ctap2 } = require('./device/ctap2');
const { RP_ID } = require('./device/tunnel');

/* The web app checkout under test; the kit must not assume where. */
const WEBAPP_SRC = path.join(require('./paths').WEBAPP_ROOT, 'src');

/**
 * Is the web app checked out, on node-onlykey-lib? The port's marker is its
 * okLib plugin; a checkout without it is the pre-port app (whose in-repo
 * library the kit no longer drives) or none at all.
 * @returns {{ok: boolean, why: string|null}}
 */
function probe() {
  if (fs.existsSync(path.join(WEBAPP_SRC, 'onlykey-lib', 'plugin.js'))) return { ok: true, why: null };
  return {
    ok: false,
    why: `the web app at ${path.dirname(WEBAPP_SRC)} is not the node-onlykey-lib port ` +
      '(bm-ok/0c-coder-onlykey.github.io branch use-node-onlykey-lib)',
  };
}

function base64url(buf) {
  return Buffer.from(buf).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * A WebAuthn assertion, the way a browser hands one back.
 *
 * Buffers rather than ArrayBuffers on purpose: the library's Node branch
 * (onlykey-api.js:272) does Buffer.from(response.authenticatorData.slice(...)),
 * so this is the shape it expects when getOS() says "Node".
 */
function assertionResponse(assertion, credentialId, clientDataJSON) {
  return {
    id: base64url(credentialId),
    rawId: Buffer.from(credentialId),
    type: 'public-key',
    response: {
      authenticatorData: assertion.get(2),
      signature: assertion.get(3),
      clientDataJSON: Buffer.from(clientDataJSON, 'utf8'),
      userHandle: assertion.get(4) || null,
    },
  };
}

/**
 * A failure shaped like the browser's.
 *
 * The library reads error.name and nothing else - it checks for AbortError,
 * NS_ERROR_ABORT, InvalidStateError and NotAllowedError by name. A bare Error
 * would take a path meant for something quite different, so anything the
 * authenticator refuses is reported the way a browser reports it: NotAllowedError.
 */
function webAuthnError(err) {
  const out = new Error(err && err.message ? err.message : String(err));
  out.name = 'NotAllowedError';
  out.cause = err;
  return out;
}

/**
 * The browser surface, with `device` behind it.
 *
 * @param {object} device the kit's device handle
 * @param {object} [opts] {rpId, ctap, signal, onKeepAlive, console, silentCheck (Windows: an up-false check before each request)}
 * @returns {{window, app, console, ctap}}
 */
function create(device, opts = {}) {
  const rpId = opts.rpId || RP_ID;
  const ctap = opts.ctap || new Ctap2(device);
  let started = ctap.started === true;

  const window = {
    /*
     * node:crypto's webcrypto has the two things the library reaches for -
     * subtle.digest and getRandomValues - so there is nothing to shim here
     * beyond handing it over under the name a browser uses.
     */
    crypto: crypto.webcrypto,
    TextEncoder,
    TextDecoder,
    atob: (s) => Buffer.from(s, 'base64').toString('latin1'),
    btoa: (s) => Buffer.from(s, 'latin1').toString('base64'),

    /*
     * The origin the page runs at. The key admits only its trusted origins
     * (webcryptcheck, 3.1.0 on), and on v3.0.4 the rpId is also an input to
     * derived keys - so this matches what tunnel.js and the CLI use.
     */
    location: { hostname: rpId, origin: `https://${rpId}`, href: `https://${rpId}/` },

    navigator: {
      /* Exactly "NODE": getOS() compares the whole string. */
      userAgent: 'NODE',
      vendor: 'node',
      platform: 'Linux',

      credentials: {
        /**
         * The one call the library makes at the device, translated into the
         * CTAP2 GetAssertion this kit already speaks.
         */
        async get({ publicKey } = {}) {
          if (!publicKey) throw webAuthnError(new Error('no publicKey options'));

          if (!started) {
            await ctap.init(opts);
            started = true;
          }

          /*
           * A real clientDataJSON, hashed properly. The device does not read
           * it on the tunnel path, but it is signed over on every other path,
           * so building it correctly here keeps this shim honest for the
           * ceremonies as well as the tunnel.
           */
          const clientDataJSON = JSON.stringify({
            type: 'webauthn.get',
            challenge: base64url(publicKey.challenge || crypto.randomBytes(32)),
            origin: `https://${publicKey.rpId || rpId}`,
            crossOrigin: false,
          });

          const allow = (publicKey.allowCredentials || []).map(
            (c) => new Map([['id', Buffer.from(c.id)], ['type', c.type || 'public-key']])
          );

          const params = new Map([
            [1, publicKey.rpId || rpId],
            [2, crypto.createHash('sha256').update(clientDataJSON).digest()],
          ]);
          if (allow.length) params.set(3, allow);

          /*
           * opts.silentCheck: THE HOST WINDOWS IS. Windows' WebAuthn sends every allowCredentials request twice: first
           * a silent check (options.up false - "is this credential yours?"), then the real request (up true). A key
           * that ACTS on the silent check sees the real one as a repeat (libraries patch 0015). The silent check's
           * answer is dropped, as Windows drops it; a refusal of it ends the ceremony, as on Windows.
           */
          if (opts.silentCheck) {
            const check = new Map(params);
            check.set(5, new Map([['up', false]]));
            try {
              await ctap.getAssertion(check, { timeoutMs: publicKey.timeout || 30000, signal: opts.signal });
            } catch (err) {
              throw webAuthnError(err);
            }
            params.set(5, new Map([['up', true]]));
          }

          try {
            const assertion = await ctap.getAssertion(params, {
              timeoutMs: publicKey.timeout || 30000,
              signal: opts.signal,
              onKeepAlive: opts.onKeepAlive,
            });
            const first = publicKey.allowCredentials && publicKey.allowCredentials[0];
            return assertionResponse(
              assertion,
              (first && first.id) || Buffer.alloc(0),
              clientDataJSON
            );
          } catch (err) {
            throw webAuthnError(err);
          }
        },
      },
    },
  };

  /* The app event bus the web app's plugins announce on (ok-connected ...). */
  const app = new EventEmitter();
  app.setMaxListeners(0);
  app.on('error', () => {});

  return { window, app, console: opts.console || quietConsole(), ctap };
}

/**
 * The library's browser stack on that window, CONNECTED - what the web app's
 * okLib plugin (src/onlykey-lib/plugin.js) builds, minus the page's focus gate.
 *
 * @param {object} device the kit's device handle
 * @param {object} [opts] as create(), plus `connect: false` to skip connectTunnel
 * @returns {Promise<{lib, okcrypto, window, app}>}
 */
async function browserLib(device, opts = {}) {
  const env = create(device, opts);
  const { startBrowser } = require('node-onlykey-lib/browser');
  /*
   * A page at another origin (the kit's local server is `localhost`) names it
   * in BOTH places the library keeps an rpId - the ctap's and okcrypto's list -
   * or the library refuses the mismatch before asking anything. Only a DEBUG
   * build admits an origin outside apps.crp.to / apps.onlykey.io.
   */
  const lib = await startBrowser({
    credentials: env.window.navigator.credentials,
    rpId: opts.rpId,
    config: opts.rpId ? { okcrypto: { rpIds: [opts.rpId] } } : {},
  });
  const okcrypto = lib.services.okcrypto;
  if (opts.connect !== false) await okcrypto.connectTunnel();
  return { lib, okcrypto, window: env.window, app: env.app };
}

/** A module of the web app's own, from the checkout under test (e.g. 'onlykey-lib/pgp-engine.js'). */
function webappModule(relPath) {
  return require(path.join(WEBAPP_SRC, relPath));
}

/** The PQC-aware openpgp fork - node-onlykey-lib's copy, the one the web app now bundles. */
function openpgp() {
  return require('node-onlykey-lib/crypto/pgp');
}

/** A console that says nothing; pass `console` in opts to watch instead. */
function quietConsole() {
  const noop = () => {};
  return { log: noop, warn: noop, error: noop, info: noop, debug: noop };
}

module.exports = {
  create, browserLib, webappModule, openpgp, probe, quietConsole, WEBAPP_SRC,
};
