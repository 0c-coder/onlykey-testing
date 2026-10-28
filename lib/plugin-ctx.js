'use strict';
/*
 * What a side-loaded firmware plugin test gets from the kit (`ctx`), shared by the two
 * files that side-load them: 08-plugins/01-softkey-plugins (the emulator, from its build.json) and
 * 08-plugins/00-hardkey-plugins (a hard key, plugins named per run). A plugin test reaches the kit only
 * through this, never by a relative path into the repo.
 */
const { IFACE, okmsg } = require('./device');
const { PINS } = require('./config');

/*
 * requireLib: the kit's OWN pinned node-onlykey-lib, by public subpath - a plugin's
 * test checks the firmware against the library the kit runs, never a copy of its own.
 */
/*
 * OKT_LIB_DIR: a node-onlykey-lib CHECKOUT to load instead of the kit's pinned copy, for `node-onlykey-lib/...` ids -
 * resolved through that checkout's own package.json exports, as a consumer resolves it. So a lib change is proven
 * against the firmware before the kit re-pins (the ctap_bridge tunnel test, 2026-10-26). Unset: the pinned copy.
 */
function requireLib(id) {
  const dir = process.env.OKT_LIB_DIR;
  const m = /^node-onlykey-lib(?:\/(.*))?$/.exec(id);
  if (!dir || !m) return require(id);
  const path = require('path');
  const exp = require(path.join(dir, 'package.json')).exports || {};
  const target = exp[m[1] ? `./${m[1]}` : '.'];
  if (typeof target !== 'string') throw new Error(`${id}: not exported by the lib at OKT_LIB_DIR=${dir}`);
  return require(path.join(dir, target));
}

function pluginCtx({ debug }) {
  return {
    IFACE, okmsg, PINS,
    requireLib,
    /* the same library's FILE path (a plugin test that hands a lib program to a child process, e.g. git's gpg.program) */
    resolveLib: (id) => require.resolve(id),
    /*
     * the kit's own helpers a plugin test may need: the device backup (a plugin's
     * backup section rides on it), and pqc (readyForKeygen: config mode, for
     * loading the keys a plugin test signs or decrypts with)
     */
    kit: {
      backup: require('./device/backup'), pqc: require('./pqc'),
      /* the lib composed over the kit's device, in-process (lib/libstack.js) - for a plugin test that runs lib code against the firmware */
      libstack: require('./libstack'),
      /* the kit's CTAP2 layer and WebAuthn tunnel: a plugin proves what it REFUSES over CTAP (config) */
      ctap2: require('./device/ctap2'), tunnel: require('./device/tunnel'),
      /* a browser's WebAuthn over the kit's device (lib/webenv.js): a plugin test composes the lib as a web page does (ctap_bridge) */
      webenv: require('./webenv'),
      /* RSA slots from a host (lib/rsa-slots.js): load, read, wipe - a patch test proves an RSA fix (0013) */
      rsaSlots: require('./rsa-slots'),
    },
    /* a DEBUG build: some plugin requests exist only there (config's OKSETCONFIG) */
    build: { debug },
  };
}

module.exports = { pluginCtx };
