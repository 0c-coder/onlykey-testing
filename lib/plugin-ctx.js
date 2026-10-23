'use strict';
/*
 * What a side-loaded firmware plugin test gets from the kit (`ctx`), shared by the two
 * files that side-load them: 01-protocol/38 (the emulator, from its build.json) and
 * 01-protocol/37 (a hard key, plugins named per run). A plugin test reaches the kit only
 * through this, never by a relative path into the repo.
 */
const { IFACE, okmsg } = require('./device');
const { PINS } = require('./config');

/*
 * requireLib: the kit's OWN pinned node-onlykey-lib, by public subpath - a plugin's
 * test checks the firmware against the library the kit runs, never a copy of its own.
 */
function pluginCtx({ debug }) {
  return {
    IFACE, okmsg, PINS,
    requireLib: (id) => require(id),
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
    },
    /* a DEBUG build: some plugin requests exist only there (config's OKSETCONFIG) */
    build: { debug },
  };
}

module.exports = { pluginCtx };
