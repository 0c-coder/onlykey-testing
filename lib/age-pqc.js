/*
 * age-pqc.js - the derived (label-based) X-Wing split-custody maths, in JS.
 *
 * A port of python-onlykey's onlykey/age_plugin/derived_xwing.py, which is what
 * age-plugin-onlykey actually computes, and the twin of what the web app
 * computes in a browser. Three implementations have to agree byte for byte -
 * this one, the CLI's (kyber_py), and the firmware's
 * (okcrypto_xwing_web_derive(), okcrypto.cpp) - and a disagreement shows up as
 * "decryption failed" with no indication of which of the three is wrong.
 *
 * Split custody is the whole point: the device holds sk_X and never emits it.
 * What it emits is one X25519 shared secret and a one-way
 * SHA256(sk_X || tag)-derived ML-KEM seed the host expands locally, so neither
 * half can decrypt alone.
 *
 *   DERIVE_PUBLIC_KEY -> [ pk_X(32) | mlkem_seed(32) ]
 *   DERIVE_SHAREDSEC  -> [ ss_X(32) | mlkem_seed(32) ]
 *
 * This module reaches no device. It is the host half on its own, which is what
 * lets it be checked against a fixed vector in the sanity section, with no
 * device host, no gadget and no key - and, one day, what a real derive over the
 * WebAuthn tunnel will be checked AGAINST. Getting the maths pinned first is
 * what will make that debuggable: when the tunnelled derive command starts
 * answering, a mismatch is then the device's option bytes and not this file.
 *
 * The three @noble packages are optional dependencies and are loaded on first
 * use, not at require() time, so that a kit without them can still LOAD this
 * file and report a skip with a reason - the same arrangement as node-hid in
 * lib/device/hardware.js. See the 'xwing-math' capability.
 *
 * THE MATHS NOW COME FROM node-onlykey-lib (crypto.pqc - one lib, any GUI; the
 * test CLI is a GUI), whose age_pqc.js was ported from this file. The three
 * implementations that have to agree are now the library, the CLI's and the
 * firmware's - still three, still independent of one another. Checked before
 * the switch: the keypair from a seed, the recipient, the combiner, ctXOf,
 * splitDecapsulate (recovering the host's secret), recipient and identity
 * encoding - 13/13 identical - and bech32 20/20. The library is loaded on first
 * use too, so this file still loads, and probe() still answers, without it.
 * What stays here: probe() / PACKAGES (the kit's own dependency check) and the
 * three X25519 helpers that stand in for a device that is not there.
 */
'use strict';

const PACKAGES = ['@noble/post-quantum', '@noble/hashes', '@noble/curves'];

let loaded = null;

/**
 * The packages, loaded once - x25519 for the stand-in helpers below; the rest
 * are what node-onlykey-lib's maths need, so probe() still says whether the
 * X-Wing maths can run at all.
 */
function deps() {
  if (loaded) return loaded;
  try {
    loaded = {
      ml_kem768: require('node-onlykey-lib/vendor/@noble/post-quantum/ml-kem.js').ml_kem768,
      shake256: require('node-onlykey-lib/vendor/@noble/hashes/sha3.js').shake256,
      x25519: require('node-onlykey-lib/vendor/@noble/curves/ed25519.js').x25519,
    };
  } catch (err) {
    /* First line only: node appends a whole require stack, and this string is
     * a skip REASON that has to read as one sentence in a log. */
    const [first] = String(err.message).split('\n');
    throw new Error(
      `the X-Wing maths need ${PACKAGES.join(', ')}, which node-onlykey-lib ` +
      `vendors - is it installed? npm install  (${first})`
    );
  }
  return loaded;
}

/**
 * Whether the packages are here, and one sentence saying what to do if not.
 * Read by lib/capabilities.js, which is why it must not throw.
 *
 * @returns {{ok: boolean, why: string|null}}
 */
function probe() {
  try {
    deps();
    return { ok: true, why: null };
  } catch (err) {
    return { ok: false, why: err.message };
  }
}

/* node-onlykey-lib's crypto.pqc, on first use (see the header). */
let pqcLib = null;
function lib() {
  if (!pqcLib) { deps(); pqcLib = require('node-onlykey-lib/crypto').pqc; }
  return pqcLib;
}

/* Sizes and constants - the library's, same values (checked). */
const MLKEM_PK = 1184;
const MLKEM_CT = 1088;
const XWING_PK = 1216;
const XWING_CT = 1120;
const SEED = 32;
const XWING_LABEL = Uint8Array.from([0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c]);
const RECIPIENT_HRP = 'age1onlykey';
const IDENTITY_HRP = 'age-plugin-onlykey-';   // must match cli.py's IDENTITY_HRP
const DERIVED_MARKER = 0xFF;

/** X25519 on the device's behalf, for a test that has no device. */
function x25519Base(skX) {
  return deps().x25519.getPublicKey(skX);
}

/** ss_X, the one value a real device computes and returns. */
function x25519Shared(skX, ctX) {
  return deps().x25519.getSharedSecret(skX, ctX);
}

/** A random X25519 secret, for standing in for a device that is not here. */
function x25519Secret() {
  return deps().x25519.utils.randomSecretKey();
}

/* The library's, forwarded - a forwarder rather than a reference so the
 * library is not loaded until something is actually computed. */
const fwd = (name) => (...args) => lib()[name](...args);

/**
 * A DERIVED identity, or null - this file's contract, which callers rely on to
 * fall back to a slot decode. The library's decodeIdentity() reads BOTH kinds
 * and returns {derived: false, slot, ...} for a slot identity; returned as is,
 * a slot identity would be taken for a derived one (00-sanity's
 * 04-age-pqc-derived caught exactly that on the switch).
 */
function decodeIdentity(s) {
  const r = lib().decodeIdentity(s);
  return r && r.derived ? r : null;
}

module.exports = {
  probe,
  PACKAGES,
  mlkemKeypairFromSeed: fwd('mlkemKeypairFromSeed'),
  buildRecipient: fwd('buildRecipient'),
  xwingCombiner: fwd('xwingCombiner'),
  splitDecapsulate: fwd('splitDecapsulate'),
  ctXOf: fwd('ctXOf'),
  xwingEncapsHost: fwd('xwingEncapsHost'),
  x25519Base,
  x25519Shared,
  x25519Secret,
  encodeIdentity: fwd('encodeIdentity'),
  decodeIdentity,
  encodeRecipient: fwd('encodeRecipient'),
  decodeRecipient: fwd('decodeRecipient'),
  bech32Encode: fwd('bech32Encode'),
  bech32Decode: fwd('bech32Decode'),
  RECIPIENT_HRP,
  IDENTITY_HRP,
  DERIVED_MARKER,
  XWING_LABEL,
  MLKEM_PK,
  MLKEM_CT,
  XWING_PK,
  XWING_CT,
  SEED,
};
