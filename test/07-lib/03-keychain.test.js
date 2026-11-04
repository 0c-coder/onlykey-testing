/*
 * node-onlykey-lib's Key Chain (L1 + L3, lib 0.4.0 in progress), against the
 * real firmware: keys made ON the device and on the host, named by their
 * label, and then recognised again by probeKeySlot - which has to work out
 * what a slot holds from its public key alone, because no command returns the
 * stored type byte.
 *
 * WHY AGAINST THE FIRMWARE. probeKeySlot is a chain of inferences about how the
 * firmware answers OKGETPUBKEY, and every link was written from a reading of
 * okcore.cpp / okcrypto.cpp and proved only against the lib's fake firmware -
 * which encodes the same reading. Three of the links are not things a reading
 * can settle:
 *
 *   ML-KEM vs X-Wing  both answer 19 reports. 1216 bytes (X-Wing) fill them;
 *                     1184 (ML-KEM) leave 32 bytes of the last one, and the lib
 *                     reads those 32 as LEFTOVER - send_transport_response
 *                     copying the short final piece over resp_buffer without
 *                     clearing it (okcore.cpp:2568-2573), so they repeat the
 *                     previous report's second half. If the firmware zeroed the
 *                     buffer, or the emulator's USB layer padded the report,
 *                     an ML-KEM slot would read as X-Wing with a pk_X of
 *                     junk - a recipient nobody holds. So it is probed WITHOUT
 *                     the label hint, and the raw last report is checked here
 *                     byte for byte, not only the lib's verdict.
 *   Ed25519 vs X25519 both answer 32 bytes. The lib asks again with field 4
 *                     (the Curve25519 conversion in okcrypto_geteccpubkey) and
 *                     calls the slot X25519 only if the key comes back the same.
 *                     Checked raw: an Ed25519 slot's field-4 answer must
 *                     differ from its field-0 key, and an X25519 slot's must
 *                     be its own key. What the Ed25519 one IS turned out not
 *                     to be the birational map of the Ed25519 key - the
 *                     host-key test pins the formula (unclamped, seed read
 *                     big-endian) where the secret is known.
 *   silence           config mode drops OKGETPUBKEY without a word
 *                     (okcore.cpp:335-340). A probe there must REJECT, naming
 *                     locked / config mode - never answer "empty", which would
 *                     invite a caller to write over a key that is there.
 *
 * THE ORACLES. A key the host made has a public key computed on the host - the
 * probe must return exactly it. An ML-KEM / X-Wing key made on the device was
 * answered by generateKey in config mode; the probe after the restart must
 * return the same bytes. A P-256 / secp256k1 answer is a point the lib checked
 * is on the curve; an Ed25519 / X25519 answer is cross-checked through the
 * conversion above. Labels are read back with the lib's own readKeyLabels.
 *
 * ONE LONG OPERATION, like 35: the keys made in the first test are probed,
 * renamed and wiped by the ones after it, and the second test needs the config
 * mode the first one entered. So this file is not --isolate material, and that
 * is the design rather than a fault.
 *
 * SURFACES: the lib over the kit's in-process emulator (lib/libstack.js,
 * transport/embedded), vendor only; raw OKGETPUBKEY reads through the kit's
 * device handle; presses through the firmware's debug button harness. No
 * gadget, so this runs on Windows.
 */
'use strict';

const crypto = require('crypto');

const { describe, it } = require('../../lib/harness');
const { IFACE, okmsg } = require('../../lib/device');
const { PINS } = require('../../lib/config');
const { composeLib } = require('../../lib/libstack');
const { keys: deviceKeys } = require('node-onlykey-lib/device');
const keychain = require('node-onlykey-lib/keychain');
const { ed25519, x25519 } = require('node-onlykey-lib/vendor/@noble/curves/ed25519.js');

/*
 * Slots: 34 uses ECC1 (101) and 35 slot 3's LABEL (a button slot, not RSA3);
 * this file keeps to ECC 105-116 and RSA3/RSA4 so a reader never has to
 * wonder whether a neighbour's key is what got probed.
 */
const DEVICE_KEYS = [
  { slot: 109, kind: 'ed25519', type: 1, use: { signature: true }, label: 'ssh:l8ed' },
  { slot: 110, kind: 'p256', type: 2, use: { signature: true }, label: 'sig:l8p256' },
  { slot: 111, kind: 'secp256k1', type: 3, use: { signature: true }, label: 'sig:l8k1' },
  { slot: 112, kind: 'x25519', type: 4, use: { decryption: true }, label: 'age:l8x' },
  { slot: 113, kind: 'mlkem768', type: 5, pqc: 1184, label: 'mlk:l8mlkem' },
  { slot: 114, kind: 'xwing', type: 6, pqc: 1216, label: 'xwg:l8xwing' },
];
const HOST_KEYS = [
  { slot: 105, kind: 'ed25519', host: 'ed25519', label: 'ssh:l8hosted' },
  { slot: 106, kind: 'p256', host: 'p256', label: 'sig:l8hostp' },
  { slot: 3, kind: 'rsa', host: 'rsa', bits: 2048, label: 'pgp:l8rsa' },
];
const EMPTY_ECC = 116;
const EMPTY_RSA = 4;
const RENAMED = 110;                    // setKeyLabel(..., '') blanks this one
const WIPED = 109;                      // wipeKey takes this one

const REPORT = 64;
const MLKEM_BYTES = 1184;
const XWING_BYTES = 1216;
const CURVE25519_FIELD = 4;             // OKGETPUBKEY field: the Curve25519 conversion

const CONFIG_MODE_REFUSAL = /LOCKED[\s\S]*config mode/;

const hex = (b) => Buffer.from(b).toString('hex');
const labelOf = (list, slot) => {
  const row = list.keys.find((k) => k.slot === slot);
  return row ? row.label : undefined;
};
/*
 * u(s * base) for a scalar s taken as-is - NO clamping, which is what the
 * firmware's Curve25519::eval does (it is the raw RFC 7748 function; only dh1
 * clamps). Done on the Edwards curve, whose base point maps to u = 9, and
 * mapped across: s mod L * G is the same point as s * G.
 */
function unclampedBase(s) {
  const L = ed25519.Point.Fn.ORDER;
  const point = ed25519.Point.BASE.multiply(((s % L) + L) % L || L);
  return Buffer.from(ed25519.utils.toMontgomery(point.toBytes()));
}

/* A status broadcast is not part of a key's answer. */
const isStatus = (buf) => /^(UNLOCKED|INITIALIZED|LOCKED|CONFIG)/.test(Buffer.from(buf).toString('latin1'));

/**
 * One OKGETPUBKEY sent RAW (no lib), every report it produced: the reply has
 * no length, so it ends when the bus has been quiet for `quietMs`. This is
 * the lib-independent view the ML-KEM / X-Wing and Ed25519 / X25519 claims are
 * checked against.
 */
async function rawPublicKey(device, signal, slot, field = 0, { quietMs = 500, timeoutMs = 8000 } = {}) {
  const since = device.mark(IFACE.VENDOR);
  device.sendVendor({ msg: okmsg.MSG.OKGETPUBKEY, slot, field });
  const deadline = Date.now() + timeoutMs;
  let seen = 0;
  let quietSince = Date.now();
  while (Date.now() < deadline) {
    await device.sleep(50, { signal });
    const n = device.reportsSince(IFACE.VENDOR, since).filter((r) => !isStatus(r)).length;
    if (n !== seen) { seen = n; quietSince = Date.now(); }
    else if (seen && Date.now() - quietSince >= quietMs) break;
  }
  const reports = device.reportsSince(IFACE.VENDOR, since)
    .filter((r) => !isStatus(r)).map((r) => Buffer.from(r).subarray(0, REPORT));
  return { reports: reports.length, data: Buffer.concat(reports) };
}

/** A lib stack on an UNLOCKED device, its session connected (version known). */
async function libUnlocked(device, signal, { restart = true } = {}) {
  if (restart) {
    await device.restart({ signal });
    await device.unlock(PINS.primary, { signal });
  } else {
    await device.ensureUnlocked(PINS.primary, { signal });
  }
  const lib = await composeLib(device);
  await lib.services.device.connect({ timeoutMs: 6000 });
  return lib;
}

describe('node-onlykey-lib Key Chain: generate, label, probe, wipe - real firmware', {
  state: 'initialized',
  requires: ['crypto'],
  negative: true,
  timeoutMs: 600000,
}, () => {
  /* What the first test made, for the ones after it to check against. */
  const made = {};

  it('config mode: the device makes six key types and the host loads three, each with its label',
    async ({ device, assert, signal, log }) => {
      /* Connected while unlocked: generateEccKey's Curve25519 path needs the version. */
      const lib = await libUnlocked(device, signal);
      try {
        const dev = lib.services.device;
        await device.enterConfigMode(PINS.primary, { signal });

        /* The empty slots are made empty here, not assumed from the fixture. */
        for (const slot of [EMPTY_ECC, EMPTY_RSA]) {
          const wiped = await dev.wipeKey(slot);
          log(`wipeKey ${slot}: ${JSON.stringify(wiped.response)}`);
          assert.match(wiped.response, /^Successfully wiped/,
            `the firmware did not wipe slot ${slot}: ${wiped.response}`);
        }

        for (const k of DEVICE_KEYS) {
          if (k.pqc) {
            const pub = Buffer.from(await dev.generateKey(k.slot, k.type, { label: k.label }));
            log(`generateKey ${k.kind} slot ${k.slot}: ${pub.length} bytes, ${hex(pub.subarray(0, 8))}…${hex(pub.subarray(-8))}`);
            assert.equal(pub.length, k.pqc,
              `generateKey returned ${pub.length} bytes for ${k.kind}; the key is ${k.pqc}`);
            assert.notEqual(hex(pub), '00'.repeat(k.pqc), `${k.kind}: generateKey returned all zeros`);
            made[k.slot] = pub;
          } else {
            const r = await dev.generateEccKey(k.slot, k.type, { ...k.use, label: k.label });
            log(`generateEccKey ${k.kind} slot ${k.slot}: ${JSON.stringify(r.response)}`);
            assert.match(String(r.response), /^Successfully set ECC Key/,
              `the firmware did not acknowledge generating ${k.kind}: ${r.response}`);
          }
        }

        for (const k of HOST_KEYS) {
          const key = await keychain.generate.hostKey(k.host, k.bits ? { bits: k.bits } : {});
          made[k.slot] = Buffer.from(key.publicKey);
          /* A TEST key: its secret is kept for the field-4 check in the host-key test. */
          if (k.host === 'ed25519') made.edSecret = Buffer.from(key.secret);
          const prepared = deviceKeys.prepareKey(key.material, { slot: k.slot, signature: true });
          assert.equal(prepared.slot, k.slot, `prepareKey moved slot ${k.slot} to ${prepared.slot}`);
          const r = await dev.loadKey(prepared.slot, { type: prepared.type, key: prepared.key }, { label: k.label });
          keychain.generate.wipe(key);
          log(`loadKey host ${k.host} slot ${k.slot}: ${JSON.stringify(r.response)}`);
          assert.match(String(r.response), /^Successfully set/,
            `the firmware did not take the host ${k.host} key: ${r.response}`);
        }
        assert.control('every generation and load in config mode was acknowledged by the device', true);
      } finally {
        await lib.destroy();
      }
    });

  it('probeKeySlot in config mode REJECTS as locked/config mode - a full slot and an empty one alike, never "empty"',
    async ({ device, assert, log }) => {
      /* Still in the first test's config mode: no restart has happened. */
      const lib = await composeLib(device);
      try {
        const dev = lib.services.device;
        /*
         * CONTROL: the device is alive and answering vendor messages in this
         * very config mode - OKSETSLOT is one of the messages it keeps.
         * Without this, a dead emulator would "prove" the silence.
         */
        const relabel = await dev.setKeyLabel(EMPTY_ECC, '');
        log(`setKeyLabel ${EMPTY_ECC} '' in config mode: ${JSON.stringify(relabel.response)}`);
        assert.control('the device answers OKSETSLOT in config mode', /^Success/i.test(relabel.response));

        for (const slot of [109, EMPTY_ECC]) {
          let result = null;
          let err = null;
          try { result = await dev.probeKeySlot(slot); } catch (e) { err = e; }
          log(`probe ${slot} in config mode: ${err ? err.message.slice(0, 90) : JSON.stringify(result)}`);
          assert.absent(!result,
            `probeKeySlot(${slot}) ANSWERED in config mode (${JSON.stringify(result && result.kind)}) - ` +
            'the firmware drops OKGETPUBKEY there, so either it no longer does or the lib read something else as the key');
          assert.match(String(err && err.message), CONFIG_MODE_REFUSAL,
            `the lib rejected, but not with its locked/config-mode message: ${err && err.message}`);
        }
      } finally {
        await lib.destroy();
      }
    });

  it('after the restart: probeKeySlot names every kind WITHOUT a hint, and the public keys are the real ones',
    async ({ device, assert, signal, log }) => {
      const lib = await libUnlocked(device, signal);
      try {
        const dev = lib.services.device;
        const probed = {};
        /*
         * X-Wing BEFORE ML-KEM: if the firmware ever stopped clearing its buffer
         * between replies, ML-KEM's tail would carry X-Wing bytes from the
         * previous reply rather than its own - and the raw check below sees it.
         */
        for (const k of [DEVICE_KEYS[5], DEVICE_KEYS[4], ...DEVICE_KEYS.slice(0, 4)]) {
          probed[k.slot] = await dev.probeKeySlot(k.slot);
          const p = probed[k.slot];
          log(`probe ${k.slot}: ${p.kind}, ${p.publicKey ? p.publicKey.length : 0} bytes`);
        }

        /* --- ML-KEM-768 vs X-Wing: the lib's tail rule, and the raw bytes under it. */
        for (const k of DEVICE_KEYS.filter((d) => d.pqc)) {
          const raw = await rawPublicKey(device, signal, k.slot);
          const last = raw.data.subarray(18 * REPORT, 19 * REPORT);
          log(`RAW ${k.kind} slot ${k.slot}: ${raw.reports} reports; last report ${hex(last)}`);
          log(`    previous report's second half ${hex(raw.data.subarray(MLKEM_BYTES - 64, MLKEM_BYTES - 32))}`);
          assert.equal(raw.reports, 19, `the firmware answered ${k.kind} in ${raw.reports} reports, the lib expects 19`);
          assert.bytes(raw.data.subarray(0, k.pqc), made[k.slot],
            `the ${k.kind} key read RAW after the restart is not the key generateKey returned`);
          const tail = raw.data.subarray(MLKEM_BYTES, XWING_BYTES);
          if (k.kind === 'mlkem768') {
            /* The firmware premise itself: the 32 bytes past an ML-KEM key are the previous report's tail. */
            assert.bytes(tail, raw.data.subarray(MLKEM_BYTES - 64, MLKEM_BYTES - 32),
              'FIRMWARE vs LIB: the 32 bytes after an ML-KEM key are NOT the previous report\'s second half - ' +
              'the lib\'s untagged ML-KEM/X-Wing rule (okcore.cpp:2568-2573) does not hold');
          } else {
            assert.bytes(tail, made[k.slot].subarray(MLKEM_BYTES),
              'the last 32 bytes of the X-Wing answer are not its X25519 key');
          }
          assert.equal(probed[k.slot].kind, k.kind,
            `LIB: probeKeySlot(${k.slot}) with no hint said ${probed[k.slot].kind}; the slot holds ${k.kind}`);
          assert.bytes(probed[k.slot].publicKey, made[k.slot],
            `LIB: probeKeySlot's ${k.kind} public key is not the generated one`);
        }

        /* --- P-256 / secp256k1: the lib's curve check, and node:crypto's. */
        for (const [slot, curve] of [[110, 'prime256v1'], [111, 'secp256k1']]) {
          const p = probed[slot];
          let loaded = null;
          try { loaded = crypto.ECDH.convertKey(Buffer.concat([Buffer.from([4]), p.publicKey]), curve); } catch (e) { loaded = e; }
          assert.ok(loaded && !(loaded instanceof Error),
            `node:crypto does not load slot ${slot}'s ${curve} point: ${loaded && loaded.message}`);
          assert.equal(p.kind, DEVICE_KEYS.find((d) => d.slot === slot).kind,
            `LIB: probeKeySlot(${slot}) said ${p.kind}`);
        }

        /*
         * --- Ed25519 vs X25519: the field-4 answer, raw. The lib's rule needs
         * exactly one thing of it - an Ed25519 slot answers a DIFFERENT key
         * under field 4, an X25519 slot the SAME one. What the different key
         * IS (not the birational map of the Ed25519 key - see the host-key
         * test, which knows the secret) does not enter the rule.
         */
        const ed = probed[109];
        const edConverted = await rawPublicKey(device, signal, 109, CURVE25519_FIELD);
        log(`RAW field 4 on Ed25519 slot 109: ${hex(edConverted.data.subarray(0, 32))} vs field 0 ${hex(ed.publicKey)}`);
        assert.equal(edConverted.reports, 1, `field 4 on an Ed25519 slot answered ${edConverted.reports} reports`);
        assert.notEqual(hex(edConverted.data.subarray(0, 32)), hex(ed.publicKey),
          'FIRMWARE vs LIB: field 4 on an Ed25519 slot answers the SAME key as field 0 - the lib would call it X25519');
        const xs = probed[112];
        const xConverted = await rawPublicKey(device, signal, 112, CURVE25519_FIELD);
        log(`RAW field 4 on X25519 slot 112: ${hex(xConverted.data.subarray(0, 32))} vs field 0 ${hex(xs.publicKey)}`);
        assert.bytes(xConverted.data.subarray(0, 32), xs.publicKey,
          'FIRMWARE vs LIB: field 4 on an X25519 slot does not answer the same key - the lib\'s rule cannot tell X25519 from Ed25519');
        assert.equal(ed.kind, 'ed25519', `LIB: probeKeySlot(109) said ${ed.kind}; the slot holds Ed25519`);
        assert.equal(xs.kind, 'x25519', `LIB: probeKeySlot(112) said ${xs.kind}; the slot holds X25519`);

        /* --- empty, and RSA's bits. */
        const emptyEcc = await dev.probeKeySlot(EMPTY_ECC);
        const emptyRsa = await dev.probeKeySlot(EMPTY_RSA);
        log(`probe ${EMPTY_ECC}: ${JSON.stringify(emptyEcc)}; probe RSA${EMPTY_RSA}: ${JSON.stringify(emptyRsa)}`);
        assert.equal(emptyEcc.kind, 'empty', `LIB: an empty ECC slot probed as ${emptyEcc.kind}`);
        assert.equal(emptyRsa.kind, 'empty', `LIB: an empty RSA slot probed as ${emptyRsa.kind}`);
        assert.control('the same probe that reports "empty" reports keys where there are keys',
          Object.values(probed).every((p) => p.kind !== 'empty'));
      } finally {
        await lib.destroy();
      }
    });

  it('host keys: hostKey -> prepareKey -> loadKey, and the probe returns the host\'s own public key',
    async ({ device, assert, signal, log }) => {
      const lib = await libUnlocked(device, signal, { restart: false });
      try {
        const dev = lib.services.device;
        for (const k of HOST_KEYS) {
          const p = await dev.probeKeySlot(k.slot);
          log(`probe ${k.slot}: ${p.kind}${p.bits ? ` ${p.bits} bits` : ''}, ${hex(Buffer.from(p.publicKey).subarray(0, 8))}…`);
          assert.equal(p.kind, k.kind, `LIB: probeKeySlot(${k.slot}) said ${p.kind}; the host loaded ${k.kind}`);
          if (k.bits) assert.equal(p.bits, k.bits, `LIB: the RSA slot probed as ${p.bits} bits; the key is ${k.bits}`);
          assert.bytes(p.publicKey, made[k.slot],
            `slot ${k.slot}'s public key is not the one the host computed - the load or the probe is wrong`);
        }
        assert.control('each host key was found by its own public key', true);

        /*
         * WHAT FIELD 4 IS on an Ed25519 slot, measured where the secret is
         * known. NOT the birational image of the Ed25519 key (what libsodium's
         * crypto_sign_ed25519_pk_to_curve25519 gives, and what a reader of
         * "the Curve25519 conversion" would assume): okcrypto_compute_pubkey
         * switches the type to CURVE25519 (okcrypto.cpp:724-726), reverses the
         * 32-byte SEED in place (swap_buffer) and hands it to
         * Curve25519::eval - the raw RFC 7748 function, which does not clamp
         * and reads bits 254..0. So the answer is u(s * B) with s = the seed
         * read big-endian, bit 255 dropped. Measured 2026-10-01 on the 3.1.0
         * emulator: that matched, the birational map and both clamped forms
         * did not. The lib's probe rule only needs it to DIFFER from field 0,
         * so this pins a fact for any future caller of field 4 rather than a
         * lib assumption.
         */
        const f4 = (await rawPublicKey(device, signal, 105, CURVE25519_FIELD)).data.subarray(0, 32);
        const candidates = {
          birational: Buffer.from(ed25519.utils.toMontgomery(made[105])),
          seedAsScalar: Buffer.from(x25519.getPublicKey(made.edSecret)),
          reversedSeedAsScalar: Buffer.from(x25519.getPublicKey(Buffer.from(made.edSecret).reverse())),
          unclampedSeedBE255: unclampedBase(BigInt(`0x${hex(made.edSecret)}`) & ((1n << 255n) - 1n)),
        };
        made.edSecret.fill(0);
        log(`RAW field 4 on host Ed25519 slot 105: ${hex(f4)}`);
        for (const [name, v] of Object.entries(candidates)) log(`    ${name.padEnd(22)} ${hex(v)}${v.equals(f4) ? '  <== match' : ''}`);
        assert.bytes(f4, candidates.unclampedSeedBE255,
          'field 4 on an Ed25519 slot is no longer u(unclamped big-endian seed * B) - the firmware changed its conversion');
        assert.notEqual(hex(f4), hex(candidates.birational),
          'field 4 on an Ed25519 slot is now the birational image of the Ed25519 key - update the note above');
      } finally {
        await lib.destroy();
      }
    });

  it('readKeyLabels shows every label generation and loading wrote; setKeyLabel(slot, \'\') blanks one and keeps the key',
    async ({ device, assert, signal, log }) => {
      const lib = await libUnlocked(device, signal, { restart: false });
      try {
        const dev = lib.services.device;
        const before = await dev.readKeyLabels();
        for (const k of [...DEVICE_KEYS, ...HOST_KEYS]) {
          assert.equal(labelOf(before, k.slot), k.label,
            `slot ${k.slot}'s label reads ${JSON.stringify(labelOf(before, k.slot))}; it was written as ${k.label}`);
        }
        assert.control('the labels written in config mode read back', labelOf(before, RENAMED) === 'sig:l8p256');

        const r = await dev.setKeyLabel(RENAMED, '');
        log(`setKeyLabel ${RENAMED} '': ${JSON.stringify(r.response)}`);
        const after = await dev.readKeyLabels();
        log(`labels after: ${JSON.stringify(after.keys.filter((k) => k.slot >= 105 && k.slot <= 116).map((k) => [k.slot, k.label]))}`);
        assert.absent(!labelOf(after, RENAMED),
          `slot ${RENAMED}'s label survived setKeyLabel(''): ${JSON.stringify(labelOf(after, RENAMED))}`);
        assert.equal(labelOf(after, 111), 'sig:l8k1', 'blanking one label touched another');
        const still = await dev.probeKeySlot(RENAMED);
        assert.equal(still.kind, 'p256', `renaming slot ${RENAMED} changed what it holds: ${still.kind}`);
      } finally {
        await lib.destroy();
      }
    });

  it('wipeKey: the slot probes empty afterwards and its label is blank, its neighbours untouched',
    async ({ device, assert, signal, log }) => {
      const lib = await libUnlocked(device, signal);
      try {
        const dev = lib.services.device;
        await device.enterConfigMode(PINS.primary, { signal });
        const w = await dev.wipeKey(WIPED);
        log(`wipeKey ${WIPED}: ${JSON.stringify(w)}`);
        assert.match(w.response, /^Successfully wiped ECC Key/, `the firmware did not wipe slot ${WIPED}: ${w.response}`);

        await device.restart({ signal });
        await device.unlock(PINS.primary, { signal });
        const neighbour = await dev.probeKeySlot(111);
        assert.control('the probe still sees the secp256k1 key next door', neighbour.kind === 'secp256k1');
        const p = await dev.probeKeySlot(WIPED);
        const labels = await dev.readKeyLabels();
        log(`probe ${WIPED} after wipe: ${JSON.stringify(p)}; label ${JSON.stringify(labelOf(labels, WIPED))}`);
        assert.equal(p.kind, 'empty', `a wiped slot probed as ${p.kind}`);
        assert.absent(!labelOf(labels, WIPED),
          `the wiped slot still names a key: ${JSON.stringify(labelOf(labels, WIPED))}`);
        assert.equal(labelOf(labels, 112), 'age:l8x', 'wiping one slot touched another slot\'s label');
      } finally {
        await lib.destroy();
      }
    });
});
