/*
 * pqc.js - driving age-plugin-onlykey's on-device key operations.
 *
 * Every PQC operation the CLI asks for is gated behind a three-button challenge
 * the device makes up on the spot, and the device's only way of telling a human
 * which buttons to press is its own LEDs. A test has no eyes, so it computes the
 * digits instead - which it can, because the challenge is a pure function of a
 * packet whose contents are known before it is sent.
 *
 *   ecc_priv_flash() (okcore.cpp:5264) sees an all-0xFF key body, recognises it
 *   as "generate on device", and - for ML-KEM and X-Wing only - primes a
 *   challenge over a 9-byte packet: [keytype, 0xFF x 8]. done_process_packets()
 *   SHA256s that packet and takes bytes 0, 15 and 31 mod 6, plus one.
 *
 * So the digits are knowable, and this file knows them. What is NOT knowable
 * ahead of time is WHEN to press: priming runs synchronously inside the
 * firmware's HID report handler, blocking loop() for the best part of a second,
 * and a press that arrives during that window is not queued - it is dropped.
 *
 * The old kit solved that by watching the CLI's own "Press OnlyKey button"
 * line - which fires before the device has even been asked - and then waiting a
 * fixed margin comfortably past the longest priming it had measured. It did
 * that because the device's own "Encrypted Buffer" print, which is the exact
 * end of the blocking window, arrives over DEBUG-serial, and on a real key under
 * load that channel drops output.
 *
 * Here it does not. The debug console is an in-process event, not a USB
 * interface being polled, so this waits for the device to say it has finished
 * rather than guessing how long finishing takes. That is the whole reason to
 * have an emulator: the instrument the hardware kit wanted was there all along,
 * it just could not be trusted through a cable.
 */
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { PINS } = require('./config');
const { anySignal, sleep } = require('./device/waits');
const { byteprintAfter } = require('./device/logbuf');
const cli = require('./cli');

/* okcore.h's KEYTYPE_*, mirrored in python-onlykey's age_plugin/__init__.py. */
const KEYTYPE = { MLKEM768: 5, XWING: 6 };

/* ct_M(1088) || ct_X(32), the age mlkem768x25519 stanza's argument. */
const XWING_CT_SIZE = 1120;

/* An all-0xFF key body is what tells the firmware to generate rather than
 * store - the `gen_key == 2040` trigger in ecc_priv_flash(). */
const GENERATE_TRIGGER = Buffer.alloc(8, 0xff);

/* The end of the blocking window, printed by done_process_packets()
 * (okcore.cpp:7560) once the challenge is primed and the response encrypted. */
const PRIMED = /Encrypted Buffer/g;

/**
 * The three buttons the device is about to ask for, from the packet it is
 * about to ask about.
 *
 * done_process_packets(), okcore.cpp ~7533: SHA256 over the whole accumulated
 * packet, then temp[0], temp[15] and temp[31], each mod 6 plus 1. The DUO takes
 * mod 3, and this is not a DUO - if that ever changes, the digits go wrong in a
 * way that looks like the device ignoring presses.
 *
 * @param {Buffer|Uint8Array} packet whatever ended up in packet_buffer
 * @returns {number[]} three buttons, 1..6
 */
function challengeDigitsFor(packet) {
  const hash = crypto.createHash('sha256').update(Buffer.from(packet)).digest();
  return [hash[0] % 6 + 1, hash[15] % 6 + 1, hash[31] % 6 + 1];
}

/**
 * Keygen's digits. ecc_priv_flash() primes over a 9-byte packet it builds
 * itself: the key type, then the eight 0xFF trigger bytes.
 * @param {number} keytype KEYTYPE.*
 */
function challengeDigits(keytype) {
  return challengeDigitsFor(Buffer.concat([Buffer.from([keytype]), GENERATE_TRIGGER]));
}

/**
 * Decapsulation's digits, which are a function of the CIPHERTEXT.
 *
 * okcrypto_xwing_decaps() calls process_packets() once per incoming report
 * while CRYPTO_AUTH is clear, and process_packets() only reaches
 * done_process_packets() on the last chunk - so the packet hashed is the whole
 * 1120-byte X-Wing ciphertext, and the digits differ for every file decrypted.
 */
function challengeDigitsForCiphertext(ciphertext) {
  if (ciphertext.length !== XWING_CT_SIZE) {
    throw new Error(`X-Wing ciphertext must be ${XWING_CT_SIZE} bytes, got ${ciphertext.length}`);
  }
  return challengeDigitsFor(ciphertext);
}

/**
 * The X-Wing ciphertext out of an age file.
 *
 * age writes stanza ARGUMENTS on one line - only the body that follows is
 * wrapped - so the base64 is never split.
 */
function xwingCiphertextOf(ageFile) {
  const text = fs.readFileSync(ageFile, 'utf8');
  const m = text.match(/^-> mlkem768x25519 (\S+)$/m);
  if (!m) {
    throw new Error(`no mlkem768x25519 stanza in ${ageFile} - was it encrypted to an X-Wing recipient?`);
  }
  /* age uses unpadded base64; Buffer does not mind. */
  return Buffer.from(m[1], 'base64');
}

/**
 * Put the device where OKSETPRIV will be accepted, from wherever it is.
 *
 * Restart first, deliberately. Config-mode entry begins with a long press that
 * only means "config mode" on an unlocked device, and the unlock that precedes
 * it only means "unlock" on a locked one - so entering this sequence from an
 * unknown state feeds PIN digits to a device that reads them as slot presses.
 * A reboot is the cheapest way to know which state we are in, and it also
 * leaves config mode, which has no other exit.
 */
async function readyForKeygen(device, opts = {}) {
  const { pin = PINS.primary } = opts;
  await device.restart(opts);
  await device.unlock(pin, opts);
  await device.enterConfigMode(pin, opts);
}

/* done_process_packets() dumps the packet it is about to hash, right before it
 * computes the challenge from it. */
const RECEIVED = /Received Message/g;

/**
 * The packet the device just hashed, read off its own console.
 *
 * Everything else here PREDICTS the challenge, which works when the caller
 * chose the payload. It does not work when a browser page did: an openpgp
 * signature is over subpackets the page assembles, so the digest is not
 * knowable from outside without reimplementing what is being tested.
 *
 * The device prints it. done_process_packets() does `Serial.println("Received
 * Message"); byteprint(packet_buffer, packet_buffer_offset);` immediately
 * before deriving the digits from those exact bytes - so reading them is both
 * simpler and more honest than recomputing them.
 *
 * The dump format itself - and the unpadded-hex trap in it - belongs to
 * byteprint(), not to this challenge, so it lives in logbuf.js where every
 * caller reads the same one. 02-cli/08-lib-agent-ssh is the other one.
 */
function packetFromConsole(device) {
  return byteprintAfter(device.log.text, 'Received Message');
}

/**
 * Answer a challenge whose payload this process did not choose.
 *
 * Waits for the device to announce the packet, reads it, derives the digits
 * from what was actually hashed, and presses. That covers the browser pages,
 * where the payload is assembled inside the page.
 *
 * Console-based, so emulator-only in practice - which is no constraint, since
 * everything that needs it is emulator-only anyway.
 */
async function confirmFromConsole(device, work, opts = {}) {
  const { primeMs = 60000, signal } = opts;
  let seen = device.log.count(RECEIVED);

  /*
   * EVERY challenge the work raises, not just the first.
   *
   * A composite decryption asks the device twice - registerCompositeHooks wires
   * both hooks.ecdh and hooks.mlkemDecaps, and openpgp needs both halves - so
   * each raises its own confirmation. Answering only the first leaves the
   * second unanswered, and the page then reports "Composite operation abandoned
   * by the device" for an operation that was half done: one CTAP1_SUCCESS in
   * its console, then an abandonment.
   *
   * The watcher is stopped by an AbortController rather than by a flag, and
   * that is the whole difference between this working and not. A flag is only
   * read between iterations, so the wait outstanding when the work finished sat
   * in device.pending until its own timeout - three of them by the end of a
   * run, which is what the inactivity watchdog then reported instead of the
   * real problem. Aborting cancels the wait itself, so nothing outlives the
   * operation it was watching.
   */
  const stop = new AbortController();
  const watching = anySignal([signal, stop.signal].filter(Boolean));

  const running = work().finally(() => stop.abort());

  (async () => {
    for (;;) {
      await device.log.waitForCount(RECEIVED, seen + 1, {
        timeoutMs: primeMs, signal: watching, pending: device.pending,
      });
      seen = device.log.count(RECEIVED);

      /* The dump follows the line; give it the moment it takes to arrive. */
      await sleep(250, { signal: watching });
      const packet = packetFromConsole(device);
      if (packet) device.pressLine(challengeDigitsFor(packet));
    }
  })().catch(() => { /* aborted, or the work itself will report why */ });

  return running;
}

/**
 * Answer the button challenge raised by something this process is doing.
 *
 * The same arrangement as runWithConfirm(), for callers whose operation is a
 * promise rather than a child process - the web app's library, whose
 * composite_sign() and composite_decrypt() prime and poll from inside JS.
 *
 * The wait is armed BEFORE the work starts, because the device can prime faster
 * than the caller gets to its next await.
 *
 * @param {object} device
 * @param {number[]} digits from challengeDigitsFor()
 * @param {function(): Promise} work
 */
async function confirmWhilst(device, digits, work, opts = {}) {
  const { primeMs = 30000, signal } = opts;
  const before = device.log.count(PRIMED);

  const primed = device.log.waitForCount(PRIMED, before + 1, {
    timeoutMs: primeMs,
    signal,
    pending: device.pending,
  });

  const running = work();

  /* If priming never happens the operation itself has the explanation, so let
   * it finish and report rather than failing here on "no press window". */
  primed.then(() => device.pressLine(digits)).catch(() => {});

  return running;
}

/**
 * Run a venv binary that will trigger a keygen challenge, and answer it.
 *
 * The wait is armed BEFORE the process starts, because the device can prime the
 * challenge faster than a python interpreter takes to import its modules, and a
 * wait armed afterwards would sit through the whole thing having already missed
 * what it was waiting for.
 *
 * @param {object} device
 * @param {string} name  a venv binary, e.g. 'age-plugin-onlykey'
 * @param {string[]} argv
 * @param {object} [opts] {digits, timeoutMs, signal, primeMs, env}
 * @returns {Promise<{code:number, stdout:string, stderr:string, timedOut:boolean}>}
 */
async function runWithConfirm(device, name, argv, opts = {}) {
  const {
    digits = challengeDigits(KEYTYPE.XWING),
    timeoutMs = 60000,
    primeMs = 30000,
    signal,
    env,
  } = opts;

  const before = device.log.count(PRIMED);

  const primed = device.log.waitForCount(PRIMED, before + 1, {
    timeoutMs: primeMs,
    signal,
    pending: device.pending,
  });

  const running = cli.run(name, argv, { timeoutMs, signal, env });

  /*
   * If priming never happens the CLI is the one with the explanation - it will
   * have said what it could not do - so let it finish and report rather than
   * failing here on a timeout that only says "no press window".
   */
  try {
    await primed;
  } catch {
    return running;
  }

  /* One write, not three. The firmware paces the replay itself, which is what
   * makes this the reliable way to send a sequence - there is no host-side
   * delay between digits to get wrong. */
  device.pressLine(digits);

  return running;
}

/**
 * The whole thing: get into config mode, run the command, answer the challenge.
 *
 * Returns the CLI result. It never throws on a non-zero exit - several of these
 * tests are about the CLI failing correctly - so the caller asserts on `code`.
 */
async function generate(device, argv, opts = {}) {
  await readyForKeygen(device, opts);
  return runWithConfirm(device, 'age-plugin-onlykey', argv, opts);
}

/* age spawns `age-plugin-onlykey` by name, so the venv has to be on PATH. */
function agePath() {
  return { PATH: `${cli.VENV_BIN}:${process.env.PATH}` };
}

/** `age -r recipient -o out in`. Encryption is host-only - no device, no press. */
function encrypt(recipient, input, output, opts = {}) {
  return cli.run('age', ['-r', recipient, '-o', output, input], {
    timeoutMs: 30000, env: agePath(), ...opts,
  });
}

/**
 * `age -d -i identity -o out in`, answering the decapsulation challenge.
 *
 * Two things make this unlike a keygen, and both simplify it. OKDECRYPT needs
 * the device unlocked and nothing more - there is no config mode, so no long
 * press and no second unlock. And the digits come from the ciphertext, so they
 * are different for every file and are read out of the age file itself.
 *
 * What does NOT simplify: age runs the plugin as its own child and does not
 * relay its stderr, so the CLI's "Press OnlyKey button" line never reaches
 * anybody. The device's own print is not just the better signal here, it is the
 * only one - which is why the old kit had to fall back to pressing blind when
 * that print went missing under load on hardware.
 */
async function decrypt(device, { ageFile, identityFile, output }, opts = {}) {
  const { pin = PINS.primary } = opts;

  /* A known state: the unlock below is only an unlock on a locked device. */
  await device.restart(opts);
  await device.unlock(pin, opts);

  return runWithConfirm(device, 'age',
    ['-d', '-i', identityFile, '-o', output, ageFile], {
      ...opts,
      digits: challengeDigitsForCiphertext(xwingCiphertextOf(ageFile)),
      env: agePath(),
    });
}

/**
 * The identity and recipient a successful --generate prints.
 *
 * They come out on different streams, which is not an accident: the identity is
 * the only thing on stdout, so `age-plugin-onlykey --generate > identity.txt`
 * writes a usable identity file and everything else is commentary on stderr.
 *
 * @returns {{identity: string|null, recipient: string|null}}
 */
function parseGenerated({ stdout = '', stderr = '' } = {}) {
  const identity = stdout.match(/^AGE-PLUGIN-ONLYKEY-1[A-Z0-9]+$/m);
  const recipient = `${stdout}\n${stderr}`.match(/age1onlykey1[a-z0-9]+/);
  return {
    identity: identity ? identity[0] : null,
    recipient: recipient ? recipient[0] : null,
  };
}

/**
 * A composite PGP-PQC key made the way the web app makes one - AND its armored
 * private key, which the web app's generateCompositeKey() does not return.
 *
 * Why the kit needs the armored key at all: `onlykey-cli loadpqc` is the only
 * way to put a composite key on the device, and it takes an ARMORED KEY FILE
 * and nothing else. python-onlykey deleted `setpqc`, the raw-blob route, in
 * 4b452ef ("loadpqc is the only way to load a composite PQC key"), because the
 * browser generator that printed setpqc lines is gone.
 *
 * The generateKey() call mirrors composite_pgp.js's generateCompositeKey()
 * line for line (hooks cleared, type 'pqc', one subkey, v6), and the blob is
 * packed with the web app's OWN packBlob(). That keeps the cross-client check
 * the load tests exist for: the CLI parses the armored file through its bridge
 * and derives the blob it sends, the kit derives the blob the web app's way,
 * and the device's signature only verifies if the two agree.
 *
 * @param {object} openpgp    webenv.openpgp()
 * @param {object} composite  webenv.loadPlain('composite_pgp.js')
 * @returns {Promise<{blob: Buffer, armoredPrivateKey: string, armoredPublicKey: string}>}
 */
async function compositeKey(openpgp, composite, { userId } = {}) {
  openpgp.clearHardwareHooks();
  const { privateKey, publicKey } = await openpgp.generateKey({
    type: 'pqc',
    userIDs: [userId || { name: 'Kit', email: 'kit@example.com' }],
    subkeys: [{}],
    format: 'object',
    config: { v6Keys: true },
  });
  const primary = privateKey.keyPacket.privateParams;
  const subkey = privateKey.subkeys[0].keyPacket.privateParams;
  const blob = Buffer.from(composite.packBlob(
    primary.eccSecretKey, primary.mldsaSeed, subkey.eccSecretKey, subkey.mlkemSeed));
  return {
    blob,
    armoredPrivateKey: await privateKey.armor(),
    armoredPublicKey: await publicKey.armor(),
  };
}

/**
 * Hand `fn` the path of a file holding an armored private key, and delete it
 * afterwards whatever happened. It is PRIVATE KEY MATERIAL, so: a fresh
 * directory of its own, mode 0600, and removal in `finally` - a failing test
 * must not leave a key behind in /tmp.
 */
async function withCompositeKeyFile(armoredPrivateKey, fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'okt-pqc-'));
  const file = path.join(dir, 'composite.asc');
  try {
    fs.writeFileSync(file, armoredPrivateKey, { mode: 0o600 });
    return await fn(file);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

/**
 * Load a composite key onto the device the one way python-onlykey supports:
 * `onlykey-cli loadpqc <file> PQC1`. The device must already be in config
 * mode (OKSETPRIV is refused outside it). Slots are PQC1-PQC4; the CLI refuses
 * RSA names for them.
 */
function loadWithCli(armoredPrivateKey, { slot = 'PQC1', ...opts } = {}) {
  return withCompositeKeyFile(armoredPrivateKey, (file) =>
    cli.run('onlykey-cli', ['loadpqc', file, slot], opts));
}

module.exports = {
  KEYTYPE,
  GENERATE_TRIGGER,
  compositeKey,
  withCompositeKeyFile,
  loadWithCli,
  XWING_CT_SIZE,
  challengeDigitsFor,
  challengeDigits,
  challengeDigitsForCiphertext,
  confirmWhilst,
  confirmFromConsole,
  packetFromConsole,
  xwingCiphertextOf,
  readyForKeygen,
  runWithConfirm,
  generate,
  encrypt,
  decrypt,
  parseGenerated,
};
