/*
 * TC-13, the GPG half: `onlykey-gpg init`, and the identity it leaves behind.
 *
 * DO NOT READ THIS AS THE SSH FILE WITH A DIFFERENT BINARY. lib-agent's
 * pubkey() branches on the identity's proto, and GPG takes the other side of
 * every branch that matters:
 *
 *                        08-lib-agent-ssh        this file
 *   hashed               user@host               the WHOLE identity string,
 *                                                `gpg://` + the user id
 *   pubkey slot          132                     132, but reached via
 *                                                get_sk_dk() rather than
 *                                                unconditionally
 *   keys derived         one (ed25519)           TWO - ed25519 to sign and
 *                                                curve25519 to decrypt
 *   signs anything       no                      yes, twice
 *   button challenge     none                    one per signature
 *
 * That last row is the real difference. Exporting a public key is a read;
 * `init` builds an OpenPGP key by SIGNING - a self-certification over the
 * primary, then a binding signature over the encryption subkey - and each
 * signature is gated on the three-button confirmation. So this is the first
 * lib-agent test that needs lib/pqc.js at all, and it needs it twice in one
 * command.
 *
 * The signature also takes a different firmware path from the pubkey export:
 * okcrypto_sign() dispatches slot 201, not 132, into okcrypto_ecdsa_eddsa(),
 * which is where `buffer[5] == 201` maps back to okcrypto_derive_key(1, ...).
 * lib-agent picks 201/202/203 by curve. Slot 132 is the OLD number for this and
 * is still what the pubkey call uses, which is worth knowing before reading
 * either as a typo.
 *
 * WHAT IS CHECKED, beyond `init` exiting 0:
 *
 *   - The digits lib-agent PRINTED for the user match the ones derived from the
 *     packet the device says it received. Those are computed on opposite sides
 *     of a multi-report send - lib-agent from sha256(blob+data) before sending,
 *     the device from what it reassembled - so agreeing means the whole
 *     send_large_message2() framing arrived intact. A dropped chunk shows up
 *     here as two different triples rather than as a confirmation that is
 *     mysteriously refused.
 *   - The key GnuPG ends up holding is the key THIS KIT derives for the same
 *     identity, asked for over the in-process vendor interface. Same three-way
 *     arrangement as the SSH file: without it, `init` succeeding only says
 *     lib-agent and gpg agreed with each other about whatever came back.
 *   - The homedir is wired to the device rather than to a software key -
 *     run-agent.sh naming the slots, gpg.conf pointing gpg at it.
 *
 * `--homedir` IS PASSED EXPLICITLY, ALWAYS. Without it run_init() defaults to
 * `~/.gnupg/onlykey`, which on a developer's machine is their own keyring. It
 * also refuses to reuse a directory that exists, so a retry needs a fresh path
 * rather than a cleaned one - the last test pins that refusal, because it is
 * the thing most likely to be mistaken for a device failure on a second run.
 */
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { describe, it } = require('../../lib/harness');
const { IFACE, okmsg } = require('../../lib/device');
const { PINS } = require('../../lib/config');
const cli = require('../../lib/cli');
const pqc = require('../../lib/pqc');

const PRIMED = /Encrypted Buffer/g;

/* okcore.h. 132 is what the pubkey export asks for; the signature arrives as
 * 201, which okcrypto_ecdsa_eddsa() maps back onto the same derivation. */
const RESERVED_KEY_DERIVATION = 132;
const KEYTYPE_ED25519 = 1;
const KEYTYPE_CURVE25519 = 4;

/* OpenPGP algorithm ids, RFC 4880 §9.1 plus the EdDSA extension. */
const ALGO_EDDSA = 22;
const ALGO_ECDH = 18;

const USER_ID = 'OKT Test <okt@example.com>';

/*
 * What lib-agent hashes. gpg/client.py's create_identity() builds
 * Identity('gpg://') and then sets identity_dict['host'] to the user id, so
 * identity_to_string() is exactly this - and pubkey() takes to_bytes() of it
 * whole, unlike the ssh branch which picks two fields out.
 */
const IDENTITY_STRING = `gpg://${USER_ID}`;

const identityHash = () => crypto.createHash('sha256').update(IDENTITY_STRING, 'ascii').digest();

/*
 * The venv on PATH, which `init` genuinely needs and the other section-2 files
 * do not. Everything else here is run by absolute path deliberately, so that
 * "which onlykey-cli answered" has one answer - but run_init() calls
 * util.which('onlykey-gpg-agent') and BAKES the result into run-agent.sh, so
 * without this it dies with `Cannot find 'onlykey-gpg-agent' in $PATH` before
 * touching the device. It is also why the resulting homedir is only as portable
 * as the venv it was created against.
 */
const VENV_PATH = { PATH: `${cli.VENV_BIN}:${process.env.PATH}` };

/**
 * Walk OpenPGP packets. RFC 4880 §4.2, both header formats.
 *
 * Hand-rolled rather than reached for from a library, for the same reason the
 * rest of this kit is: an oracle that agrees with the thing it is checking is
 * not an oracle. gpg wrote these bytes; something that is not gpg has to read
 * them. It is thirty lines because only the shapes gpg actually emits here are
 * handled - no partial body lengths, no indeterminate lengths.
 */
function packets(buf) {
  const out = [];
  let i = 0;
  while (i < buf.length) {
    const header = buf[i++];
    if (!(header & 0x80)) throw new Error(`not a packet header at ${i - 1}: 0x${header.toString(16)}`);

    let tag;
    let len;
    if (header & 0x40) {                                  // new format
      tag = header & 0x3F;
      const first = buf[i++];
      if (first < 192) len = first;
      else if (first < 224) len = ((first - 192) << 8) + buf[i++] + 192;
      else if (first === 255) { len = buf.readUInt32BE(i); i += 4; }
      else throw new Error('partial body lengths are not handled');
    } else {                                              // old format
      tag = (header >> 2) & 0x0F;
      const type = header & 0x03;
      if (type === 0) len = buf[i++];
      else if (type === 1) { len = buf.readUInt16BE(i); i += 2; }
      else if (type === 2) { len = buf.readUInt32BE(i); i += 4; }
      else throw new Error('indeterminate lengths are not handled');
    }

    out.push({ tag, body: buf.subarray(i, i + len) });
    i += len;
  }
  return out;
}

/**
 * The bytes out of an ASCII-armored block.
 *
 * The export is asked for armored rather than binary for a mundane reason that
 * costs a run to find: lib/cli.js runs everything through execFile with
 * `encoding: 'utf8'`, so binary stdout is UTF-8 decoded on the way out and the
 * bytes cannot be recovered from the string afterwards - latin1 does not undo
 * it. Armor is ASCII by construction, so it survives, and `gpg --export
 * --armor` is what a person would run anyway.
 *
 * The trailing `=xxxx` line is a CRC-24 over the data, which is dropped rather
 * than checked: a bad dearmor fails the packet walk on the next line anyway,
 * and with a better message.
 */
function dearmor(text) {
  const lines = text.split('\n');
  const start = lines.findIndex((l) => l.startsWith('-----BEGIN PGP'));
  const end = lines.findIndex((l) => l.startsWith('-----END PGP'));
  if (start === -1 || end === -1) {
    throw new Error(`no armored block in ${JSON.stringify(text.slice(0, 120))}`);
  }

  const body = lines.slice(start + 1, end)
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('=') && !l.includes(': '));   // blank, CRC, armor headers
  return Buffer.from(body.join(''), 'base64');
}

/**
 * The EC point out of a v4 public-key packet body.
 *
 * Layout: version, 4-byte creation time, algorithm, then for both EdDSA and
 * ECDH a length-prefixed curve OID followed by an MPI. The MPI's value for
 * either curve is 0x40 (the "native point format" prefix) followed by 32 bytes,
 * and that tail is the raw key the device returned.
 */
function publicPoint(body) {
  if (body[0] !== 4) throw new Error(`expected a v4 packet, got version ${body[0]}`);
  const algo = body[5];
  const oidLen = body[6];
  let i = 7 + oidLen;
  const bits = body.readUInt16BE(i);
  i += 2;
  const mpi = body.subarray(i, i + Math.ceil(bits / 8));
  return { algo, mpi, key: mpi.subarray(1), prefix: mpi[0], created: body.readUInt32BE(1) };
}

/**
 * The pids of any onlykey-gpg-agent running against a given homedir.
 *
 * Read straight out of /proc, matched on the homedir this test created, and
 * that precision is the whole point. This is a shared machine with several
 * workspaces on it, so a pattern kill on "gpg-agent" would take down the
 * developer's own; the homedir is a fresh mkdtemp path that nothing else can
 * be using.
 */
function agentsFor(dir) {
  const pids = [];
  for (const entry of fs.readdirSync('/proc')) {
    if (!/^\d+$/.test(entry)) continue;
    let cmdline;
    try {
      cmdline = fs.readFileSync(`/proc/${entry}/cmdline`, 'utf8').split('\0').join(' ');
    } catch { continue; }                       // exited between readdir and read
    if (cmdline.includes('onlykey-gpg-agent') && cmdline.includes(dir)) pids.push(Number(entry));
  }
  return pids;
}

describe('onlykey-gpg, initialising a GnuPG identity', {
  state: 'initialized',
  requires: ['crypto', 'client-access'],
  timeoutMs: 300000,
}, () => {
  let parent = null;
  let homedir = null;
  let init = null;           // the result of the one `onlykey-gpg init`
  let exported = null;       // what gpg holds afterwards, as packets

  const at = (name) => path.join(homedir, name);

  /** Every gpg invocation is against the throwaway homedir, never the user's. */
  const gpg = (argv, opts) => cli.runHost('gpg', ['--homedir', homedir, ...argv],
    { timeoutMs: 30000, ...opts });

  it('has a venv, a gpg, and a homedir that does not exist yet',
    async ({ assert, signal, log, skip }) => {
      if (!cli.venvPresent()) skip(`no venv at ${cli.VENV_BIN}`);
      assert.ok(cli.binary('onlykey-gpg'), 'onlykey-gpg is missing from the venv');
      assert.ok(cli.binary('onlykey-gpg-agent'),
        'onlykey-gpg-agent is missing - run-agent.sh would name a binary that is not there');

      if (!cli.hostBinaryPresent('gpg')) skip('no gpg on PATH');

      /*
       * lib-agent warns rather than fails on an old gpg, so a version below
       * 2.1.11 would produce a confusing failure much later. Checked here
       * instead, where it can be a sentence.
       */
      const version = await gpgVersion({ signal });
      log(`gpg ${version}`);
      const [major, minor] = version.split('.').map(Number);
      assert.ok(major > 2 || (major === 2 && minor >= 1),
        `lib-agent needs gpg >= 2.1.11, this is ${version}`);

      /*
       * run_init() does `mkdir -p` itself and REFUSES a homedir that already
       * exists, so what it needs is a path rather than a directory. The parent
       * is real so that the test owns something it can remove.
       */
      parent = fs.mkdtempSync(path.join(os.tmpdir(), 'okt-tc13-gpg-'));
      homedir = path.join(parent, 'gnupg');
      assert.ok(!fs.existsSync(homedir), `${homedir} exists already`);
      log(`homedir will be ${homedir}`);
    });

  async function gpgVersion(opts) {
    const result = await cli.runHost('gpg', ['--version'], { timeoutMs: 15000, ...opts });
    const m = result.stdout.match(/^gpg \(GnuPG\)\s+(\S+)/m);
    if (!m) throw new Error(`could not read a gpg version from ${JSON.stringify(result.stdout.slice(0, 80))}`);
    return m[1];
  }

  it('initialises an identity, answering a challenge for each signature',
    async ({ device, assert, signal, log }) => {
      /*
       * Unlocked first, as everywhere else - lib-agent's connect() sets the
       * time and then insists on reading a version string back.
       */
      await device.unlock(PINS.primary, { signal });
      const primed = device.log.count(PRIMED);

      /*
       * Two signatures, so two confirmations, and neither digit triple can be
       * predicted from here: they are sha256 over the OpenPGP packet lib-agent
       * assembles, which includes a creation timestamp and the user id. Reading
       * them off the device's own console is what confirmFromConsole() is for,
       * and this is its second live caller after the composite operations.
       */
      init = await pqc.confirmFromConsole(device, () => cli.run('onlykey-gpg',
        ['init', USER_ID, '--homedir', homedir],
        { timeoutMs: 240000, signal, env: VENV_PATH }), { signal });

      log(`onlykey-gpg init exited ${init.code}`);
      assert.equal(init.code, 0,
        `onlykey-gpg init failed: ${init.stderr.slice(-2000) || init.stdout.slice(-2000)}`);

      /*
       * Exactly two, and the number is the assertion. export_public_key() calls
       * signer_func twice - encode.create_primary() for the self-certification
       * and encode.create_subkey() for the binding - so one challenge would
       * mean a key was built without a signature it is supposed to carry, and
       * three would mean something signed that nobody asked for.
       */
      const raised = device.log.count(PRIMED) - primed;
      log(`button challenges raised: ${raised}`);
      assert.equal(raised, 2,
        'init should sign exactly twice: the primary self-certification and the subkey binding');
    });

  it('printed the digits the device was actually going to ask for',
    async ({ device, assert, log }) => {
      /*
       * The two sides of the challenge are computed independently and never
       * compared by anything in normal use - lib-agent hashes the message it is
       * about to send, the device hashes what it reassembled out of several
       * 64-byte reports, and a human is expected to notice if the numbers on
       * the screen do not open the device. Comparing them here is what turns a
       * framing bug from "the device kept refusing my confirmation" into a
       * sentence naming which side is wrong.
       *
       * lib-agent prints the triple once per signature. It used to be alone on
       * the line after "Enter the 3 digit challenge code"; since the press-mode
       * work it is inline - "Confirm on OnlyKey to authorize <id>: press any
       * button, or enter 5 4 2 if derivedkeymode/storedkeymode is 0" - because
       * the host cannot tell which mode the key is in. Both forms are accepted.
       */
      const printed = [...init.stdout.matchAll(
        /(?:^\s*|\benter )([1-6]) ([1-6]) ([1-6])(?=\s*$|\s+if\b)/gm)]
        .map((m) => [Number(m[1]), Number(m[2]), Number(m[3])]);

      log(`lib-agent printed ${JSON.stringify(printed)}`);
      assert.equal(printed.length, 2,
        `expected one printed challenge per signature, got ${JSON.stringify(printed)}`);

      /*
       * Against the LAST packet the device dumped, which is the subkey binding
       * signature - the accumulator is not cleared, so the most recent dump is
       * the most recent challenge, and that is the one the second triple is
       * for.
       */
      const packet = pqc.packetFromConsole(device);
      assert.ok(packet, 'the device never dumped a packet - is this a DEBUG build?');

      const derived = pqc.challengeDigitsFor(packet);
      log(`derived from the device's own dump: ${JSON.stringify(derived)}`);
      assert.equal(JSON.stringify(printed[1]), JSON.stringify(derived),
        'lib-agent and the device disagree about the challenge - the message did not arrive intact');
    });

  it('wrote a homedir wired to the device', async ({ assert, log }) => {
    /*
     * What makes this a HARDWARE identity rather than an ordinary one is two
     * files: run-agent.sh, which names the agent binary and the slots, and
     * gpg.conf, which tells gpg to use that script instead of the stock
     * gpg-agent. If either is wrong the keyring looks perfectly normal and
     * every operation fails at the point of use.
     */
    for (const name of ['run-agent.sh', 'gpg.conf', 'env', 'pubkey.asc', 'ownertrust.txt']) {
      assert.ok(fs.existsSync(at(name)), `init did not write ${name}`);
    }

    const script = fs.readFileSync(at('run-agent.sh'), 'utf8');
    assert.includes(script, 'onlykey-gpg-agent', 'run-agent.sh does not launch the OnlyKey agent');
    assert.includes(script, '--skey-slot=ECC32', 'run-agent.sh does not name the signing slot');
    assert.includes(script, '--dkey-slot=ECC32', 'run-agent.sh does not name the decryption slot');

    /* ECC32 is convert_keyslot()'s spelling of 132 - the derived-key slot. A
     * different number here means the agent would later ask for a STORED key
     * that nothing ever put in the device. */
    log(`run-agent.sh slots: ${(script.match(/--[sd]key-slot=\S+/g) || []).join(' ')}`);

    const conf = fs.readFileSync(at('gpg.conf'), 'utf8');
    assert.includes(conf, `agent-program ${at('run-agent.sh')}`,
      'gpg.conf does not point gpg at the hardware agent');
    assert.includes(conf, `default-key "${USER_ID}"`, 'gpg.conf names a different default key');

    /* 700 on both, because run-agent.sh is executed and the homedir holds a
     * keyring; gpg refuses a homedir with looser permissions anyway. */
    assert.equal(fs.statSync(homedir).mode & 0o777, 0o700, 'the homedir is not 700');
    assert.equal(fs.statSync(at('run-agent.sh')).mode & 0o777, 0o700, 'run-agent.sh is not 700');
  });

  it('imported the key into a keyring gpg can read', async ({ assert, signal, log }) => {
    const listed = await gpg(['--list-keys', '--with-colons', '--fingerprint'], { signal });
    assert.equal(listed.code, 0, `gpg --list-keys failed: ${listed.stderr}`);

    assert.match(listed.stdout, /^pub:/m, 'gpg has no public key in this homedir');
    assert.includes(listed.stdout, USER_ID, 'the imported key carries a different user id');

    /*
     * "u" is ultimate ownertrust, which run_init() sets by exporting the
     * fingerprint into ownertrust.txt and importing it. Without it the key
     * imports fine and then every use of it warns that it is not certified,
     * which reads as a device problem to anyone who did not write this.
     */
    const pub = listed.stdout.split('\n').find((l) => l.startsWith('pub:'));
    log(`pub record: ${pub}`);
    assert.equal(pub.split(':')[1], 'u',
      `the imported key is not ultimately trusted: ${pub}`);

    const raw = await gpg(['--export', '--armor', USER_ID], { signal });
    assert.equal(raw.code, 0, `gpg --export failed: ${raw.stderr}`);

    exported = packets(dearmor(raw.stdout));
    log(`exported packets: ${exported.map((p) => `${p.tag}(${p.body.length})`).join(' ')}`);
    assert.ok(exported.some((p) => p.tag === 6), 'no public-key packet in the export');
  });

  it('holds the key this kit derives for the same identity',
    async ({ device, assert, signal, log }) => {
      /*
       * The three-way check, as in 08-lib-agent-ssh: lib-agent asked over
       * hidapi, gpg wrote down whatever it was told, and this asks the same
       * question over the in-process vendor interface. Without it, `init`
       * succeeding says only that lib-agent and gpg agreed with each other.
       *
       * Both keys are checked, because init derives TWO and they come from
       * separate requests with different keytype bytes - the ed25519 primary
       * that signs and the curve25519 subkey that decrypts. A firmware that
       * ignored the keytype would return the same point twice and pass a test
       * that only looked at one of them.
       */
      const primary = exported.find((p) => p.tag === 6);
      const subkey = exported.find((p) => p.tag === 14);
      assert.ok(subkey, 'no public-subkey packet - init is supposed to add an encryption subkey');

      const primaryPoint = publicPoint(primary.body);
      const subkeyPoint = publicPoint(subkey.body);

      assert.equal(primaryPoint.algo, ALGO_EDDSA, `the primary is algorithm ${primaryPoint.algo}, not EdDSA`);
      assert.equal(subkeyPoint.algo, ALGO_ECDH, `the subkey is algorithm ${subkeyPoint.algo}, not ECDH`);
      assert.equal(primaryPoint.prefix, 0x40, 'the primary MPI is not in native point format');
      assert.equal(primaryPoint.key.length, 32, `an ed25519 point is 32 bytes, this is ${primaryPoint.key.length}`);

      log(`gpg holds  sign ${primaryPoint.key.toString('hex')}`);
      log(`gpg holds   dec ${subkeyPoint.key.toString('hex')}`);

      const askFor = async (keytype) => {
        const since = device.mark(IFACE.VENDOR);
        device.sendVendor({
          msg: okmsg.MSG.OKGETPUBKEY,
          slot: RESERVED_KEY_DERIVATION,
          payload: Buffer.concat([Buffer.from([keytype]), identityHash()]),
        });
        const reply = await device.waitHid(IFACE.VENDOR, { since, timeoutMs: 10000, signal });
        assert.ok(!/^Error/.test(okmsg.text(reply)),
          `the device refused OKGETPUBKEY for keytype ${keytype}: ${okmsg.text(reply)}`);
        return reply.subarray(0, 32);
      };

      const ours = await askFor(KEYTYPE_ED25519);
      log(`the kit derives  ${ours.toString('hex')}`);
      assert.bytes(ours, primaryPoint.key,
        'gpg holds a different signing key than the device derives for this identity');

      const oursEcdh = await askFor(KEYTYPE_CURVE25519);
      log(`the kit derives  ${oursEcdh.toString('hex')} (ecdh)`);
      assert.bytes(oursEcdh, subkeyPoint.key,
        'gpg holds a different decryption key than the device derives for this identity');

      /* And they are genuinely two keys. Same identity, same slot, different
       * keytype byte - so this is the assertion that the keytype reached the
       * derivation at all. */
      assert.notEqual(primaryPoint.key.toString('hex'), subkeyPoint.key.toString('hex'),
        'the signing and decryption keys are the same - the keytype byte is being ignored');
    });

  it('leaves an agent running, and stops it', async ({ device, assert, signal, log }) => {
    /*
     * Visible cleanup rather than a hook, and the first half is an assertion
     * rather than a formality: `init` DOES leave a daemon behind, and that is
     * worth stating because it is not obvious from anything it prints.
     * run_init()'s last step is `gpg --list-secret-keys`, which makes gpg
     * launch the agent named in gpg.conf - so by the time the command exits
     * successfully there is a long-lived onlykey-gpg-agent holding the device's
     * hidraw node, and it outlives the test, the file and the run.
     *
     * NOT `gpgconf --kill all`, which is the documented way and does not work
     * here: it HANGS. gpgconf drives the agent over assuan and asks it things
     * the stock gpg-agent answers - the observed stall was
     * `gpg-connect-agent ... GETINFO tpm2d_running` - and onlykey-gpg-agent is
     * a different program that does not, so the call sits until its timeout.
     * Reading /proc and signalling the pid is both faster and honest about what
     * is being killed.
     *
     * This was found the expensive way: FOUR of these were running on this
     * machine from an earlier attempt at this row, forty hours old, with their
     * homedirs long since deleted. A test that starts a daemon and does not
     * stop it does not fail - it accumulates.
     */
    const running = agentsFor(homedir);
    log(`onlykey-gpg-agent pids for this homedir: ${JSON.stringify(running)}`);
    assert.ok(running.length > 0,
      'init did not leave an agent running - gpg.conf may not be pointing at run-agent.sh');

    for (const pid of running) {
      try { process.kill(pid, 'SIGTERM'); } catch { /* already gone */ }
    }

    /* Give them a moment to go, then say so plainly if they did not. */
    for (let i = 0; i < 40 && agentsFor(homedir).length; i++) {
      await device.sleep(100, { signal });
    }

    const left = agentsFor(homedir);
    assert.equal(left.length, 0,
      `an agent is still running for ${homedir}: ${JSON.stringify(left)}`);
  });

  it('refuses to reuse a homedir, without touching the device',
    async ({ device, assert, signal, log }) => {
      /*
       * The trap this row was written around. run_init() exits 1 rather than
       * reusing or clearing an existing homedir, so a second attempt at the
       * same path fails for a reason that has nothing to do with the device -
       * and the message goes to the log, not to stderr, which is why anyone
       * retrying by hand sees a bare non-zero exit and blames the key.
       *
       * The device must also be untouched: this has to fail BEFORE anything is
       * asked of it, or a failed retry would leave a challenge primed and the
       * next operation would consume it. That is the same ordering hazard
       * 06-composite-ops records.
       */
      const primed = device.log.count(PRIMED);
      const before = device.log.text.length;

      const again = await cli.run('onlykey-gpg',
        ['init', USER_ID, '--homedir', homedir],
        { timeoutMs: 60000, signal, env: VENV_PATH });

      log(`the second init exited ${again.code}`);
      assert.equal(again.code, 1, 'init reused an existing homedir instead of refusing');
      assert.equal(device.log.count(PRIMED), primed,
        'the refused init still primed a challenge - the next operation would consume it');
      assert.equal(device.log.text.length, before,
        'the refused init reached the device before deciding it could not run');
    });

  it('cleans up after itself', async ({ assert }) => {
    /* A failure above leaves the homedir behind on purpose - the keyring that
     * came out wrong is the evidence. */
    fs.rmSync(parent, { recursive: true, force: true });
    assert.ok(!fs.existsSync(parent), `${parent} is still there`);
  });
});
