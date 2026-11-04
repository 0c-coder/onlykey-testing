/*
 * CLI parity: can onlykey-js replace onlykey-cli, command by command?
 *
 * Two command lines drive one device here. python-onlykey's `onlykey-cli` is
 * the one people have; node-onlykey-lib's `onlykey-js` (the lib's package.json
 * "bin", run through cli.runLib) is the candidate replacement, with no protocol
 * code of its own. For each command in scope, python runs first and onlykey-js
 * second, against the same device state.
 *
 * THE DEVICE IS THE TRUTH, NOT THE OTHER CLI. Every assertion compares a CLI's
 * stdout with what the device itself said on the vendor interface (0xFFAB),
 * read over the kit's in-process bus independently of both clients - the same
 * oracle 10/11/12-cli use. Comparing the two CLIs with each other would pass
 * when both are wrong in the same way, and would give no answer to "which one
 * is right" when they differ. Where a write changes state, the stored result
 * is read back over the same bus as well: an acknowledgement says a write was
 * accepted, a readback says the right bytes arrived.
 *
 * EVERY DIFFERENCE GETS A VERDICT, and each test states its verdicts in a
 * PARITY line in the log (`grep PARITY` over a run gives the table):
 *
 *   INTENTIONAL  on the lib author's documented list (node-onlykey-lib
 *                cli/README.md) - it passes, and is named in the PARITY line.
 *   PYTHON BUG   python disagrees with the device, found by this file and
 *                pinned as it ships (the kit's rule: assert shipped behaviour,
 *                say why). Passes, named in the PARITY line; a fixed python
 *                passes too.
 *   FAIL         anything else. The message names which CLI disagrees with
 *                the device.
 *
 * PYTHON BUG #9 IS NOT MASKED. python-onlykey reads a reply with a 100 ms
 * timeout, and a device that answers a little later leaves it printing "".
 * When that happens the test fails and names python and #9, as 11-cli-settings
 * does - but only after the onlykey-js half has run and been asserted, so one
 * python flake cannot hide an onlykey-js answer.
 *
 * TRAFFIC THE TWO SEND DIFFERENTLY, AND WHY IT IS FILTERED. onlykey-js opens
 * every command with OKCONNECT (it sets the clock, and tells the lib the model
 * and version), so the device answers its status line - "UNLOCKEDv3.1.0-..." -
 * before anything else. python sends that only for fwversion/settime. So the
 * write acknowledgements are read as "what the device said that is not a status
 * line or a label", which is identical for both.
 *
 * OUT OF SCOPE: firmware update, backup/restore, init and PIN setup, the PQC
 * commands (loadpqc/signpqc/decryptpqc) and solo's FIDO commands - onlykey-js
 * has none of them, by design.
 *
 * Every test stands alone - `okt run <file> --test setkey` - and establishes
 * its own state (config mode is sticky; see 11-cli-settings).
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

const PY = 'onlykey-cli';
const JS = 'onlykey-js';

/*
 * The lib author's documented differences (node-onlykey-lib cli/README.md at
 * 489636b). A difference on this list passes and is named; nothing else does.
 */
const INTENTIONAL = {
  refusalExit: 'a refusal exits 1 (python exits 0)',
  usageExit: 'a usage error exits 2, before anything is sent',
  oneValue: 'setslot takes exactly one value (python stores the first word and says it worked)',
  settingsSlot: 'settings are written on slot 0 (python: slot 1; the firmware ignores it)',
  oneWay: 'one-way settings need --yes',
  genkeyEcc: 'genkey takes ECC slots only (python sends genkey HMAC1 to slot 130)',
  ownVersion: 'version prints each program\'s own name and version',
  capsSource: 'capabilities come from the lib\'s version table (python asks for a report the firmware does not send)',
  statusNew: 'status is new in onlykey-js; python has no such command',
};

/* python disagreeing with the device, found here and pinned as it ships. */
const PYTHON_BUG = {
  erasedLabel: 'an erased label (0xFF x 16) prints as blanks instead of <empty>',
  wipeslotEight: 'wipeslot prints eight of the ten acks the device sends (fixed in bm-ok python-onlykey)',
};

/* RFC 8032 test vectors 1 and 2: published seeds, so the public half is
 * recomputed here rather than taken from the device. */
const SEED_PY = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';
const SEED_JS = '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb';

const ECC1 = 101;
const ECC1_LABEL_INDEX = 29;                  // key label slots: RSA1-4 25-28, ECC1-16 29-44
const TYPE_ED25519_SIGN = 0x41;               // KEYTYPE_ED25519 | MODIFIER.SIGNATURE
const NO_ECC_KEY = /Error no ECC Private Key/;

const STATUS = /^(UNLOCKED|INITIALIZED|UNINITIALIZED)/;

/* A label reply is "<slot byte>|<16 label bytes>": slot bytes 1-9 and 16-18
 * for the twelve profile slots (10-12 are sent +6, off the control characters
 * that would end a line), 25-44 for the key slots. */
const isLabelReply = (buf) => buf[1] === 0x7c && buf[0] >= 1 && buf[0] <= 44;

const deviceText = (buf) => okmsg.text(buf).replace(/\s+$/, '');

/** What the device said that is an answer to a write: not a status line, not a label. */
const isAck = (buf) => {
  const text = deviceText(buf);
  return !!text && !STATUS.test(text) && !isLabelReply(buf);
};

/** Parse label replies: Map slot -> { text, erased }. The last reply per slot wins. */
function labelsFrom(reports, { keys }) {
  const map = new Map();
  for (const buf of reports) {
    if (!isLabelReply(buf)) continue;
    let n = buf[0];
    if (keys ? (n < 25) : (n > 24)) continue;
    if (!keys && n >= 16) n -= 6;
    let end = 2;
    while (end < Math.min(buf.length, 18) && buf[end] !== 0) end++;
    const bytes = buf.subarray(2, end);
    map.set(n, {
      text: bytes.toString('latin1'),
      erased: bytes.length === 0 || bytes.every((b) => b === 0xff),
    });
  }
  return map;
}

const PROFILE_ORDER = ['1a', '1b', '2a', '2b', '3a', '3b', '4a', '4b', '5a', '5b', '6a', '6b'];
const profileSlot = (name) => Number(name[0]) + (name[1] === 'b' ? 6 : 0);
const KEY_ORDER = [
  ...[1, 2, 3, 4].map((n) => ({ name: `RSA Key ${n}`, index: 24 + n })),
  ...Array.from({ length: 16 }, (_, i) => ({ name: `ECC Key ${i + 1}`, index: 29 + i })),
];

/** The ed25519 public key for a seed, from node:crypto. */
function ed25519PublicKey(seedHex) {
  const der = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(seedHex, 'hex')]);
  const priv = crypto.createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
  return crypto.createPublicKey(priv).export({ format: 'der', type: 'spki' }).subarray(-32);
}

const short = (s, n = 160) => JSON.stringify(String(s).length > n ? `${String(s).slice(0, n)}...` : String(s));
const stdoutLines = (s) => s.replace(/\n+$/, '').split('\n');

/**
 * One command's verdict sheet. Checks are collected rather than thrown so the
 * onlykey-js half always runs after a python failure (and vice versa), and the
 * PARITY line is logged whatever happened.
 */
function sheet(assert, log, command) {
  const fails = [];
  const verdicts = new Set();
  const cells = { py: '-', js: '-', device: '-' };
  return {
    cells,
    /** `who` disagrees with the device unless `ok`. */
    check(who, ok, message) {
      if (!ok) fails.push(`${who} disagrees with the device: ${message}`);
      return !!ok;
    },
    fail(message) { fails.push(message); },
    intentional(key) { verdicts.add(`INTENTIONAL: ${INTENTIONAL[key]}`); },
    pythonBug(key) { verdicts.add(`PYTHON BUG: ${PYTHON_BUG[key]}`); },
    done() {
      const verdict = fails.length ? `FAIL (${fails.length})`
        : (verdicts.size ? [...verdicts].join('; ') : 'same');
      log(`PARITY | ${command} | py ${cells.py} | js ${cells.js} | device ${cells.device} | ${verdict}`);
      assert.ok(fails.length === 0, fails.join('\n'));
    },
  };
}

describe('CLI parity: onlykey-cli (python) against onlykey-js (node-onlykey-lib), with the device as the truth', {
  state: 'initialized',
  requires: ['crypto', 'client-access'],
  timeoutMs: 300000,
}, () => {
  const needBoth = ({ skip }) => {
    if (!cli.venvPresent()) skip(`no venv at ${cli.VENV_BIN}`);
    cli.binary('onlykey-cli');
    const missing = cli.libCliMissing();
    if (missing) skip(`onlykey-js cannot run: ${missing}`);
  };

  /**
   * Run one CLI and collect everything the device said while it ran.
   *
   * `acks` waits for that many write acknowledgements before settling, which
   * matters for python bug #9: a python that gave up on a slow reply has
   * already exited when the reply lands, and the device's answer must still be
   * seen so the failure can say what python missed.
   */
  async function exchange(device, who, argv, { signal, acks = 0, input, settleMs = 600, timeoutMs = 60000 } = {}) {
    device.log.clear();
    const since = device.mark(IFACE.VENDOR);
    const opts = { timeoutMs, signal, input };
    const result = who === PY ? await cli.run('onlykey-cli', argv, opts) : await cli.runLib(argv, opts);
    /*
     * Console noise out, replies kept. On Windows python prints \r\n and a
     * whitespace-only line before its first reply; neither is anything the
     * device said. A truly EMPTY line stays: that is python printing "" for a
     * reply it missed (#9), which the checks below must still see.
     */
    result.stdout = result.stdout.replace(/\r\n/g, '\n').split('\n')
      .filter((l) => l === '' || l.trim() !== '').join('\n');
    if (acks > 0) {
      const deadline = Date.now() + 10000;
      while (device.reportsSince(IFACE.VENDOR, since).filter(isAck).length < acks && Date.now() < deadline) {
        await device.sleep(100, { signal });
      }
    }
    await device.sleep(settleMs, { signal });
    const reports = device.reportsSince(IFACE.VENDOR, since);
    const said = reports.filter(isAck).map(deviceText);
    const status = reports.map(deviceText).find((t) => STATUS.test(t)) || null;
    /* SURFACE: console - which slot and field a settings write went to. */
    const echo = [...device.log.text.matchAll(/Setting Slot #(\d+)\s+Value #(\d+)/g)].pop() || null;
    return {
      result, reports, said, status,
      echo: echo ? { slot: Number(echo[1]), field: Number(echo[2]) } : null,
      out: result.stdout.trim(),
    };
  }

  const cell = (x) => `exit ${x.result.code} ${short(x.out.split('\n').join(' / '), 90)}`;

  /**
   * The CLI printed the device's one-line answer. For python an empty stdout
   * over a real answer is bug #9, and says so.
   */
  function relayed(s, who, x, said) {
    if (who === PY && said && x.out === '') {
      return s.check(PY, false, `printed "" where the device answered ${short(said)} (exit ${x.result.code}) - `
        + 'python-onlykey bug #9: a 100 ms read gave up on a slow reply');
    }
    return s.check(who, x.out === said,
      `printed ${short(x.out)} (exit ${x.result.code}) where the device answered ${short(said)}`);
  }

  /** Unlocked and out of config mode (sticky, only a reboot leaves it). */
  const outOfConfigMode = async (device, signal) => {
    await device.restart({ signal });
    await device.ensureUnlocked(PINS.primary, { signal });
  };

  /** Write a label over the kit's own vendor interface. */
  async function kitLabel(device, slot, label, { signal }) {
    const since = device.mark(IFACE.VENDOR);
    device.sendVendor({ msg: okmsg.MSG.OKSETSLOT, slot, field: 1, payload: label });
    const ack = await device.waitHid(IFACE.VENDOR, { since, match: isAck, timeoutMs: 5000, signal });
    if (!/Successfully set Label/.test(okmsg.text(ack))) throw new Error(`kit label write refused: ${okmsg.text(ack)}`);
  }

  /** Read labels back over the kit's own vendor interface. */
  async function kitLabels(device, { keys = false, signal }) {
    const since = device.mark(IFACE.VENDOR);
    device.sendVendor(keys ? { msg: okmsg.MSG.OKGETLABELS, slot: 107 } : { msg: okmsg.MSG.OKGETLABELS });
    const want = keys ? 20 : 12;
    const deadline = Date.now() + 6000;
    let map = new Map();
    while (Date.now() < deadline) {
      map = labelsFrom(device.reportsSince(IFACE.VENDOR, since), { keys });
      if (map.size >= want) break;
      await device.sleep(100, { signal });
    }
    return map;
  }

  /** OKGETPUBKEY, out of config mode (it is refused in it - 12-cli-slots). */
  async function kitPublicKey(device, slot, { signal }) {
    const since = device.mark(IFACE.VENDOR);
    device.sendVendor({ msg: okmsg.MSG.OKGETPUBKEY, slot });
    const reply = await device.waitHid(IFACE.VENDOR,
      { since, match: (b) => !STATUS.test(deviceText(b)), timeoutMs: 10000, signal });
    return reply;
  }

  /* ================================================================ reads */

  it('`version`: each prints its own version, and the device hears nothing',
    async ({ device, assert, signal, log, skip }) => {
      needBoth({ skip });
      const s = sheet(assert, log, 'version');
      await device.ensureUnlocked(PINS.primary, { signal });

      /* Unlocked, the vendor interface is silent unless asked (10-cli-reads). */
      const py = await exchange(device, PY, ['version'], { signal, settleMs: 1000 });
      const js = await exchange(device, JS, ['version'], { signal, settleMs: 1000 });
      s.cells.py = cell(py);
      s.cells.js = cell(js);
      s.cells.device = 'silent';

      for (const [who, x, re] of [[PY, py, /^OnlyKey CLI v\d+\.\d+/], [JS, js, /^onlykey-js v\d+\.\d+/]]) {
        s.check(who, x.result.code === 0 && re.test(x.out), `version printed ${short(x.out)} (exit ${x.result.code})`);
        const heard = x.reports.map(deviceText).filter(Boolean);
        s.check(who, heard.length === 0, `version put traffic on the device: ${short(heard.join(' | '))}`);
      }
      s.intentional('ownVersion');
      s.done();
    });

  it('`fwversion`: the version after the state word, as the device reports it',
    async ({ device, assert, signal, log, skip }) => {
      needBoth({ skip });
      const s = sheet(assert, log, 'fwversion');
      const model = (await device.ensureUnlocked(PINS.primary, { signal })).replace(/\0/g, '').trim();

      const py = await exchange(device, PY, ['fwversion'], { signal });
      const js = await exchange(device, JS, ['fwversion'], { signal });
      s.cells.py = cell(py);
      s.cells.js = cell(js);
      s.cells.device = short(py.status || js.status);

      for (const [who, x] of [[PY, py], [JS, js]]) {
        if (!s.check(who, x.status, 'the device sent no status line while it ran')) continue;
        s.check(who, x.status === model, `the device answered ${short(x.status)}, the kit was told ${short(model)}`);
        relayed(s, who, x, x.status.slice(8));
        s.check(who, x.result.code === 0, `exit ${x.result.code}`);
      }
      s.done();
    });

  it('`settime`: prints the status line the device answers the clock with',
    async ({ device, assert, signal, log, skip }) => {
      needBoth({ skip });
      const s = sheet(assert, log, 'settime');
      await device.ensureUnlocked(PINS.primary, { signal });

      /* OKSETTIME is OKCONNECT (0xE4); the answer is the status line. */
      const py = await exchange(device, PY, ['settime'], { signal });
      const js = await exchange(device, JS, ['settime'], { signal });
      s.cells.py = cell(py);
      s.cells.js = cell(js);
      s.cells.device = short(py.status || js.status);

      for (const [who, x] of [[PY, py], [JS, js]]) {
        if (!s.check(who, x.status, 'the device sent no status line while it ran')) continue;
        relayed(s, who, x, x.status);
        s.check(who, x.result.code === 0, `exit ${x.result.code}`);
      }
      s.done();
    });

  it('`getlabels`: every profile slot, in python\'s layout, as the device lists them',
    async ({ device, assert, signal, log, skip }) => {
      needBoth({ skip });
      const s = sheet(assert, log, 'getlabels');
      await device.ensureUnlocked(PINS.primary, { signal });

      /* 1a is sent as slot byte 1, 6b as 18 (12 + 6): one of each encoding. */
      await kitLabel(device, 1, 'oktpar1a', { signal });
      await kitLabel(device, 12, 'oktpar6b', { signal });

      const py = await exchange(device, PY, ['getlabels'], { signal, settleMs: 1000 });
      const js = await exchange(device, JS, ['getlabels'], { signal, settleMs: 1000 });
      s.cells.py = `exit ${py.result.code}, ${stdoutLines(py.result.stdout).filter((l) => l.trim()).length} slot lines`;
      s.cells.js = `exit ${js.result.code}, ${stdoutLines(js.result.stdout).filter((l) => l.trim()).length} slot lines`;

      for (const [who, x] of [[PY, py], [JS, js]]) {
        const truth = labelsFrom(x.reports, { keys: false });
        if (!s.check(who, truth.size === 12, `the device listed ${truth.size} slots while it ran, not 12`)) continue;
        s.cells.device = `12 labels (1a ${short(truth.get(1).text)}, 6b ${short(truth.get(12).text)}, rest erased)`;
        const lines = stdoutLines(x.result.stdout).filter((l) => l.trim());
        if (who === PY && lines.length < 12 && x.result.code !== 0) {
          s.check(PY, false, `printed ${lines.length} of the 12 slots the device listed, exit ${x.result.code} `
            + `(${short(x.result.stderr.trim().split('\n').pop())}) - python-onlykey bug #9 when a read came back empty`);
          continue;
        }
        s.check(who, lines.length === 12, `printed ${lines.length} slot lines: ${short(lines.join(' / '))}`);
        PROFILE_ORDER.forEach((name, i) => {
          const label = truth.get(profileSlot(name));
          const want = `Slot ${name}: ${label.erased ? '<empty>' : label.text}`;
          const got = (lines[i] || '').replace(/\s+$/, '');
          if (got === want) return;
          if (who === PY && label.erased && got === `Slot ${name}:`) {
            s.pythonBug('erasedLabel');
            return;
          }
          s.check(who, false, `slot ${name}: printed ${short(got)}, the device has ${short(want)}`);
        });
        s.check(who, x.result.code === 0, `exit ${x.result.code}`);
      }
      s.done();
    });

  it('`getkeylabels`: RSA Key 1-4 and ECC Key 1-16, as the device lists them',
    async ({ device, assert, signal, log, skip }) => {
      needBoth({ skip });
      const s = sheet(assert, log, 'getkeylabels');
      await device.ensureUnlocked(PINS.primary, { signal });

      await kitLabel(device, 26, 'oktparR2', { signal });           // RSA Key 2
      await kitLabel(device, ECC1_LABEL_INDEX, 'oktparE1', { signal }); // ECC Key 1

      const py = await exchange(device, PY, ['getkeylabels'], { signal, settleMs: 1000 });
      const js = await exchange(device, JS, ['getkeylabels'], { signal, settleMs: 1000 });
      s.cells.py = `exit ${py.result.code}, ${stdoutLines(py.result.stdout).filter((l) => l.trim()).length} key lines`;
      s.cells.js = `exit ${js.result.code}, ${stdoutLines(js.result.stdout).filter((l) => l.trim()).length} key lines`;

      for (const [who, x] of [[PY, py], [JS, js]]) {
        const truth = labelsFrom(x.reports, { keys: true });
        if (!s.check(who, truth.size === 20, `the device listed ${truth.size} key slots while it ran, not 20`)) continue;
        s.cells.device = `20 labels (RSA2 ${short(truth.get(26).text)}, ECC1 ${short(truth.get(29).text)}, rest erased)`;
        const lines = stdoutLines(x.result.stdout).filter((l) => l.trim());
        if (who === PY && lines.length < 20 && x.result.code !== 0) {
          s.check(PY, false, `printed ${lines.length} of the 20 key slots the device listed, exit ${x.result.code} `
            + `(${short(x.result.stderr.trim().split('\n').pop())}) - python-onlykey bug #9 when a read came back empty`);
          continue;
        }
        s.check(who, lines.length === 20, `printed ${lines.length} key lines`);
        KEY_ORDER.forEach(({ name, index }, i) => {
          const label = truth.get(index);
          const want = `Slot ${name}: ${label.erased ? '<empty>' : label.text}`;
          const got = (lines[i] || '').replace(/\s+$/, '');
          if (got === want) return;
          if (who === PY && label.erased && got === `Slot ${name}:`) {
            s.pythonBug('erasedLabel');
            return;
          }
          s.check(who, false, `${name}: printed ${short(got)}, the device has ${short(want)}`);
        });
        s.check(who, x.result.code === 0, `exit ${x.result.code}`);
      }
      s.done();
    });

  it('`capabilities`: python relays the device\'s (absent) report, onlykey-js derives from the version',
    async ({ device, assert, signal, log, skip }) => {
      needBoth({ skip });
      const s = sheet(assert, log, 'capabilities');
      await device.ensureUnlocked(PINS.primary, { signal });

      /*
       * python asks OKGETLABELS 'c'. A firmware with no capabilities report
       * ignores the selector and lists the profile labels instead - that list
       * IS the device's answer, and it means "no report". onlykey-js asks for
       * nothing beyond the connect: it reads the version and looks it up.
       */
      const py = await exchange(device, PY, ['capabilities'], { signal, settleMs: 1000 });
      const js = await exchange(device, JS, ['capabilities'], { signal });
      s.cells.py = cell(py);
      s.cells.js = cell(js);

      const pyLabels = labelsFrom(py.reports, { keys: false }).size;
      const pyOther = py.said;
      const noReport = pyLabels > 0 && pyOther.length === 0;
      s.cells.device = noReport ? `no capabilities report (answered 'c' with ${pyLabels} labels); status ${short(js.status)}`
        : `report ${short(pyOther.join(' | '))}`;
      if (noReport) {
        s.check(PY, /does not report capabilities/.test(py.out),
          `the device sent no capabilities report, python printed ${short(py.out)}`);
      } else {
        s.check(PY, /^firmware\s/m.test(py.out), `the device sent a report, python printed ${short(py.out)}`);
      }
      s.check(PY, py.result.code === 0, `exit ${py.result.code}`);

      s.check(JS, js.status, 'the device sent no status line to onlykey-js');
      if (js.status) {
        const fw = /^firmware\s+(\S+)/m.exec(js.out);
        s.check(JS, fw && fw[1] === js.status.slice(8),
          `firmware line ${short(fw && fw[1])}, the device reported ${short(js.status.slice(8))}`);
      }
      s.check(JS, /^source\s+firmware version/m.test(js.out), `no source line: ${short(js.out)}`);
      s.check(JS, js.result.code === 0, `exit ${js.result.code}`);
      s.intentional('capsSource');
      s.done();
    });

  it('`status`: onlykey-js reports the device\'s status line and version; python has no such command',
    async ({ device, assert, signal, log, skip }) => {
      needBoth({ skip });
      const s = sheet(assert, log, 'status');
      await device.ensureUnlocked(PINS.primary, { signal });

      const py = await exchange(device, PY, ['status'], { signal, settleMs: 1000 });
      const js = await exchange(device, JS, ['status'], { signal });
      s.cells.py = cell(py);
      s.cells.js = cell(js);
      s.cells.device = short(js.status);

      s.check(PY, /Command not found/.test(py.out), `python now has a status command: ${short(py.out)}`);
      s.check(PY, py.reports.map(deviceText).filter(Boolean).length === 0, 'an unknown command reached the device');
      if (s.check(JS, js.status, 'the device sent no status line')) {
        const line = (k) => (new RegExp(`^${k}\\s+(.*)$`, 'm').exec(js.out) || [])[1];
        s.check(JS, line('status') === js.status, `status ${short(line('status'))}, device ${short(js.status)}`);
        s.check(JS, line('state') === 'unlocked', `state ${short(line('state'))} for ${short(js.status)}`);
        s.check(JS, line('firmware') === js.status.slice(8), `firmware ${short(line('firmware'))}`);
      }
      s.check(JS, js.result.code === 0, `exit ${js.result.code}`);
      s.intentional('statusNew');
      s.done();
    });

  /* ============================================================ settings */

  /*
   * Accepted with no gate. python's value, then a different one for onlykey-js,
   * so the second write is a write and not a no-op. The console echo ("Setting
   * Slot #N Value #F", SURFACE: console, a debug build only) is the one place
   * the SLOT and FIELD are visible: the field must match, and the slot differs
   * by design (python 1 - 0 for keytypespeed, whose 99 python rewrites -
   * onlykey-js 0).
   */
  const ACCEPTED = [
    ['idletimeout', '10', '11', 'Successfully set idle timeout'],
    ['ledbrightness', '5', '6', 'Successfully set LED brightness'],
    ['lockbutton', '1', '1', 'Successfully set lock button'],
    ['keylayout', '1', '1', 'Successfully set keyboard layout'],
    ['keytypespeed', '7', '8', 'Successfully set typespeed'],
  ];

  for (const [name, pyValue, jsValue, expected] of ACCEPTED) {
    it(`\`${name}\`: accepted, and acknowledged by name`, async ({ device, assert, signal, log, skip }) => {
      needBoth({ skip });
      const s = sheet(assert, log, `${name} ${pyValue}|${jsValue}`);
      await device.ensureUnlocked(PINS.primary, { signal });

      const py = await exchange(device, PY, [name, pyValue], { signal, acks: 1 });
      const js = await exchange(device, JS, [name, jsValue], { signal, acks: 1 });
      s.cells.py = cell(py);
      s.cells.js = cell(js);
      s.cells.device = short(py.said[0] || js.said[0]);

      for (const [who, x] of [[PY, py], [JS, js]]) {
        s.check(who, x.said.length === 1 && x.said[0] === expected, `the device answered ${short(x.said.join(' | '))}`);
        relayed(s, who, x, x.said[0]);
        s.check(who, x.result.code === 0, `exit ${x.result.code}`);
      }
      if (py.echo && js.echo) {
        s.check(JS, js.echo.field === py.echo.field,
          `went to field ${js.echo.field}, python's to field ${py.echo.field}`);
        if (js.echo.slot !== py.echo.slot) s.intentional('settingsSlot');
        s.cells.device += ` (console: py slot ${py.echo.slot}, js slot ${js.echo.slot}, field ${js.echo.field})`;
      }
      s.done();
    });
  }

  /* Refused outside config mode: the device's refusal, relayed by both. */
  const GATED = [
    ['storedkeymode', '1'],
    ['hmackeymode', '1'],
    ['sysadminmode', '1'],
    ['touchsense', '5'],
    ['derivedkeymode', '1'],
    ['webagentderivemode', '1'],
    ['webderivemode', '1'],
  ];

  for (const [name, value] of GATED) {
    it(`\`${name}\`: refused outside config mode`, async ({ device, assert, signal, log, skip }) => {
      needBoth({ skip });
      const s = sheet(assert, log, `${name} ${value} (not in config mode)`);
      await outOfConfigMode(device, signal);

      const py = await exchange(device, PY, [name, value], { signal, acks: 1 });
      const js = await exchange(device, JS, [name, value], { signal, acks: 1 });
      s.cells.py = cell(py);
      s.cells.js = cell(js);
      s.cells.device = short(py.said[0] || js.said[0]);

      for (const [who, x] of [[PY, py], [JS, js]]) {
        s.check(who, x.said[0] === 'Error not in config mode', `the device answered ${short(x.said.join(' | '))}`);
        relayed(s, who, x, x.said[0]);
      }
      s.check(PY, py.result.code === 0, `python exited ${py.result.code} for a refusal (it has always exited 0)`);
      s.check(JS, js.result.code === 1, `exit ${js.result.code} for the device's refusal, not 1`);
      if (py.echo && js.echo) {
        s.check(JS, js.echo.field === py.echo.field, `field ${js.echo.field}, python's ${py.echo.field}`);
      }
      s.intentional('refusalExit');
      s.done();
    });
  }

  /*
   * One-way settings. On a provisioned key outside config mode the device
   * refuses all three; onlykey-js will not even send one without --yes.
   */
  const ONE_WAY = [
    ['wipemode', '2', 'Error Wipe Mode may not be changed'],
    ['backupkeymode', '1', 'Error Backup Key Mode may not be changed'],
    ['webcryptpolicy', '1', 'Error not in config mode'],
  ];

  for (const [name, value, refusal] of ONE_WAY) {
    it(`\`${name}\`: one-way - refused by the device, and needs --yes in onlykey-js`,
      async ({ device, assert, signal, log, skip }) => {
        needBoth({ skip });
        const s = sheet(assert, log, `${name} ${value}`);
        await outOfConfigMode(device, signal);

        const py = await exchange(device, PY, [name, value], { signal, acks: 1 });
        const bare = await exchange(device, JS, [name, value], { signal, settleMs: 1000 });
        const yes = await exchange(device, JS, [name, value, '--yes'], { signal, acks: 1 });
        s.cells.py = cell(py);
        s.cells.js = `no --yes: exit ${bare.result.code}, nothing sent; --yes: ${cell(yes)}`;
        s.cells.device = short(py.said[0] || yes.said[0]);

        s.check(PY, py.said[0] === refusal, `the device answered python ${short(py.said.join(' | '))}`);
        relayed(s, PY, py, py.said[0]);

        s.check(JS, bare.result.code === 2, `without --yes exit ${bare.result.code}, not 2`);
        s.check(JS, bare.said.length === 0, `without --yes the device was written and answered ${short(bare.said.join(' | '))}`);
        s.check(JS, /--yes/.test(bare.result.stderr), `without --yes it did not say to add --yes: ${short(bare.result.stderr)}`);

        s.check(JS, yes.said[0] === refusal, `with --yes the device answered ${short(yes.said.join(' | '))}`);
        relayed(s, JS, yes, yes.said[0]);
        s.check(JS, yes.result.code === 1, `with --yes exit ${yes.result.code} for the device's refusal, not 1`);
        s.intentional('oneWay');
        s.intentional('refusalExit');
        s.done();
      });
  }

  /* ================================================================ slots */

  it('`setslot`: every field the command line can reach, acknowledged by name',
    async ({ device, assert, signal, log, skip }) => {
      needBoth({ skip });
      const s = sheet(assert, log, 'setslot 1a <13 fields>');
      await device.ensureUnlocked(PINS.primary, { signal });

      const fields = [
        ['label', 'oktpy', 'oktjs', 'Successfully set Label'],
        ['url', 'https://py.example', 'https://js.example', 'Successfully set URL'],
        ['username', 'oktpyuser', 'oktjsuser', 'Successfully set Username'],
        ['delay1', '1', '2', 'Successfully set Delay1'],
        ['delay2', '2', '3', 'Successfully set Delay2'],
        ['delay3', '3', '4', 'Successfully set Delay3'],
        ['addchar1', '1', '2', 'Successfully set before Username Additional Character'],
        ['addchar2', '2', '1', 'Successfully set after Username Additonal Character'],
        ['addchar3', '1', '2', 'Successfully set additional character after password'],
        ['addchar4', '2', '1', 'Successfully set before OTP Additional Character'],
        ['addchar5', '1', '2', 'Successfully set after OTP Character'],
        ['2fa', 'g', 'g', 'Successfully set 2FA Type'],
        ['typespeed', '5', '6', 'Successfully set typespeed'],
      ];
      const bad = [];
      for (const [field, pyValue, jsValue, expected] of fields) {
        for (const [who, value] of [[PY, pyValue], [JS, jsValue]]) {
          const x = await exchange(device, who, ['setslot', '1a', field, value], { signal, acks: 1, settleMs: 300 });
          const ok = s.check(who, x.said[0] === expected, `setslot ${field}: the device answered ${short(x.said.join(' | '))}`)
            & relayed(s, who, x, x.said[0])
            & s.check(who, x.result.code === 0, `setslot ${field}: exit ${x.result.code}`);
          if (!ok) bad.push(`${who} ${field}`);
          /* The label is read back after each write: the python value, then onlykey-js's. */
          if (field === 'label') {
            const got = (await kitLabels(device, { signal })).get(1);
            s.check(who, got && got.text === value, `after setslot label ${value} slot 1a holds ${short(got && got.text)}`);
          }
        }
      }
      s.cells.py = `13 fields, ${bad.filter((b) => b.startsWith(PY)).length} wrong`;
      s.cells.js = `13 fields, ${bad.filter((b) => b.startsWith(JS)).length} wrong`;
      s.cells.device = 'each field acknowledged in its own words; label read back';
      s.done();
    });

  it('`setslot` with an unquoted two-word value: python stores one word, onlykey-js refuses',
    async ({ device, assert, signal, log, skip }) => {
      needBoth({ skip });
      const s = sheet(assert, log, 'setslot 3a label My Bank');
      await device.ensureUnlocked(PINS.primary, { signal });
      await kitLabel(device, 3, 'oktbefore', { signal });

      const py = await exchange(device, PY, ['setslot', '3a', 'label', 'My', 'Bank'], { signal, acks: 1 });
      const afterPy = (await kitLabels(device, { signal })).get(3);
      await kitLabel(device, 3, 'oktbefore', { signal });
      const js = await exchange(device, JS, ['setslot', '3a', 'label', 'My', 'Bank'], { signal, settleMs: 1000 });
      const afterJs = (await kitLabels(device, { signal })).get(3);
      s.cells.py = `${cell(py)}; slot holds ${short(afterPy && afterPy.text)}`;
      s.cells.js = `exit ${js.result.code}, nothing sent; slot holds ${short(afterJs && afterJs.text)}`;
      s.cells.device = `py: ${short(py.said.join(' | '))}; js: silent`;

      /* python: the device took "My", and python relayed its success. */
      s.check(PY, py.said[0] === 'Successfully set Label', `the device answered ${short(py.said.join(' | '))}`);
      relayed(s, PY, py, py.said[0]);
      s.check(PY, afterPy && afterPy.text === 'My', `slot 3a holds ${short(afterPy && afterPy.text)}, not "My"`);
      /* onlykey-js: a usage error, before any key is opened. */
      s.check(JS, js.result.code === 2, `exit ${js.result.code}, not 2`);
      s.check(JS, js.reports.map(deviceText).filter(Boolean).length === 0, 'the refused command line reached the device');
      s.check(JS, afterJs && afterJs.text === 'oktbefore', `slot 3a holds ${short(afterJs && afterJs.text)} - it was written`);
      s.intentional('oneValue');
      s.intentional('usageExit');
      s.done();
    });

  it('`wipeslot`: the device wipes ten fields; onlykey-js prints all ten, python as shipped eight',
    async ({ device, assert, signal, log, skip }) => {
      needBoth({ skip });
      const s = sheet(assert, log, 'wipeslot 2a');
      await device.ensureUnlocked(PINS.primary, { signal });

      const results = {};
      for (const who of [PY, JS]) {
        await kitLabel(device, 2, `oktw${who === PY ? 'py' : 'js'}`, { signal });
        const x = await exchange(device, who, ['wipeslot', '2a'], { signal, acks: 10, settleMs: 800 });
        const after = (await kitLabels(device, { signal })).get(2);
        results[who] = x;
        s.check(who, x.said.length === 10 && x.said.every((t) => /^Successfully wiped /.test(t)),
          `the device answered ${x.said.length} times: ${short(x.said.join(' | '))}`);
        s.check(who, after && after.erased, `slot 2a still holds ${short(after && after.text)} after the wipe`);
        s.check(who, x.result.code === 0, `exit ${x.result.code}`);
      }
      const py = results[PY];
      const js = results[JS];
      s.cells.py = `exit ${py.result.code}, ${stdoutLines(py.result.stdout).length} lines`;
      s.cells.js = cell(js);
      s.cells.device = `${py.said.length} acks, "${py.said[0]}" ... "${py.said[py.said.length - 1]}"; slot erased`;

      /*
       * python as shipped reads exactly eight replies (100 ms each) - they must
       * be the device's first eight; bm-ok's python-onlykey 0f50148+ reads until
       * the device goes quiet - all ten. Either way what it prints must be the
       * device's acks, in order. Windows prints \r\n and can add a whitespace-
       * only line; those are console noise, not replies, and are dropped. A
       * truly empty line is still a reply python missed (#9).
       */
      const rawLines = stdoutLines(py.result.stdout).map((l) => l.replace(/\r$/, ''));
      const pyLines = rawLines.filter((l) => l === '' || l.trim() !== '');
      if (py.result.stdout.trim() === '' || pyLines.some((l) => l === '')) {
        s.check(PY, false, `printed ${short(pyLines.join(' / '))} with empty lines where the device answered `
          + `${short(py.said.join(' / '))} - python-onlykey bug #9`);
      } else {
        const n = pyLines.length;
        s.check(PY, (n === 8 || n === py.said.length) && pyLines.join('\n') === py.said.slice(0, n).join('\n'),
          `printed ${n} lines ${short(pyLines.join(' / '))}, the device's acks were ${short(py.said.join(' / '))}`);
        if (n === 8) s.pythonBug('wipeslotEight');
      }
      /*
       * node-onlykey-lib 59ddcdb: wipeSlot collects every reply until the device
       * is quiet, and the CLI prints each one - python-onlykey e6d261c's rule.
       * It used to print only the first and leave nine on the bus.
       */
      const jsLines = js.out.split('\n').map((l) => l.replace(/\r$/, '')).filter((l) => l.trim() !== '');
      s.check(JS, jsLines.join('\n') === js.said.join('\n'),
        `printed ${short(jsLines.join(' / '))}, the device's acks were ${short(js.said.join(' / '))}`);
      s.done();
    });

  /* ================================================================= keys */

  it('`setkey`: refused outside config mode, and stores the key it was given',
    async ({ device, assert, signal, log, skip }) => {
      needBoth({ skip });
      const s = sheet(assert, log, 'setkey ECC1 x s <hex>');
      await outOfConfigMode(device, signal);

      const refused = {};
      for (const who of [PY, JS]) {
        const x = await exchange(device, who, ['setkey', 'ECC1', 'x', 's', SEED_PY], { signal, acks: 1 });
        refused[who] = x;
        s.check(who, x.said[0] === 'Error not in config mode', `outside config mode the device answered ${short(x.said.join(' | '))}`);
        relayed(s, who, x, x.said[0]);
      }
      s.check(PY, refused[PY].result.code === 0, `python exited ${refused[PY].result.code} for a refusal`);
      s.check(JS, refused[JS].result.code === 1, `exit ${refused[JS].result.code} for the device's refusal, not 1`);

      /* Accepted in config mode: python stores vector 1, onlykey-js then stores
       * vector 2 over it, and each is read back as its public half. */
      const stored = {};
      for (const [who, seed] of [[PY, SEED_PY], [JS, SEED_JS]]) {
        await pqc.readyForKeygen(device, { signal });
        const x = await exchange(device, who, ['setkey', 'ECC1', 'x', 's', seed], { signal, acks: 1 });
        stored[who] = x;
        s.check(who, x.said[0] === 'Successfully set ECC Key', `in config mode the device answered ${short(x.said.join(' | '))}`);
        relayed(s, who, x, x.said[0]);
        s.check(who, x.result.code === 0, `exit ${x.result.code}`);
        await outOfConfigMode(device, signal);
        const pub = (await kitPublicKey(device, ECC1, { signal })).subarray(0, 32);
        s.check(who, pub.equals(ed25519PublicKey(seed)),
          `ECC1 publishes ${pub.toString('hex')}, the seed's public half is ${ed25519PublicKey(seed).toString('hex')}`);
      }
      s.cells.py = `refused: ${cell(refused[PY])}; config: ${cell(stored[PY])}`;
      s.cells.js = `refused: ${cell(refused[JS])}; config: ${cell(stored[JS])}`;
      s.cells.device = '"Error not in config mode", then "Successfully set ECC Key"; public key read back';
      s.intentional('refusalExit');
      s.done();
    });

  it('`setkey <slot> label`: names a key slot, not gated',
    async ({ device, assert, signal, log, skip }) => {
      needBoth({ skip });
      const s = sheet(assert, log, 'setkey ECC2 label <text>');
      await device.ensureUnlocked(PINS.primary, { signal });

      const results = {};
      for (const [who, label] of [[PY, 'oktpyk'], [JS, 'oktjsk']]) {
        const x = await exchange(device, who, ['setkey', 'ECC2', 'label', label], { signal, acks: 1 });
        results[who] = x;
        s.check(who, x.said[0] === 'Successfully set Label', `the device answered ${short(x.said.join(' | '))}`);
        relayed(s, who, x, x.said[0]);
        const got = (await kitLabels(device, { keys: true, signal })).get(30);
        s.check(who, got && got.text === label, `ECC Key 2's label is ${short(got && got.text)}, not ${short(label)}`);
      }
      s.cells.py = cell(results[PY]);
      s.cells.js = cell(results[JS]);
      s.cells.device = '"Successfully set Label"; label read back at index 30';
      s.done();
    });

  it('`genkey`: refused outside config mode, and generates a fresh key on the device',
    async ({ device, assert, signal, log, skip }) => {
      needBoth({ skip });
      const s = sheet(assert, log, 'genkey ECC3 x s');
      await outOfConfigMode(device, signal);

      const refused = {};
      for (const who of [PY, JS]) {
        const x = await exchange(device, who, ['genkey', 'ECC3', 'x', 's'], { signal, acks: 1 });
        refused[who] = x;
        s.check(who, x.said[0] === 'Error not in config mode', `outside config mode the device answered ${short(x.said.join(' | '))}`);
        relayed(s, who, x, x.said[0]);
      }
      s.check(JS, refused[JS].result.code === 1, `exit ${refused[JS].result.code} for the device's refusal, not 1`);

      /* genkey HMAC1: python sends an Ed25519 generation to HMAC slot 130; the
       * device refuses it here only because it is not in config mode. */
      const pyHmac = await exchange(device, PY, ['genkey', 'HMAC1', 'x', 'd'], { signal, acks: 1 });
      const jsHmac = await exchange(device, JS, ['genkey', 'HMAC1', 'x', 'd'], { signal, settleMs: 1000 });
      s.check(PY, pyHmac.said.length === 1, `genkey HMAC1: the device answered python ${short(pyHmac.said.join(' | '))}`);
      relayed(s, PY, pyHmac, pyHmac.said[0]);
      s.check(JS, jsHmac.result.code === 2, `genkey HMAC1 exit ${jsHmac.result.code}, not 2`);
      s.check(JS, jsHmac.reports.map(deviceText).filter(Boolean).length === 0, 'genkey HMAC1 reached the device');

      const keys = {};
      for (const who of [PY, JS]) {
        await pqc.readyForKeygen(device, { signal });
        const x = await exchange(device, who, ['genkey', 'ECC3', 'x', 's'], { signal, acks: 1 });
        s.check(who, x.said[0] === 'Successfully set ECC Key', `in config mode the device answered ${short(x.said.join(' | '))}`);
        relayed(s, who, x, x.said[0]);
        s.check(who, x.result.code === 0, `exit ${x.result.code}`);
        await outOfConfigMode(device, signal);
        const reply = await kitPublicKey(device, 103, { signal });
        const pub = reply.subarray(0, 32).toString('hex');
        keys[who] = { x, pub };
        s.check(who, !NO_ECC_KEY.test(deviceText(reply)), `ECC3 is empty after genkey: ${short(deviceText(reply))}`);
        s.check(who, pub !== '00'.repeat(32) && pub !== 'ff'.repeat(32), `ECC3 holds a trivial key ${pub}`);
      }
      s.check(JS, keys[JS].pub !== keys[PY].pub, 'onlykey-js\'s genkey left python\'s key in ECC3 - nothing was generated');
      s.cells.py = `refused: ${cell(refused[PY])}; HMAC1: sent; config: ${cell(keys[PY].x)}`;
      s.cells.js = `refused: ${cell(refused[JS])}; HMAC1: exit ${jsHmac.result.code}, nothing sent; config: ${cell(keys[JS].x)}`;
      s.cells.device = `refusals; HMAC1 -> ${short(pyHmac.said[0])}; "Successfully set ECC Key" x2, two different public keys`;
      s.intentional('refusalExit');
      s.intentional('genkeyEcc');
      s.intentional('usageExit');
      s.done();
    });

  it('`wipekey`: refused outside config mode; in it, the key and its label go',
    async ({ device, assert, signal, log, skip }) => {
      needBoth({ skip });
      const s = sheet(assert, log, 'wipekey ECC1');
      await outOfConfigMode(device, signal);

      const refused = {};
      for (const who of [PY, JS]) {
        const x = await exchange(device, who, ['wipekey', 'ECC1'], { signal, acks: 1, settleMs: 1000 });
        refused[who] = x;
        /* One answer: a refused wipe must not be followed by a label clear. */
        s.check(who, x.said.length === 1 && x.said[0] === 'Error not in config mode',
          `outside config mode the device answered ${short(x.said.join(' | '))}`);
        relayed(s, who, x, x.said[0]);
      }
      s.check(JS, refused[JS].result.code === 1, `exit ${refused[JS].result.code} for the device's refusal, not 1`);

      const wiped = {};
      for (const [who, label] of [[PY, 'oktwkpy'], [JS, 'oktwkjs']]) {
        /* Prepared over the kit's own interface: a label, then a key in config mode. */
        await outOfConfigMode(device, signal);
        await kitLabel(device, ECC1_LABEL_INDEX, label, { signal });
        await pqc.readyForKeygen(device, { signal });
        const since = device.mark(IFACE.VENDOR);
        device.sendVendor({ msg: okmsg.MSG.OKSETPRIV, slot: ECC1, field: TYPE_ED25519_SIGN, payload: Buffer.from(SEED_PY, 'hex') });
        const prep = await device.waitHid(IFACE.VENDOR, { since, match: isAck, timeoutMs: 8000, signal });
        if (!/Successfully set ECC Key/.test(deviceText(prep))) throw new Error(`could not prepare ECC1: ${deviceText(prep)}`);

        const x = await exchange(device, who, ['wipekey', 'ECC1'], { signal, acks: 2, settleMs: 800 });
        wiped[who] = x;
        s.check(who, x.said[0] === 'Successfully wiped ECC Key' && x.said.length === 2,
          `in config mode the device answered ${short(x.said.join(' | '))}`);
        const lines = stdoutLines(x.result.stdout);
        if (who === PY && lines.some((l) => l === '')) {
          s.check(PY, false, `printed ${short(lines.join(' / '))} where the device answered `
            + `${short(x.said.join(' / '))} - python-onlykey bug #9`);
        } else {
          s.check(who, lines.join('\n') === x.said.join('\n'),
            `printed ${short(lines.join(' / '))}, the device answered ${short(x.said.join(' / '))}`);
        }
        s.check(who, x.result.code === 0, `exit ${x.result.code}`);

        await outOfConfigMode(device, signal);
        const reply = deviceText(await kitPublicKey(device, ECC1, { signal }));
        s.check(who, NO_ECC_KEY.test(reply), `ECC1 still publishes a key after the wipe: ${short(reply)}`);
        const got = (await kitLabels(device, { keys: true, signal })).get(ECC1_LABEL_INDEX);
        s.check(who, got && (got.erased || got.text === ''), `ECC Key 1 is still labelled ${short(got && got.text)}`);
      }
      s.cells.py = `refused: ${cell(refused[PY])}; config: ${cell(wiped[PY])}`;
      s.cells.js = `refused: ${cell(refused[JS])}; config: ${cell(wiped[JS])}`;
      s.cells.device = `refusal x1; then ${short(wiped[PY].said.join(' + '))}; key and label gone`;
      s.intentional('refusalExit');
      s.done();
    });

  it('`loadkey`: an armored Ed25519 key file into a named ECC slot',
    async ({ device, assert, signal, log, skip }) => {
      needBoth({ skip });
      const s = sheet(assert, log, 'loadkey <file> ECC4 s');
      const openpgp = require('node-onlykey-lib/crypto/pgp');
      const PASSPHRASE = 'okt-parity-passphrase';

      /* Two different keys, so the second load is visibly a load. Written to a
       * temp dir, never the tree (16-cli-key-files). */
      const tmpdir = fs.mkdtempSync(path.join(os.tmpdir(), 'okt-parity-'));
      const keyFile = async (name) => {
        const { privateKey } = await openpgp.generateKey({
          type: 'ecc', curve: 'curve25519', userIDs: [{ name: 'okt parity', email: 'parity@okt.invalid' }],
          passphrase: PASSPHRASE, format: 'object',
        });
        const file = path.join(tmpdir, name);
        fs.writeFileSync(file, await privateKey.armor(), { mode: 0o600 });
        const pp = privateKey.keyPacket.publicParams;
        const pub = Buffer.from(pp.A || pp.Q.subarray(1));
        return { file, pub };
      };

      try {
        const results = {};
        for (const [who, name] of [[PY, 'py.asc'], [JS, 'js.asc']]) {
          const key = await keyFile(name);
          await pqc.readyForKeygen(device, { signal });
          const x = await exchange(device, who, ['loadkey', key.file, 'ECC4', 's'],
            { signal, acks: 1, input: `${PASSPHRASE}\n`, timeoutMs: 120000 });
          results[who] = x;
          s.check(who, x.said.length === 1 && x.said[0] === 'Successfully set ECC Key',
            `the device answered ${short(x.said.join(' | '))}`);
          const lines = stdoutLines(x.result.stdout).map((l) => l.trim());
          if (who === PY && x.said[0] && !lines.includes(x.said[0])) {
            s.check(PY, false, `did not print the device's ${short(x.said[0])}: ${short(lines.join(' / '), 300)}`
              + (lines.some((l) => l === '') ? ' - python-onlykey bug #9' : ''));
          } else {
            s.check(who, lines.includes(x.said[0]), `did not print the device's ${short(x.said[0])}: ${short(lines.join(' / '), 300)}`);
          }
          s.check(who, x.result.code === 0, `exit ${x.result.code}: ${short(x.result.stderr.trim().split('\n').pop())}`);
          await outOfConfigMode(device, signal);
          const pub = (await kitPublicKey(device, 104, { signal })).subarray(0, 32);
          s.check(who, pub.equals(key.pub), `ECC4 publishes ${pub.toString('hex')}, the file's primary key is ${key.pub.toString('hex')}`);
          log(`${who} loadkey printed: ${short(lines.filter(Boolean).join(' / '), 400)}`);
        }
        s.cells.py = cell(results[PY]);
        s.cells.js = cell(results[JS]);
        s.cells.device = `${short(results[PY].said[0])}; public key read back`;
      } finally {
        fs.rmSync(tmpdir, { recursive: true, force: true });
      }
      s.done();
    });
});
