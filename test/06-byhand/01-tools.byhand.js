'use strict';
/*
 * 06-byhand / 01 - the tools against a real key, with a person only at the buttons.
 *
 * Run it with `okt byhand` (never part of `okt run`; see lib/byhand.js). Each
 * step runs the actual program a user runs - python onlykey-cli, lib-agent's
 * onlykey-agent and onlykey-gpg, onlykey-js - straight at the physical key,
 * then checks what came back against an independent tool (ssh-keygen, gpg) or
 * against the other implementation. The kit cannot do this with `--hardware`:
 * its adapter holds the key's hidraw nodes, and only a person can press.
 *
 * What it proves, beyond the emulator runs of sections 2-4: that each tool's
 * real USB path works on hardware, and that the python and Node tools agree
 * on the SAME key - same firmware version, same slot labels, same derived SSH
 * key, same derived GPG fingerprint - and that their signatures verify.
 *
 * Every step also returns a RESULT value, compared with baseline.json beside
 * this file (a passing run of every step, saved with --save-baseline), so a
 * later run that answers differently fails on that step. Values that belong
 * to one key's secret (the derived SSH key, the GPG fingerprint) are only
 * compared tool against tool: a flash makes a new secret.
 *
 * The key must be a developer key the kit has set up (`okt run 00-sanity
 * --hardware` leaves it initialized with the kit's PIN). Nothing here writes
 * a slot, a key or a setting; derived keys only. Scratch files live in a
 * temporary folder that is removed at the end, with any agent left running.
 */

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const cli = require('../../lib/cli');
const { PINS } = require('../../lib/config');

const SSH_ID = 'byhand@onlykey.example';
const GPG_ID = 'OKT Byhand <byhand@onlykey.example>';
const GPG_TIME = '1700000000';          // the same creation time for both tools, so one fingerprint
const VERSION = /v3\.1\.0/;

const py = (name, args, extra = {}) => ({ cmd: cli.binary(name), args, env: cli.venvPathEnv(), ...extra });
const js = (args, extra = {}) => ({ cmd: process.execPath, args: [cli.libCliEntry(), ...args], env: cli.venvPathEnv(), ...extra });
const ok = (out) => (out.code === 0 ? null : `exit ${out.code}`);
const pinButtons = (pin) => pin.split('').map((d) => `button ${d}`).join(', ');
const sshKey = (text) => (/(ssh-ed25519 [A-Za-z0-9+/=]+)/.exec(text) || [])[1];

/* The version a tool printed on stdout. Not \S*: python-onlykey's DEBUG log (stderr)
 * carries the raw reply, NUL padding and all, and must not be read as the answer. */
const printedVersion = (out) => (/v\d+\.\d+\.\d+(?:-[A-Za-z0-9]+)?/.exec(out.stdout) || [])[0];

/*
 * The slot labels a tool printed, as one comparable list: python pads an
 * empty label with spaces, onlykey-js writes "<empty>"; both mean "".
 */
function printedLabels(out) {
  const labels = [];
  for (const line of out.stdout.split(/\r?\n/)) {
    const m = /^\s*Slot\s+(\d+[ab]):\s?(.*)$/i.exec(line);
    if (m) labels.push(`${m[1]}=${m[2].trim() === '<empty>' ? '' : m[2].trim()}`);
  }
  return labels;
}

function verifySsh(ctx, sig) {
  const allowed = path.join(ctx.work, 'allowed_signers');
  fs.writeFileSync(allowed, `${SSH_ID} ${ctx.saved.sshKey}\n`);
  const r = spawnSync('ssh-keygen', ['-Y', 'verify', '-f', allowed, '-I', SSH_ID, '-n', 'file', '-s', sig],
    { input: fs.readFileSync(path.join(ctx.work, 'message.txt')), encoding: 'utf8' });
  ctx.note(`  ssh-keygen -Y verify: ${(r.stdout + r.stderr).trim()}`);
  return r.status === 0 ? null : `ssh-keygen -Y verify refused it: ${(r.stdout + r.stderr).trim()}`;
}

function gpgFingerprint(homedir) {
  const r = spawnSync('gpg', ['--homedir', homedir, '--list-keys', '--with-colons', GPG_ID], { encoding: 'utf8' });
  return ((r.stdout || '').split('\n').find((l) => l.startsWith('fpr:')) || '').split(':')[9] || null;
}

function sshSignStep(id, tool, cmdFor) {
  return {
    id,
    title: `${tool}: sign a file over SSH, verified by ssh-keygen`,
    press: true,
    explain: `
      Starts ${tool} as the ssh-agent for ${SSH_ID} and has ssh-keygen sign a file through it.
      The tool prints "Confirm on the OnlyKey ..." and the person presses. Then ssh-keygen
      verifies the signature against the public key the key derived.`,
    run(ctx) {
      fs.writeFileSync(path.join(ctx.work, 'message.txt'), `signed by hand, ${new Date().toISOString()}\n`);
      fs.writeFileSync(path.join(ctx.work, 'id.pub'), `${ctx.saved.sshKey} ${SSH_ID}\n`);
      fs.rmSync(path.join(ctx.work, 'message.txt.sig'), { force: true });
      return cmdFor(['--', 'ssh-keygen', '-Y', 'sign', '-n', 'file', '-f', path.join(ctx.work, 'id.pub'),
        path.join(ctx.work, 'message.txt')]);
    },
    check(out, ctx) {
      if (!ctx.saved.sshKey) return 'no public key from the earlier step';
      if (out.code !== 0) return `exit ${out.code}`;
      const sig = path.join(ctx.work, 'message.txt.sig');
      if (!fs.existsSync(sig)) return 'no signature file was written';
      return verifySsh(ctx, sig);
    },
    result: () => 'signature verified by ssh-keygen',
  };
}

function gpgInitStep(id, tool, dirName, cmdFor) {
  return {
    id,
    title: `${tool}: gpg init a derived identity`,
    press: true,
    perDevice: true,
    explain: `
      Creates a GnuPG home for "${GPG_ID}" whose key is derived in the OnlyKey. It signs
      twice (the key and its encryption subkey); the person presses at each prompt.`,
    run(ctx) {
      const homedir = path.join(ctx.work, dirName);
      (ctx.cleanup = ctx.cleanup || []).push(homedir);
      return cmdFor(homedir);
    },
    check(out, ctx) {
      if (out.code !== 0) return `exit ${out.code}`;
      const fpr = gpgFingerprint(path.join(ctx.work, dirName));
      if (!fpr) return 'gpg holds no key for that user id afterwards';
      ctx.saved[`${dirName}Fpr`] = fpr;
      return null;
    },
    result: (out, ctx) => ctx.saved[`${dirName}Fpr`],
  };
}

const steps = [
  {
    id: 'unlock',
    title: 'unlock the key',
    press: true,
    explain: `
      onlykey-js reads the key's status once and stops the run if no key answers. Then the
      person is asked to unlock it with the kit's PIN (${PINS.primary}) and press Enter - the
      only Enter of the run - and the status is read again: it must say unlocked.`,
    waitFor: () => ({
      ...js(['status']),
      expectFirst(out) {
        if (out.code !== 0 || !/state\s+\S/i.test(out.text)) return `no key answered: ${out.text.trim().split('\n').pop() || `exit ${out.code}`}`;
        return null;   // locked or already unlocked: either way the person is asked, and it is read after Enter
      },
      prompt: `unlock the key: PIN ${PINS.primary} (${pinButtons(PINS.primary)})`,
      enterWhenDone: 'When the key is unlocked, press Enter...',
      until: (out) => out.code === 0 && /state\s+unlocked/i.test(out.text),
    }),
    check: (out) => (/state\s+unlocked/i.test(out.text) ? null : 'the key does not report unlocked'),
    result: () => 'unlocked',
  },
  {
    id: 'py-fwversion',
    title: 'python onlykey-cli: firmware version',
    press: false,
    explain: 'Reads the firmware version through python-onlykey. It must be v3.1.0.',
    run: () => py('onlykey-cli', ['fwversion']),
    check: (out) => ok(out) || (VERSION.test(printedVersion(out) || '') ? null : 'not v3.1.0'),
    after: (out, ctx) => { ctx.saved.pyVersion = printedVersion(out); },
    result: (out) => printedVersion(out),
  },
  {
    id: 'js-fwversion',
    title: 'onlykey-js: firmware version, the same as python\'s',
    press: false,
    explain: 'The same question through onlykey-js (node-onlykey-lib). Both tools must report the same string.',
    run: () => js(['fwversion']),
    check(out, ctx) {
      const v = printedVersion(out);
      if (out.code !== 0) return `exit ${out.code}`;
      if (!v || !VERSION.test(v)) return 'not v3.1.0';
      return v === ctx.saved.pyVersion ? null : `python said ${ctx.saved.pyVersion}, onlykey-js says ${v}`;
    },
    result: (out) => printedVersion(out),
  },
  {
    id: 'py-getlabels',
    title: 'python onlykey-cli: slot labels',
    press: false,
    explain: 'Lists the labels of the key\'s 12 slots through python-onlykey.',
    run: () => py('onlykey-cli', ['getlabels']),
    check: (out) => ok(out) || (printedLabels(out).length === 12 ? null : `expected 12 slots, read ${printedLabels(out).length}`),
    after: (out, ctx) => { ctx.saved.pyLabels = printedLabels(out); },
    result: (out) => printedLabels(out),
  },
  {
    id: 'js-getlabels',
    title: 'onlykey-js: slot labels, the same as python\'s',
    press: false,
    explain: 'The same list through onlykey-js; slot by slot it must match python\'s (an empty label prints differently).',
    run: () => js(['getlabels']),
    check(out, ctx) {
      if (out.code !== 0) return `exit ${out.code}`;
      const mine = printedLabels(out);
      return JSON.stringify(mine) === JSON.stringify(ctx.saved.pyLabels)
        ? null : `python ${JSON.stringify(ctx.saved.pyLabels)}, onlykey-js ${JSON.stringify(mine)}`;
    },
    result: (out) => printedLabels(out),
  },
  {
    id: 'py-wink',
    title: 'python onlykey-cli: wink the LED',
    press: false,
    explain: 'Asks the key to flash its LED; the key taking the command (exit 0) is what is checked.',
    audit: 'the LED flash itself cannot be seen from here; exit 0 means the key took the command',
    run: () => py('onlykey-cli', ['wink']),
    check: ok,
    result: (out) => `exit ${out.code}`,
  },
  {
    id: 'agent-pubkey',
    title: 'lib-agent onlykey-agent: the SSH public key for an identity',
    press: false,
    perDevice: true,
    explain: `Prints the Ed25519 SSH key the key derives for ${SSH_ID}. A public key needs no press.`,
    run: () => py('onlykey-agent', [SSH_ID]),
    check: (out) => ok(out) || (sshKey(out.text) ? null : 'no ssh-ed25519 line in the output'),
    after: (out, ctx) => { ctx.saved.sshKey = sshKey(out.text); },
    result: (out) => sshKey(out.text),
  },
  {
    id: 'js-agent-pubkey',
    title: 'onlykey-js agent: the same SSH key as lib-agent',
    press: false,
    explain: 'The same identity through onlykey-js. It must be the same public key, byte for byte.',
    run: () => js(['agent', SSH_ID]),
    check(out, ctx) {
      if (out.code !== 0) return `exit ${out.code}`;
      const key = sshKey(out.text);
      if (!key) return 'no ssh-ed25519 line in the output';
      return key === ctx.saved.sshKey ? null : 'onlykey-js derives a different key than lib-agent';
    },
    result: () => 'the same key as lib-agent',
  },
  sshSignStep('agent-sign', 'lib-agent onlykey-agent', (rest) => py('onlykey-agent', [SSH_ID, ...rest])),
  sshSignStep('js-agent-sign', 'onlykey-js agent', (rest) => js(['agent', SSH_ID, ...rest])),
  gpgInitStep('gpg-init', 'lib-agent onlykey-gpg', 'gpg-libagent',
    (homedir) => py('onlykey-gpg', ['init', GPG_ID, '-t', GPG_TIME, '--homedir', homedir])),
  {
    id: 'gpg-sign',
    title: 'gpg: clear-sign a file with the derived key, and verify it',
    press: true,
    pressUpFront: 'gpg signs through the OnlyKey agent, which prints no prompt here',
    explain: `
      gpg signs a file through the agent onlykey-gpg set up, and the person presses.
      Then gpg verifies the signature with the public key it imported.`,
    run(ctx) {
      fs.writeFileSync(path.join(ctx.work, 'gpg-message.txt'), `signed by hand, ${new Date().toISOString()}\n`);
      return { cmd: 'gpg', args: ['--homedir', path.join(ctx.work, 'gpg-libagent'), '--batch', '--yes',
        '--clearsign', '-o', path.join(ctx.work, 'gpg-message.asc'), path.join(ctx.work, 'gpg-message.txt')],
      env: cli.venvPathEnv() };
    },
    check(out, ctx) {
      if (out.code !== 0) return `exit ${out.code}`;
      const r = spawnSync('gpg', ['--homedir', path.join(ctx.work, 'gpg-libagent'), '--verify',
        path.join(ctx.work, 'gpg-message.asc')], { encoding: 'utf8' });
      ctx.note(`  gpg --verify: ${(r.stderr || '').trim().split('\n').filter((l) => /signature|using/i.test(l)).join(' / ')}`);
      return r.status === 0 ? null : `gpg --verify refused it: ${(r.stderr || '').trim().split('\n').pop()}`;
    },
    result: () => 'signature verified by gpg',
  },
  gpgInitStep('js-gpg-init', 'onlykey-js gpg', 'gpg-onlykeyjs',
    (homedir) => js(['gpg', 'init', GPG_ID, '-t', GPG_TIME, '--homedir', homedir])),
  {
    id: 'gpg-parity',
    title: 'the same GPG fingerprint from both tools',
    press: false,
    explain: 'Same user id, same creation time, same key: lib-agent and onlykey-js must make the same key.',
    run: null,
    check(out, ctx) {
      const a = ctx.saved['gpg-libagentFpr'];
      const b = ctx.saved['gpg-onlykeyjsFpr'];
      if (!a || !b) return 'one of the gpg init steps did not run';
      return a === b ? null : `lib-agent ${a}, onlykey-js ${b}`;
    },
    result: () => 'the same fingerprint from both tools',
  },
];

module.exports = { name: '06-byhand/01-tools', steps };
