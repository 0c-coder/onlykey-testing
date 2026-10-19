/*
 * cli.js - running the Python venv's binaries, for section 2.
 *
 * Section 2 tests what a REAL client does, which means running the real client:
 * onlykey-cli, onlykey-agent, age-plugin-onlykey, all out of the okpqc venv
 * beside this checkout. Nothing here reimplements the protocol - that is
 * section 1's job, and the point of having both is that they can disagree.
 *
 * Why this can share a device with the kit at all: with the USB gadget up, the
 * kit's device host holds /dev/hidg* (the device side of the link) and these
 * binaries open /dev/hidraw* (the host side). Opposite ends, different file
 * descriptors, no contention - which is what lets section 2 keep the fixture
 * isolation section 1 has. Against a PHYSICAL key that is not true: there the
 * kit's own adapter holds the same hidraw nodes the CLI wants, and they would
 * steal each other's reports.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');

const { CHECKOUTS_ROOT } = require('./paths');
const { tracked } = require('./device/waits');

/*
 * A Windows venv keeps its programs in Scripts\ as <name>.exe, and has
 * python.exe but no python3.exe. The tests say 'python3' and 'onlykey-cli' on
 * every platform; the mapping lives here, once.
 */
const WIN = process.platform === 'win32';
const VENV_BIN = path.join(CHECKOUTS_ROOT, 'okpqc-venv', WIN ? 'Scripts' : 'bin');

function venvFileName(name) {
  if (!WIN) return name;
  return (name === 'python3' ? 'python' : name) + '.exe';
}

/**
 * The env for a child that must find venv programs on PATH (age plugins,
 * onlykey-agent's helpers): VENV_BIN first, joined with the platform's
 * delimiter. It is set under the name the environment already uses: Windows
 * calls it Path, and adding a second PATH beside it hands the child two
 * variables that differ only in case.
 */
function venvPathEnv() {
  const key = Object.keys(process.env).find((k) => k.toUpperCase() === 'PATH') || 'PATH';
  return { [key]: `${VENV_BIN}${path.delimiter}${process.env[key] || ''}` };
}

/** Absolute path to a venv binary, or an error naming where it looked. */
function binary(name) {
  const file = path.join(VENV_BIN, venvFileName(name));
  if (!fs.existsSync(file)) {
    throw new Error(
      `${name} is not in the venv (looked in ${VENV_BIN}). ` +
      'Run the workspace setup, or point CHECKOUTS_ROOT somewhere that has it.'
    );
  }
  return file;
}

/** Is the venv there at all? Cheap enough to ask before skipping a whole file. */
function venvPresent() {
  return fs.existsSync(VENV_BIN);
}

/**
 * Run a venv binary to completion.
 *
 * Never rejects on a non-zero exit: an exit code is a result, and several of
 * these tests are about the CLI failing correctly. It rejects only when the
 * process could not be run, or outlived its budget.
 *
 * @param {string} name  e.g. 'onlykey-cli'
 * @param {string[]} argv
 * @param {object} [opts] {timeoutMs, signal, pending, input, env}
 * @returns {Promise<{code:number, stdout:string, stderr:string, timedOut:boolean}>}
 */
function run(name, argv = [], opts = {}) {
  return spawn(name, binary(name), argv, opts);
}

/**
 * Run a binary from the HOST's PATH rather than from the venv.
 *
 * The venv is deliberately the default, because "which onlykey-cli answered"
 * has to have one answer. But some of what section 2 drives is not a Python
 * client at all: `onlykey-gpg init` shells out to the system `gpg` throughout,
 * so a test that wants to read back what it imported has to run the same gpg it
 * did - and the one it did is whatever is on PATH.
 *
 * Kept as a separate call rather than a fallback inside run(), so that a typo
 * in a venv binary's name stays an error naming the venv instead of silently
 * finding something else with the same name.
 */
function runHost(name, argv = [], opts = {}) {
  return spawn(name, name, argv, opts);
}

/** Is a host binary on PATH? Used to state a skip rather than fail obscurely. */
function hostBinaryPresent(name) {
  /* Windows finds `gpg` as gpg.exe (PATHEXT); look the way it will. */
  const exts = WIN ? ['', ...(process.env.PATHEXT || '.EXE;.CMD;.BAT').split(';')] : [''];
  const key = Object.keys(process.env).find((k) => k.toUpperCase() === 'PATH') || 'PATH';
  return (process.env[key] || '').split(path.delimiter).some((dir) => exts.some((ext) => {
    try { return fs.statSync(path.join(dir, name + ext)).isFile(); } catch { return false; }
  }));
}

/**
 * Is there a gpg that lib-agent can drive? null if so, else why not.
 *
 * lib-agent finds gpg by asking `gpgconf --list-components` and then runs the
 * path it reports. On Windows the gpg on a Git Bash PATH is Git's own MSYS
 * build, whose gpgconf answers `/usr/bin/gpg` - a path native Windows Python
 * cannot execute (FileNotFoundError, WinError 2; measured 2026-09-29). So on
 * Windows the question is whether gpgconf reports a Windows path, not whether
 * a `gpg` is on PATH.
 */
function gpgUnusableWhy() {
  if (!hostBinaryPresent('gpg')) return 'no gpg on PATH';
  if (!WIN) return null;
  let out = '';
  try {
    out = require('child_process').execFileSync('gpgconf', ['--list-components'],
      { encoding: 'utf8', timeout: 15000, windowsHide: true });
  } catch (err) {
    return `gpgconf did not run: ${err.message}`;
  }
  const line = out.split(/\r?\n/).find((l) => l.startsWith('gpg:')) || '';
  /* gpgconf percent-escapes its fields: a native Windows GnuPG reports
   * `C%3a\Program Files\GnuPG\bin\gpg.exe`. Read without unescaping, that was
   * taken for the MSYS gpg and the test skipped. */
  const gpgPath = line.split(':').slice(2).join(':')
    .replace(/%([0-9a-fA-F]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
  if (/^[A-Za-z]:[\\/]/.test(gpgPath)) return null;
  return `the gpg on PATH reports ${gpgPath || 'no path'} - Git for Windows' MSYS gpg, which ` +
    'native Windows programs (lib-agent) cannot run; install GnuPG for Windows ' +
    '(winget install GnuPG.GnuPG) to include this test';
}

/*
 * onlykey-js - node-onlykey-lib's own CLI, the candidate replacement for
 * onlykey-cli.
 *
 * It is not in the venv and not on PATH: it is the lib's package.json "bin",
 * and the kit already depends on that lib, so the copy under node_modules is
 * the one the kit's pin names. It is run as `node <entry>` with THIS node
 * (process.execPath) rather than through a .bin shim, so the same program runs
 * on Windows and Linux and no npm link step is needed.
 *
 * node-hid is the lib's OPTIONAL peer - the lib does not install it - so its
 * absence is a reason to skip, stated by libCliMissing(), not a failure.
 * Note that a plain `npm install` in the kit prunes a --no-save node-hid.
 */
function libCliEntry() {
  let pkgFile;
  try {
    pkgFile = require.resolve('node-onlykey-lib/package.json');
  } catch {
    throw new Error('node-onlykey-lib is not installed in the kit - run npm install');
  }
  const pkg = require(pkgFile);
  const bin = typeof pkg.bin === 'string' ? pkg.bin : (pkg.bin || {})['onlykey-js'];
  if (!bin) throw new Error(`node-onlykey-lib ${pkg.version} has no onlykey-js bin`);
  return path.join(path.dirname(pkgFile), bin);
}

/** Why onlykey-js cannot run here, or null when it can. */
function libCliMissing() {
  try {
    libCliEntry();
  } catch (err) {
    return err.message;
  }
  try {
    require.resolve('node-hid');
  } catch {
    return 'node-hid is not installed (the lib\'s optional peer): npm install --no-save node-hid';
  }
  return null;
}

/**
 * Run onlykey-js to completion. Same contract as run(): the same result shape,
 * never rejects on a non-zero exit, and cancellation kills the child.
 */
function runLib(argv = [], opts = {}) {
  return spawn('onlykey-js', process.execPath, argv, opts, [libCliEntry()]);
}

function spawn(label, file, argv = [], opts = {}, leading = []) {
  const { timeoutMs = 30000 } = opts;

  return tracked(
    `${label} ${argv.join(' ')}`,
    { timeoutMs: 0, signal: opts.signal, pending: opts.pending },
    (resolve, reject) => {
      const child = execFile(file, [...leading, ...argv], {
        timeout: timeoutMs,
        killSignal: 'SIGKILL',
        encoding: 'utf8',
        env: { ...process.env, ...(opts.env || {}) },
      }, (err, stdout, stderr) => {
        /*
         * execFile's `err` conflates three things: the binary would not run,
         * it exited non-zero, and it was killed for taking too long. Only the
         * first is this function's problem.
         */
        if (err && err.code === 'ENOENT') {
          return reject(new Error(`${label} could not be executed: ${err.message}`));
        }
        const timedOut = !!(err && err.killed);
        return resolve({
          code: err && typeof err.code === 'number' ? err.code : (err ? 1 : 0),
          stdout: stdout || '',
          stderr: stderr || '',
          timedOut,
        });
      });

      if (opts.input !== undefined && child.stdin) {
        child.stdin.end(opts.input);
      }

      /* Cancellation has to reach the child, or a timed-out test leaves a
       * python process holding the device open for the next one. */
      return () => { try { child.kill('SIGKILL'); } catch { /* already gone */ } };
    }
  );
}

module.exports = {
  run, runHost, runLib, hostBinaryPresent, gpgUnusableWhy, binary, venvPresent, venvPathEnv, VENV_BIN,
  libCliEntry, libCliMissing,
};
