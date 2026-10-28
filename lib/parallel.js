'use strict';
/*
 * `okt run --jobs <n|auto>`: the test files on several soft keys at once (Brad, 2026-10-28: "testing could be faster,
 * can we use more than 1 core at a time? if i have 4 cores, it should use 3 cores for test while 1 core for managing
 * testing"). `auto` is one worker per core but one: the core left over is this manager's.
 *
 * WHY FILES, AND WHY PROCESSES. Every file already starts from a fixture of its own in a device session of its own (its
 * run folder, its storage, its socket - lib/runner.js runOneFile), so no file depends on another having run, and the
 * emulator maps its flash per process. A worker is a plain `okt run <file>` child: the runner, the watchdogs and the
 * reporter each see one file exactly as they do in a serial run, and nothing in them had to learn about concurrency.
 * Each slot takes the next file the moment its last one ends, so a long file never holds up the others.
 *
 * NEVER SILENT: every child line is passed on at once, prefixed with its slot ([1] ...), and a line a minute says which
 * file each slot is in and how long since it last spoke.
 *
 * THE VERDICT IS A SERIAL RUN'S: one OKT-END line in the same shape, the counts added up. A failing test stops new files
 * from starting, as it ends a serial run (--keep-going runs on past it); anything that says the instrument broke - the
 * device host died, a watchdog, a firmware crash, a runner error - stops the other slots too, since what they measure
 * after that is the breakage. The fixture cache is shared: a fixture two slots build at once is assembled beside its
 * target and renamed into place (lib/fixtures), so the later rename only replaces it with the same images.
 */
const os = require('os');
const path = require('path');
const readline = require('readline');
const { spawn } = require('child_process');
const { resolveTargets, list } = require('./runner');

/*
 * ONE BUS AT A TIME. A file that needs the USB gadget (lib/runner.js NEEDS_BUS - the CLI, the GUIs, the App) raises
 * the one gadget the machine has, so those files take turns in a lane of their own while the rest run beside them.
 */
const NEEDS_BUS = ['kernel-hid', 'client-access', 'client-lend', 'bus-detach'];
const { EXIT } = require('./report');

const OKT = path.join(__dirname, '..', 'bin', 'okt.js');
const TEST_ROOT = path.join(__dirname, '..', 'test');
const END_RE = /--- OKT-END status=(\S+) code=(\d+) tests=(\d+)p\/(\d+)f\/(\d+)s elapsed=\d+s reason=("(?:[^"\\]|\\.)*")/;
const HEARTBEAT_MS = 60 * 1000;

/** `auto`: one worker per core but one (the manager's); else the number, at least 1 */
function jobsFrom(value) {
  const cores = typeof os.availableParallelism === 'function' ? os.availableParallelism() : os.cpus().length;
  if (value === 'auto') return Math.max(1, cores - 1);
  const n = parseInt(value, 10);
  return Number.isFinite(n) && n > 0 ? n : 1;
}

async function runParallel(opts) {
  const { targets = [], jobs, keepGoing = false, timeoutMs, filter, reverse = false } = opts;
  const startedAt = Date.now();
  const say = (line) => process.stdout.write(`${line}\n`);
  const end = (status, code, counts, reason) => {
    say(`--- OKT-END status=${status} code=${code} tests=${counts.p}p/${counts.f}f/${counts.s}s ` +
      `elapsed=${Math.round((Date.now() - startedAt) / 1000)}s reason=${JSON.stringify(reason)} ---`);
    return code;
  };

  let files;
  try {
    files = resolveTargets(targets);
  } catch (err) {
    return end('aborted', EXIT.RUNNER_ERROR, { p: 0, f: 0, s: 0 }, err.message);
  }
  if (!files.length) return end('aborted', EXIT.RUNNER_ERROR, { p: 0, f: 0, s: 0 }, 'no test files matched');
  /* what each file needs, read as the serial run reads it; a file that will not load ends the run, as it would there */
  const usesBus = new Set();
  const entries = list(targets);
  for (const [i, entry] of entries.entries()) {
    if (!entry.ok) return end('aborted', EXIT.RUNNER_ERROR, { p: 0, f: 0, s: 0 }, `could not load ${entry.file}: ${entry.error}`);
    const requires = (entry.suites[0] && entry.suites[0].meta && entry.suites[0].meta.requires) || [];
    if (requires.some((r) => NEEDS_BUS.includes(r))) usesBus.add(files[i]);
  }

  const cores = typeof os.availableParallelism === 'function' ? os.availableParallelism() : os.cpus().length;
  const slots = Math.min(jobs, files.length);
  say(`okt: ${files.length} files on ${slots} worker(s) - ${cores} core(s), one left to this manager` +
    (usesBus.size ? `; ${usesBus.size} that use the USB gadget take turns` : ''));

  const queue = files.slice();
  const order = new Map(files.map((f, i) => [f, i]));
  const running = new Map();   // slot -> {file, rel, child, startedAt, lastOutput, end, killed}
  const results = [];
  let stop = null;             // why no new file starts
  let broken = false;          // the instrument broke: the other slots were stopped too

  const heartbeat = setInterval(() => {
    const now = Date.now();
    const busy = [...running.entries()].map(([slot, j]) =>
      `[${slot}] ${j.rel} ${Math.round((now - j.startedAt) / 1000)}s (quiet ${Math.round((now - j.lastOutput) / 1000)}s)`);
    const sum = results.reduce((a, r) => ({ p: a.p + r.p, f: a.f + r.f }), { p: 0, f: 0 });
    say(`[okt] ${new Date().toISOString().slice(11, 19)} ${results.length}/${files.length} files done, ` +
      `${sum.p} passed, ${sum.f} failed - ${busy.join('; ') || 'no slot busy'}`);
  }, HEARTBEAT_MS);

  const stopAll = (signal) => {
    for (const j of running.values()) { j.killed = true; j.child.kill(signal); }
  };
  const onSignal = (sig) => { stop = stop || `stopped by ${sig}`; broken = true; stopAll('SIGTERM'); };
  process.once('SIGINT', onSignal);
  process.once('SIGTERM', onSignal);

  await new Promise((resolve) => {
    const free = new Set(Array.from({ length: slots }, (_, i) => i + 1));
    /* the next file a free slot may take: the first in order, but not a bus file while another holds the bus */
    const nextFile = () => {
      const busBusy = [...running.values()].some((j) => usesBus.has(j.file));
      const i = queue.findIndex((f) => !(busBusy && usesBus.has(f)));
      return i < 0 ? null : queue.splice(i, 1)[0];
    };
    const fill = () => {
      while (!stop && free.size) {
        const file = nextFile();
        if (!file) break;
        const slot = Math.min(...free);
        free.delete(slot);
        start(slot, file);
      }
      if (!running.size && (stop || !queue.length)) resolve();
    };
    const start = (slot, file) => {
      const rel = path.relative(TEST_ROOT, file);
      const argv = [OKT, 'run', file];
      if (timeoutMs) argv.push('--timeout', String(timeoutMs));
      if (filter) argv.push('--test', filter);
      if (reverse) argv.push('--reverse');
      const child = spawn(process.execPath, argv, { stdio: ['ignore', 'pipe', 'pipe'], env: process.env });
      const job = { file, rel, child, startedAt: Date.now(), lastOutput: Date.now(), end: null, killed: false };
      running.set(slot, job);
      for (const stream of [child.stdout, child.stderr]) {
        readline.createInterface({ input: stream }).on('line', (line) => {
          job.lastOutput = Date.now();
          const m = END_RE.exec(line);
          if (m) job.end = m;
          say(`[${slot}] ${line}`);
        });
      }
      child.on('close', (code, signal) => {
        running.delete(slot);
        const m = job.end;
        const r = {
          file, rel, killed: job.killed,
          status: m ? m[1] : 'aborted',
          code: m ? Number(m[2]) : (code === null ? EXIT.HOST_DIED : code || EXIT.HOST_DIED),
          p: m ? Number(m[3]) : 0, f: m ? Number(m[4]) : 0, s: m ? Number(m[5]) : 0,
          secs: Math.round((Date.now() - job.startedAt) / 1000),
          reason: m ? JSON.parse(m[6]) : `ended without its OKT-END line (${signal ? `signal ${signal}` : `exit ${code}`})`,
        };
        results.push(r);
        say(`[${slot}] === ${rel}: ${r.p}p/${r.f}f/${r.s}s, exit ${r.code}, ${r.secs}s${r.killed ? ' (stopped)' : ''}`);
        if (r.code !== EXIT.PASS && !r.killed) {
          const testFailure = r.code === EXIT.TEST_FAILURE && r.status === 'finished';
          if (!testFailure) {
            stop = stop || `${rel}: ${r.reason}`;
            broken = true;
            stopAll('SIGTERM');
          } else if (!keepGoing) {
            stop = stop || `${rel}: ${r.reason}`;
          }
        }
        free.add(slot);
        fill();
      });
    };
    fill();
  });
  clearInterval(heartbeat);
  process.removeListener('SIGINT', onSignal);
  process.removeListener('SIGTERM', onSignal);

  /* the files in their own order: what each did, then what never started */
  results.sort((a, b) => order.get(a.file) - order.get(b.file));
  say('\nokt: per file');
  for (const r of results) say(`  ${r.code === EXIT.PASS ? 'ok  ' : r.killed ? 'stop' : 'FAIL'} ${r.rel}  ${r.p}p/${r.f}f/${r.s}s  ${r.secs}s`);
  if (queue.length) say(`  not started (${queue.length}): ${queue.map((f) => path.relative(TEST_ROOT, f)).join(', ')}`);

  const counts = results.reduce((a, r) => ({ p: a.p + r.p, f: a.f + r.f, s: a.s + r.s }), { p: 0, f: 0, s: 0 });
  const failing = results.filter((r) => r.code !== EXIT.PASS && !r.killed);
  if (broken) {
    const first = failing.find((r) => !(r.code === EXIT.TEST_FAILURE && r.status === 'finished')) || failing[0];
    return end(first ? first.status : 'aborted', first ? first.code : EXIT.RUNNER_ERROR, counts, stop);
  }
  if (failing.length) {
    return end('finished', EXIT.TEST_FAILURE, counts,
      `${counts.f} test(s) failed in ${failing.map((r) => r.rel).join(', ')}`);
  }
  return end('finished', EXIT.PASS, counts, 'all tests passed');
}

module.exports = { runParallel, jobsFrom };
