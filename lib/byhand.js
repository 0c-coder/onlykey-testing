'use strict';
/*
 * byhand.js - section 06: the real tools against a real key, with a person
 * only at the buttons.
 *
 * WHY IT EXISTS. `okt run --hardware` drives a physical key through the kit's
 * own adapter, which holds every /dev/hidraw node of the key - so section 2
 * (the CLIs) and sections 3-4 (the GUIs) cannot run against hardware: a CLI
 * needs the same nodes, and two clients would fight over one device. And on a
 * physical key only a person can press. This section steps aside entirely:
 * the kit opens nothing, and each step runs the actual tool (python
 * onlykey-cli, lib-agent, onlykey-js, gpg, ssh-keygen) as a user would.
 *
 * THE PERSON ONLY PRESSES (owner, 2026-10-19: "i just want to run it, and see
 * PRESS NOW in red so i press ... if it fails it should stop so you can
 * review"). No questions and no Enter between steps: the run goes straight
 * through, shows a red PRESS NOW when the key needs a finger (and the PIN at
 * the start), and stops at the first failure. Anything only a person could
 * judge is written to the log for the reviewer instead of being asked.
 *
 * IT NEVER RUNS WITH THE OTHERS. Its files are `*.byhand.js`, and the runner
 * only ever loads `*.test.js` (lib/runner.js filesIn), so `okt run` - with or
 * without targets - cannot pick them up. It runs only as `okt byhand`.
 *
 * A step file exports { name, steps: [step, ...] }. A step:
 *   id        short name, for --only
 *   title     one line
 *   press     true = the key will want a press during this step
 *   explain   what it does (to the log; the terminal shows the title)
 *   run(ctx)  -> { cmd, args, env?, cwd?, timeoutMs? }, or null
 *   check(out, ctx) -> null when the result is right, else why not. `out` is
 *             { code, stdout, stderr, text } (text = both streams)
 *   audit     a note for the reviewer: what to read in this step's output
 *   after(out, ctx) keeps what later steps need (a public key, a fingerprint)
 *   result(out, ctx) -> the step's outcome as a plain value (a version, the
 *             labels, 'verified') - recorded in the report and compared with
 *             test/06-byhand/baseline.json, so a later run that answers
 *             differently fails on that step
 *   perDevice true when the value belongs to one key's secret (a derived SSH
 *             key, a GPG fingerprint): recorded, never compared with the
 *             baseline - a flash makes a new secret - only with the other tool
 *   waitFor   { cmd, args, env, until(out), everyMs, timeoutMs, prompt } -
 *             repeat a read until it says what it should (the PIN step)
 *
 * Everything shown goes to runs/byhand-<time>.log as it happens, copied to
 * runs/byhand-latest.log at the end; the results to runs/byhand-<time>.json.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn, spawnSync } = require('child_process');
const { RUNS_ROOT } = require('./paths');

const BYHAND_ROOT = path.join(__dirname, '..', 'test', '06-byhand');
const BASELINE = path.join(BYHAND_ROOT, 'baseline.json');
const BAR = '-'.repeat(72);

function loadBaseline() {
  try { return JSON.parse(fs.readFileSync(BASELINE, 'utf8')); } catch { return null; }
}

/* What a tool prints when it is waiting for the key's button. */
const PRESS_PROMPT = /Confirm on (the )?OnlyKey|press any button|enter \d \d \d|Touch (the|your) (OnlyKey|key)/i;

/* Red on the terminal (a bell too), plain in the log. */
const RED = (s) => (process.stdout.isTTY ? `\x07\x1b[1;37;41m ${s} \x1b[0m` : `*** ${s} ***`);

/*
 * The transcript: everything on the terminal also goes to the log file, with
 * appendFileSync so a run stopped with Ctrl-C keeps everything up to there.
 */
let transcript = null;
function record(text) { if (transcript) fs.appendFileSync(transcript, text); }
function say(line = '') { console.log(line); record(`${line}\n`); }
function note(line = '') { record(`${line}\n`); }
function pressNow(what) {
  console.log(`\n  ${RED(`PRESS NOW${what ? ` - ${what}` : ''}`)}\n`);
  record(`\n  *** PRESS NOW${what ? ` - ${what}` : ''} ***\n\n`);
}

function stepFiles() {
  if (!fs.existsSync(BYHAND_ROOT)) return [];
  return fs.readdirSync(BYHAND_ROOT).filter((f) => f.endsWith('.byhand.js')).sort()
    .map((f) => path.join(BYHAND_ROOT, f));
}

/**
 * Run a command, its output shown live and captured, and a red PRESS NOW
 * each time it prints a press prompt. Never rejects.
 */
function runLive({ cmd, args = [], env, cwd, timeoutMs = 180000 }) {
  return new Promise((resolve) => {
    let stdout = '';
    let stderr = '';
    let text = '';
    let prompts = 0;
    const child = spawn(cmd, args, {
      cwd, env: { ...process.env, ...(env || {}) }, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true,
    });
    const timer = setTimeout(() => {
      text += `\n[byhand] gave up after ${Math.round(timeoutMs / 1000)} s\n`;
      child.kill();
    }, timeoutMs);
    const take = (stream, sink) => (d) => {
      const s = d.toString();
      if (stream === 'out') stdout += s; else stderr += s;
      text += s;
      sink.write(s);
      record(s);
      const seen = (text.match(new RegExp(PRESS_PROMPT.source, 'gi')) || []).length;
      if (seen > prompts) { prompts = seen; pressNow(); }
    };
    child.stdout.on('data', take('out', process.stdout));
    child.stderr.on('data', take('err', process.stderr));
    child.on('error', (err) => { clearTimeout(timer); resolve({ code: -1, stdout, stderr, text: `${text}${err.message}` }); });
    child.on('close', (code) => { clearTimeout(timer); resolve({ code: code === null ? -1 : code, stdout, stderr, text }); });
  });
}

/** Repeat a quiet read until it says what it should, or time runs out. */
async function waitUntil({ cmd, args, env, until, everyMs = 3000, timeoutMs = 120000 }) {
  const end = Date.now() + timeoutMs;
  let last = null;
  while (Date.now() < end) {
    const r = spawnSync(cmd, args, { env: { ...process.env, ...(env || {}) }, encoding: 'utf8', windowsHide: true, timeout: 30000 });
    last = { code: r.status === null ? -1 : r.status, stdout: r.stdout || '', stderr: r.stderr || '', text: `${r.stdout || ''}${r.stderr || ''}` };
    if (until(last)) { record(last.text); return last; }
    await new Promise((res) => setTimeout(res, everyMs));
  }
  if (last) record(last.text);
  return { ...(last || { code: -1, stdout: '', stderr: '', text: '' }), timedOut: true };
}

/** The pids of processes whose command line names `dir` (agents a step left behind). */
function processesNaming(dir) {
  if (process.platform === 'win32') {
    const out = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command',
      'Get-CimInstance Win32_Process | ForEach-Object { "$($_.ProcessId)`t$($_.CommandLine)" }'],
    { encoding: 'utf8', windowsHide: true, timeout: 30000 }).stdout || '';
    return out.split(/\r?\n/).filter((l) => l.toLowerCase().includes(dir.toLowerCase()))
      .map((l) => Number(l.split('\t')[0])).filter((pid) => pid && pid !== process.pid);
  }
  const pids = [];
  for (const entry of fs.readdirSync('/proc')) {
    if (!/^\d+$/.test(entry) || Number(entry) === process.pid) continue;
    try {
      if (fs.readFileSync(`/proc/${entry}/cmdline`, 'utf8').split('\0').join(' ').includes(dir)) pids.push(Number(entry));
    } catch { /* exited */ }
  }
  return pids;
}

/**
 * @param {object} opts
 * @param {string[]} [opts.only]   step ids to run (all when empty)
 * @param {boolean} [opts.list]    print the steps and stop
 * @returns {Promise<number>} 0 when every step passed
 */
async function runByHand({ only = [], list = false, saveBaseline = false } = {}) {
  const files = stepFiles();
  const all = files.flatMap((file) => {
    const mod = require(file);
    return mod.steps.map((step) => ({ ...step, file: path.basename(file), section: mod.name }));
  });
  const steps = only.length ? all.filter((s) => only.includes(s.id)) : all;

  if (list) {
    for (const s of all) console.log(`  ${s.id.padEnd(18)} ${s.press ? 'PRESS ' : '      '} ${s.title}`);
    console.log(`\n${all.length} step(s) in ${files.length} file(s): okt byhand [--only id,id]`);
    return 0;
  }

  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'okt-byhand-'));
  const ctx = { work, saved: {}, note };
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  fs.mkdirSync(RUNS_ROOT, { recursive: true });
  transcript = path.join(RUNS_ROOT, `byhand-${stamp}.log`);
  const latest = path.join(RUNS_ROOT, 'byhand-latest.log');
  fs.writeFileSync(latest, `okt byhand started ${new Date().toISOString()} - the full log is ${transcript}\n`);

  const baseline = loadBaseline();
  say(`${BAR}\nokt byhand - ${steps.length} step(s) on the key. Press only when you see PRESS NOW.`);
  note(baseline ? `baseline: ${BASELINE} (recorded ${baseline.recorded}, ${baseline.firmware})` : 'baseline: none yet');
  say(`It stops at the first failure. Log: ${transcript}\n${BAR}`);

  const results = [];
  let failed = null;
  for (let i = 0; i < steps.length && !failed; i++) {
    const step = steps[i];
    say(`\n[${i + 1}/${steps.length}] ${step.title}`);
    note(`  id: ${step.id}`);
    for (const line of String(step.explain || '').trim().split('\n')) note(`  ${line.trim()}`);
    if (step.audit) note(`  AUDIT: ${step.audit}`);

    const started = Date.now();
    let out = { code: 0, stdout: '', stderr: '', text: '' };
    let why = null;
    let value;
    try {
      if (step.waitFor) {
        const w = step.waitFor(ctx);
        /* The state the step starts from (e.g. "plugged in and locked"), read once before asking for anything. */
        if (w.expectFirst) {
          const first = await waitUntil({ ...w, until: () => true, timeoutMs: 1 });
          why = w.expectFirst(first);
          out = first;
        }
        if (!why && w.enterWhenDone) {
          /*
           * The one Enter of the whole run (owner, 2026-10-19: "i press enter after
           * unlocking the key"): the person does the thing, says so, and it is
           * read once. Nothing after this waits for the keyboard.
           */
          pressNow(w.prompt);
          await new Promise((resolve) => {
            const rl = require('readline').createInterface({ input: process.stdin, output: process.stdout });
            rl.question(`  ${w.enterWhenDone} `, () => { rl.close(); resolve(); });
          });
          note('  (Enter)');
          out = await waitUntil({ ...w, timeoutMs: 1 });
          why = w.until(out) ? null : 'it did not take - read the status above';
        } else if (!why) {
          pressNow(w.prompt);
          out = await waitUntil(w);
          why = out.timedOut ? `not done within ${Math.round((w.timeoutMs || 120000) / 1000)} s` : null;
        }
      } else {
        const spec = step.run ? step.run(ctx) : null;
        if (spec) {
          note(`  $ ${[spec.cmd, ...(spec.args || [])].map((a) => (/\s/.test(a) ? JSON.stringify(a) : a)).join(' ')}`);
          /* A press that comes from a program which prints no prompt of its own (gpg through its agent). */
          if (step.press && step.pressUpFront) pressNow(step.pressUpFront);
          out = await runLive(spec);
        }
      }
      if (!why) why = step.check ? step.check(out, ctx) : (out.code === 0 ? null : `exit ${out.code}`);
      if (!why && step.after) step.after(out, ctx);
      if (!why && step.result) {
        value = step.result(out, ctx);
        note(`  result: ${JSON.stringify(value)}${step.perDevice ? ' (this key only - not compared with the baseline)' : ''}`);
        const expected = baseline && baseline.steps && baseline.steps[step.id];
        if (expected && !step.perDevice && JSON.stringify(expected.value) !== JSON.stringify(value)) {
          why = `differs from the baseline: expected ${JSON.stringify(expected.value)}, got ${JSON.stringify(value)}`;
        } else if (!expected && !step.perDevice && baseline) {
          note('  (no baseline value for this step yet)');
        }
      }
    } catch (err) {
      why = err.message;
    }
    say(`  ${why ? 'FAIL' : 'ok  '} ${step.title}${why ? ` - ${why}` : ''}`);
    results.push({ id: step.id, title: step.title, status: why ? 'FAIL' : 'ok', why, value, perDevice: Boolean(step.perDevice), ms: Date.now() - started });
    if (why) failed = step;
  }

  for (const dir of ctx.cleanup || []) {
    for (const pid of processesNaming(dir)) { try { process.kill(pid); } catch { /* gone */ } }
  }
  fs.rmSync(work, { recursive: true, force: true, maxRetries: 10, retryDelay: 300 });

  const passed = results.filter((r) => r.status === 'ok').length;
  say(`\n${BAR}`);
  say(failed
    ? `okt byhand: STOPPED at step "${failed.id}" (${passed} ok before it, ${steps.length - results.length} not run)`
    : `okt byhand: all ${passed} step(s) ok`);
  const report = path.join(RUNS_ROOT, `byhand-${stamp}.json`);
  fs.writeFileSync(report, JSON.stringify({ at: new Date().toISOString(), host: os.hostname(), log: transcript, results }, null, 2));
  if (saveBaseline) {
    if (failed || results.length !== all.length) {
      say('baseline NOT saved: only a run of every step, all passing, can be the baseline');
    } else {
      const firmware = (results.find((r) => r.id === 'py-fwversion') || {}).value || null;
      const saved = { recorded: new Date().toISOString(), firmware, host: os.hostname(), steps: {} };
      for (const r of results) if (!r.perDevice && r.value !== undefined) saved.steps[r.id] = { value: r.value };
      fs.writeFileSync(BASELINE, `${JSON.stringify(saved, null, 2)}\n`);
      say(`baseline saved: ${BASELINE}`);
    }
  }
  say(`log: ${transcript} (copied to ${latest})\n${BAR}`);
  /* The last thing on the screen: one word the person can read from across the room. */
  const verdict = failed ? 'TEST FAIL' : 'TEST PASS';
  record(`\n${verdict}\n`);
  fs.copyFileSync(transcript, latest);
  transcript = null;
  console.log(process.stdout.isTTY
    ? `\n  ${failed ? '\x1b[1;37;41m' : '\x1b[1;30;42m'}  ${verdict}  \x1b[0m\n`
    : `\n${verdict}\n`);
  return failed ? 1 : 0;
}

module.exports = { runByHand, runLive, processesNaming, BYHAND_ROOT };
