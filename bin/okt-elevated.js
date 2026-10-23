#!/usr/bin/env node
/*
 * okt-elevated - run the kit's Windows jobs elevated, on request, from a normal shell.
 *
 *   okt-elevated serve                 start it, in an ELEVATED shell (Run as administrator)
 *   okt-elevated run <prog> <script> [args...]
 *                                      run one job through it; output streams back, and the
 *                                      exit code is the job's
 *   okt-elevated jobs                 the jobs running now, by number
 *   okt-elevated cancel <n|all>       stop a job and everything it started (taskkill /T)
 *   okt-elevated status | stop
 *
 * WHY. On Windows the key's FIDO interface is visible only to an elevated program, so the
 * kit's hardware runs have to be started by hand in an administrator shell every time. With
 * this, the administrator starts ONE thing, once, and jobs are handed to it.
 *
 * WHAT IT ALLOWS, AND WHY THAT NARROWLY. While it runs, anything running as this user that can
 * read the token file can ask it for an elevated job. So:
 *   - it listens on 127.0.0.1 only, on a random port, and every request carries a random token
 *     kept in a file in the user's profile (OKT_ELEVATED_FILE overrides);
 *   - the program must be Git Bash or node, and the first argument must be a script INSIDE the
 *     workspace (OKT_ROOT, default the folder above the kit) - no `bash -c`, nothing outside;
 *   - every request is logged, accepted or refused, to okt-elevated.log beside the token file;
 *   - it stops after 4 idle hours (OKT_ELEVATED_IDLE_MIN), on Ctrl+C, or on `stop`.
 * The scripts it runs can be edited without elevation - the same trust as running them by hand
 * in an administrator shell, which is what this replaces.
 *
 * Why TCP and not a named pipe: node cannot set a pipe's DACL, and the default one gives a
 * non-elevated process of the same user read access only, so it could not send a request.
 */
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const { spawn, spawnSync, execFile } = require('child_process');

const ROOT = path.resolve(process.env.OKT_ROOT || path.join(__dirname, '..', '..'));
const STATE = process.env.OKT_ELEVATED_FILE || path.join(os.homedir(), '.okt-elevated.json');
const AUDIT = path.join(path.dirname(STATE), 'okt-elevated.log');
const IDLE_MS = (parseInt(process.env.OKT_ELEVATED_IDLE_MIN, 10) || 240) * 60000;
const PROGRAMS = {
  bash: process.env.OKT_BASH || 'C:\\Program Files\\Git\\bin\\bash.exe',
  node: process.execPath,
};

const stamp = () => new Date().toISOString();
const audit = (line) => { try { fs.appendFileSync(AUDIT, `${stamp()} ${line}\n`); } catch { /* best effort */ } };

/* `net session` succeeds only in an elevated shell - the same check the kit's run scripts print. */
function isElevated() {
  if (process.platform !== 'win32') return process.getuid && process.getuid() === 0;
  return spawnSync('net', ['session'], { stdio: 'ignore', windowsHide: true }).status === 0;
}

/* A Git Bash path (/c/Users/...) or a Windows one, as an absolute Windows path. */
function toWindowsPath(p) {
  const m = /^\/([a-zA-Z])\/(.*)$/.exec(p);
  return path.resolve(m ? `${m[1]}:/${m[2]}` : p);
}

/** The reason a request is refused, or null when it is allowed. */
function refusal(req) {
  if (!req || !Array.isArray(req.argv) || req.argv.length < 2) return 'expected argv: [program, script, ...args]';
  if (!Object.prototype.hasOwnProperty.call(PROGRAMS, req.argv[0])) {
    return `program must be one of ${Object.keys(PROGRAMS).join(', ')}`;
  }
  const script = toWindowsPath(req.argv[1]);
  const rel = path.relative(ROOT, script);
  if (rel.startsWith('..') || path.isAbsolute(rel)) return `the script must be inside ${ROOT}`;
  if (!fs.existsSync(script) || !fs.statSync(script).isFile()) return `no such script: ${script}`;
  if (req.cwd) {
    const relCwd = path.relative(ROOT, toWindowsPath(req.cwd));
    if (relCwd.startsWith('..') || path.isAbsolute(relCwd)) return `cwd must be inside ${ROOT}`;
  }
  return null;
}

function serve(test) {
  if (test) {
    console.log('okt-elevated: --test - NOT elevated; jobs run with this shell\'s rights (protocol self-test only)');
  } else if (!isElevated()) {
    console.error('okt-elevated: this shell is not elevated - start it with "Run as administrator"');
    process.exit(1);
  }
  const token = crypto.randomBytes(32).toString('hex');
  let idle = null;
  let running = 0;
  let nextId = 1;
  const jobs = new Map();            // id -> { child, argv, started, pids }

  /*
   * Every process a job starts, recorded as it appears. taskkill /T walks parent links, and Git
   * Bash breaks them: when an intermediate MSYS process exits, its children keep a parent id
   * that no longer exists, so a cancelled kit run left timeout.exe -> node.exe (holding the key)
   * and tee.exe running. A snapshot every 2 s while a job runs catches each descendant while
   * its parent is still alive; cancel then kills all of them by pid.
   */
  /** Windows pids of an MSYS process and all its MSYS descendants (and its process group). */
  function msysFamily(rootPid) {
    const r = spawnSync(PROGRAMS.bash, ['-c', 'ps'], { encoding: 'utf8', windowsHide: true });
    const rows = String(r.stdout || '').split(/\r?\n/)
      .map((l) => /^\s*[A-Z]?\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)/.exec(l))
      .filter(Boolean)
      .map((m) => ({ pid: +m[1], ppid: +m[2], pgid: +m[3], winpid: +m[4] }));
    const family = new Set([rootPid]);
    for (let grew = true; grew;) {
      grew = false;
      for (const row of rows) {
        if (!family.has(row.pid) && (family.has(row.ppid) || row.pgid === rootPid)) { family.add(row.pid); grew = true; }
      }
    }
    return rows.filter((row) => family.has(row.pid) && row.winpid !== process.pid).map((row) => row.winpid);
  }

  let tracking = false;
  function trackDescendants() {
    if (tracking || !jobs.size || process.platform !== 'win32') return;
    tracking = true;
    execFile('powershell', ['-NoProfile', '-Command',
      'Get-CimInstance Win32_Process | ForEach-Object { "$($_.ProcessId) $($_.ParentProcessId)" }'],
    { windowsHide: true, timeout: 15000 }, (err, out) => {
      tracking = false;
      if (err || !out) return;
      const procs = out.trim().split(/\r?\n/).map((l) => l.trim().split(/\s+/).map(Number));
      for (const j of jobs.values()) {
        for (let grew = true; grew;) {
          grew = false;
          for (const [pid, ppid] of procs) {
            if (j.pids.has(ppid) && !j.pids.has(pid)) { j.pids.add(pid); grew = true; }
          }
        }
      }
    });
  }
  setInterval(trackDescendants, 2000).unref();
  const armIdle = () => {
    clearTimeout(idle);
    idle = setTimeout(() => { if (!running) shutdown('idle'); else armIdle(); }, IDLE_MS);
  };

  const server = net.createServer((sock) => {
    let buf = '';
    sock.on('data', (d) => {
      buf += d.toString('utf8');
      const nl = buf.indexOf('\n');
      if (nl < 0) return;
      let req = null;
      try { req = JSON.parse(buf.slice(0, nl)); } catch { /* answered below */ }
      buf = '';
      handle(req, sock);
    });
    sock.on('error', () => { /* the client went away */ });
  });

  const send = (sock, msg) => { try { sock.write(`${JSON.stringify(msg)}\n`); } catch { /* gone */ } };

  function handle(req, sock) {
    const tokOk = req && typeof req.token === 'string' && req.token.length === token.length
      && crypto.timingSafeEqual(Buffer.from(req.token), Buffer.from(token));
    if (!tokOk) {
      audit('REFUSED bad token');
      send(sock, { t: 'end', code: 126, error: 'bad token' });
      return sock.end();
    }
    armIdle();
    if (req.op === 'status') {
      send(sock, { t: 'end', code: 0, out: `pid ${process.pid}, root ${ROOT}, jobs running ${running}` });
      return sock.end();
    }
    if (req.op === 'jobs') {
      const list = [...jobs].map(([id, j]) => `${id}  pid ${j.child.pid}  since ${j.started}  ${j.argv.join(' ')}`);
      send(sock, { t: 'end', code: 0, out: list.length ? list.join('\n') : 'no jobs running' });
      return sock.end();
    }
    if (req.op === 'cancel') {
      const ids = req.id === 'all' ? [...jobs.keys()] : [Number(req.id)];
      const done = [];
      for (const id of ids) {
        const j = jobs.get(id);
        if (!j) continue;
        /* The whole tree: a kit run is bash -> node -> python / nw, and killing bash alone leaves them. */
        if (process.platform === 'win32') {
          /*
           * A bash job: its family from MSYS's own table, read BEFORE anything is killed. ps keeps
           * the real parent of every Git Bash process (Windows loses it when a fork exits), and
           * lists each one's Windows pid. GNU timeout moves itself into a new process group, so
           * the group alone is not enough - the tree is walked from the script's bash down.
           */
          const msys = j.pgid ? msysFamily(j.pgid) : [];
          const pids = [...new Set([...j.pids, ...msys])];
          spawnSync('taskkill', ['/T', '/F', ...pids.flatMap((p) => ['/PID', String(p)])], { stdio: 'ignore', windowsHide: true });
        } else {
          j.child.kill('SIGTERM');
        }
        audit(`CANCEL job ${id} pid ${j.child.pid} ${JSON.stringify(j.argv)}`);
        console.log(`=== ${stamp()} CANCEL job ${id}  ${j.argv.join(' ')}`);
        done.push(id);
      }
      send(sock, { t: 'end', code: done.length ? 0 : 1, out: done.length ? `cancelled job ${done.join(', ')}` : `no such job: ${req.id}` });
      return sock.end();
    }
    if (req.op === 'stop') {
      audit('STOP requested');
      send(sock, { t: 'end', code: 0, out: 'stopping' });
      sock.end();
      return shutdown('stop');
    }
    const why = refusal(req);
    if (why) {
      audit(`REFUSED ${JSON.stringify(req.argv)}: ${why}`);
      console.log(`=== ${stamp()} REFUSED ${JSON.stringify(req.argv)}: ${why}`);
      send(sock, { t: 'end', code: 126, error: why });
      return sock.end();
    }
    const [prog, script, ...rest] = req.argv;
    const exe = PROGRAMS[prog];
    const args = [prog === 'bash' ? req.argv[1] : toWindowsPath(script), ...rest];
    const cwd = req.cwd ? toWindowsPath(req.cwd) : path.dirname(toWindowsPath(script));
    audit(`RUN ${prog} ${JSON.stringify(args)} cwd=${cwd}`);
    running++;
    /* No environment from the request: NODE_OPTIONS or BASH_ENV would get past the script rule. */
    /*
     * A bash job runs as its own MSYS process group (set -m puts a background job in a new
     * group) and reports the group on a marker line, so cancel can kill the whole family with
     * MSYS's kill: Git Bash's forks re-parent its processes away from anything Windows can
     * walk. The wrapper waits for the script and exits with its code.
     */
    const WRAP = 'set -m; bash "$0" "$@" & pg=$!; echo "@@OKT_PGID $pg" >&2; wait $pg';
    const spawnArgs = prog === 'bash' ? ['-c', WRAP, ...args] : args;
    const child = spawn(exe, spawnArgs, { cwd, env: process.env, windowsHide: true });
    const id = nextId++;
    jobs.set(id, { child, argv: req.argv, started: stamp(), pids: new Set([child.pid]) });
    send(sock, { t: 'job', id });
    /* Shown in the elevated window too, so whoever keeps it open sees every job as it runs. */
    console.log(`
=== ${stamp()} RUN ${prog} ${args.join(' ')}  (cwd ${cwd})`);
    child.stdout.on('data', (d) => { process.stdout.write(d); send(sock, { t: 'out', d: d.toString('utf8') }); });
    child.stderr.on('data', (d) => {
      let text = d.toString('utf8');
      const m = /@@OKT_PGID (\d+)\r?\n?/.exec(text);
      if (m) { const j = jobs.get(id); if (j) j.pgid = Number(m[1]); text = text.replace(m[0], ''); }
      if (!text) return;
      process.stderr.write(text);
      send(sock, { t: 'err', d: text });
    });
    child.on('error', (e) => { send(sock, { t: 'err', d: `spawn failed: ${e.message}\n` }); });
    child.on('close', (code, signal) => {
      running--;
      jobs.delete(id);
      armIdle();
      audit(`EXIT ${code}${signal ? ` (${signal})` : ''} ${prog} ${JSON.stringify(args)}`);
      console.log(`=== ${stamp()} EXIT ${code === null ? signal : code}  ${prog} ${args.join(' ')}
`);
      send(sock, { t: 'end', code: code === null ? 1 : code });
      sock.end();
    });
    /* A client that disconnects does not stop the job: a kit run must finish or clean up itself. */
  }

  function shutdown(why) {
    audit(`SHUTDOWN (${why})`);
    try { fs.unlinkSync(STATE); } catch { /* already gone */ }
    console.log(`okt-elevated: stopped (${why})`);
    server.close();
    setTimeout(() => process.exit(0), 200);
  }

  server.listen(0, '127.0.0.1', () => {
    const { port } = server.address();
    fs.writeFileSync(STATE, JSON.stringify({ port, token, pid: process.pid, root: ROOT, started: stamp() }), { mode: 0o600 });
    audit(`SERVE pid ${process.pid} port ${port} root ${ROOT}`);
    console.log(`okt-elevated: serving on 127.0.0.1:${port} for jobs inside ${ROOT}`);
    console.log(`okt-elevated: stops after ${IDLE_MS / 60000} idle minutes, on Ctrl+C, or "okt-elevated stop". Audit: ${AUDIT}`);
    armIdle();
  });
  process.on('SIGINT', () => shutdown('Ctrl+C'));
}

function client(req) {
  let state;
  try { state = JSON.parse(fs.readFileSync(STATE, 'utf8')); } catch {
    console.error(`okt-elevated: not running (no ${STATE}) - start "okt-elevated serve" in an elevated shell`);
    process.exit(125);
  }
  const sock = net.connect(state.port, '127.0.0.1', () => {
    sock.write(`${JSON.stringify({ ...req, token: state.token })}\n`);
  });
  let buf = '';
  sock.on('data', (d) => {
    buf += d.toString('utf8');
    let nl;
    while ((nl = buf.indexOf('\n')) >= 0) {
      const msg = JSON.parse(buf.slice(0, nl));
      buf = buf.slice(nl + 1);
      if (msg.t === 'out') process.stdout.write(msg.d);
      else if (msg.t === 'err') process.stderr.write(msg.d);
      else if (msg.t === 'job') process.stderr.write(`okt-elevated: job ${msg.id} (cancel with: okt-elevated cancel ${msg.id})\n`);
      else if (msg.t === 'end') {
        if (msg.out) console.log(msg.out);
        if (msg.error) console.error(`okt-elevated: ${msg.error}`);
        process.exitCode = msg.code;
      }
    }
  });
  sock.on('error', (e) => {
    console.error(`okt-elevated: cannot reach the server (${e.message}) - is it still running?`);
    process.exitCode = 125;
  });
}

const [cmd, ...rest] = process.argv.slice(2);
if (cmd === 'serve') serve(rest.includes('--test'));
else if (cmd === 'run') client({ op: 'run', argv: rest, cwd: process.env.OKT_ELEVATED_CWD });
else if (cmd === 'status' || cmd === 'stop' || cmd === 'jobs') client({ op: cmd });
else if (cmd === 'cancel' && rest[0]) client({ op: 'cancel', id: rest[0] });
else {
  console.error('usage: okt-elevated serve | run <bash|node> <script inside the workspace> [args...] | jobs | cancel <n|all> | status | stop');
  process.exit(2);
}
