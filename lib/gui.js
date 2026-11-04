/*
 * gui.js - the two long-lived services section 3's browser tier needs, and a
 * CDP client to drive the window.
 *
 * Two processes, kept separate on purpose. The web app is an express server
 * (onlykey.github.io's own index.js, port 3000); nw.js is a Chromium that opens
 * pages against it and answers CDP on 9222. The old kit had nw.js spawn the
 * server as its own child, which is how a crashed browser left an orphan still
 * holding port 3000. Started separately, each one is a visible step that can be
 * seen to have run - and each is killed by PROCESS GROUP, because Chromium is a
 * tree and killing its leader leaves renderers behind.
 *
 * Neither is started by a hook. EXPLAINER is explicit about that: a wedge has to
 * stay attributable to a step somebody can point at, so 10-session starts these
 * and 19-stop stops them, and both appear in the run output like any other test.
 *
 * ORDERING THAT IS NOT OPTIONAL. The app's pages talk to the device as they
 * load. A page opened before the OnlyKey is unlocked has its startup OKCONNECT
 * time out, and Chromium then raises a NATIVE WebAuthn dialog - a real OS
 * window, outside the page, that no amount of CDP can dismiss. The session is
 * wedged from that point and only a restart clears it. So the device comes up
 * and unlocks first, and only then does anything open an app page. The landing
 * page in tools/nwjs makes no device call at all, which is why it is safe to
 * start on.
 *
 * The CDP client is Node's own global WebSocket - no dependency. Everything
 * here is optional-dependency shaped: with no nw binary the files skip with a
 * reason, the same as node-hid and the @noble packages.
 */
'use strict';

const fs = require('fs');
const http = require('http');
const path = require('path');
const { spawn } = require('child_process');

const { CHECKOUTS_ROOT, KIT_ROOT } = require('./paths');

const APP_ROOT = require('./paths').WEBAPP_ROOT;
const NW_APP = path.join(KIT_ROOT, 'tools', 'nwjs');

const CDP_PORT = 9222;
const APP_PORT = 3000;

/*
 * Where the nw binary might be. It is a ~150MB download, so the kit does not
 * carry one - it finds an installed one and says where it looked otherwise.
 * OKT_NW_BINARY wins, for a system install or a second copy.
 */
const NW_PLATFORM = { linux: 'linux', win32: 'win', darwin: 'osx' }[process.platform] || process.platform;
const NW_EXE = { win32: 'nw.exe', darwin: path.join('nwjs.app', 'Contents', 'MacOS', 'nwjs') }[process.platform] || 'nw';

function nwCandidates() {
  /* The nw package unpacks to nwjs-sdk-v<version>-<platform>-<arch>/. */
  const rel = path.join('node_modules', 'nw',
    `nwjs-sdk-v0.114.0-${NW_PLATFORM}-${process.arch}`, NW_EXE);
  return [
    process.env.OKT_NW_BINARY,
    path.join(KIT_ROOT, rel),
    path.join(CHECKOUTS_ROOT, 'onlykey-alpha-testing', 'nwjs', rel),
  ].filter(Boolean);
}

/** @returns {string|null} */
function findNw() {
  return nwCandidates().find((p) => {
    try { fs.accessSync(p, fs.constants.X_OK); return true; } catch { return false; }
  }) || null;
}

/** @returns {{ok: boolean, why: string|null}} */
function probe() {
  if (!fs.existsSync(path.join(APP_ROOT, 'index.js'))) {
    return { ok: false, why: `the web app is not checked out at ${APP_ROOT}` };
  }
  if (!findNw()) {
    return {
      ok: false,
      why: 'no nw.js SDK binary - looked in ' + nwCandidates().join(', ') +
        ' (set OKT_NW_BINARY, or npm install nw@0.114.0-sdk)',
    };
  }
  const stale = staleBuild();
  if (stale) return { ok: false, why: stale };
  return { ok: true, why: null };
}

/**
 * Is the build the server hands out the SOURCE under test?
 *
 * index.js serves docs/, a TRACKED build that nothing here rebuilds. At
 * apps.onlykey.io 183d96c it was still the one committed in c7c59d6
 * (2026-09-24): the pre-port app, whose in-repo library opened the X-Wing
 * derive reply as transit v1 when no plain connect had selected v2 first - an
 * unauthenticated decrypt of a v2 frame, whose last 1216 bytes then failed as
 * "ML-KEM.encapsulate: wrong publicKey modulus". The source, and the library
 * it bundles, derive the right key; the browser tier was measuring an artifact
 * three commits behind them and reporting it as a page fault.
 *
 * The marker is the library's own API name, which minification keeps
 * (okcrypto.deviceAge): the port's bundle has it, the pre-port one cannot.
 * @returns {string|null} why the served build is not the source, or null
 */
function staleBuild() {
  if (!fs.existsSync(path.join(APP_ROOT, 'src', 'onlykey-lib', 'plugin.js'))) return null;
  const dir = path.join(APP_ROOT, 'docs', 'app');
  let bundles = [];
  try { bundles = fs.readdirSync(dir).filter((f) => /^bundle\..*\.js$/.test(f)); } catch { /* none */ }
  if (!bundles.length) return `the web app has no build to serve (${dir}) - run its BUILD.sh`;
  const ported = bundles.some((f) => fs.readFileSync(path.join(dir, f), 'latin1').includes('deviceAge'));
  if (ported) return null;
  return `the web app serves a build older than its source: ${dir} carries no ` +
    'node-onlykey-lib (the pre-port bundle) - rebuild docs/ with its BUILD.sh';
}

/* ---- http helpers -------------------------------------------------------- */

function get(port, urlPath, timeoutMs = 3000) {
  return new Promise((resolve) => {
    const req = http.get({ host: '127.0.0.1', port, path: urlPath, timeout: timeoutMs },
      (res) => {
        let body = '';
        res.on('data', (c) => { body += c; });
        res.on('end', () => resolve({ code: res.statusCode, body }));
      });
    req.on('error', (err) => resolve({ err: err.code || err.message }));
    req.on('timeout', () => { req.destroy(); resolve({ err: 'timeout' }); });
  });
}

async function waitFor(what, fn, { timeoutMs = 30000, pollMs = 250 } = {}) {
  const deadline = Date.now() + timeoutMs;
  let last = null;
  for (;;) {
    try {
      const value = await fn();
      if (value) return value;
    } catch (err) { last = err.message; }
    if (Date.now() >= deadline) {
      throw new Error(`timed out after ${timeoutMs}ms waiting for ${what}` +
        (last ? ` (last error: ${last})` : ''));
    }
    await new Promise((r) => setTimeout(r, pollMs));
  }
}

/* ---- a process this kit owns --------------------------------------------- */

/*
 * Every group this process started, so a run that dies before its stop step
 * does not leave a browser and a web server behind.
 *
 * 19-stop is the normal path and stays a visible test; this is the backstop for
 * the runs that never reach it - a watchdog abort, a firmware crash, Ctrl-C.
 * Measured: one aborted run left seven Chromium processes and an express server
 * holding both ports, and the NEXT run then failed in startServer() with a port
 * conflict a long way from the cause.
 *
 * Not a hook in the sense EXPLAINER rejects. It starts nothing and hides no
 * step; it only ensures that what this process spawned dies with it.
 */
const running = new Set();

/*
 * Windows has no process groups, so process.kill(-pid) cannot reach a tree.
 * taskkill /T walks it by parent pid - nw.exe's renderer, GPU and crashpad
 * children included, which otherwise outlive the run holding the CDP port and
 * the runtime's files (seen 2026-09-29: an orphaned crashpad handler locked
 * nw's icudtl.dat and failed the next npm install).
 */
function killTree(pid) {
  if (process.platform === 'win32') {
    const r = require('child_process').spawnSync('taskkill', ['/PID', String(pid), '/T', '/F'],
      { stdio: 'ignore', windowsHide: true });
    return r.status === 0;
  }
  try { process.kill(-pid, 'SIGKILL'); return true; } catch { return false; }
}

function killEverything() {
  for (const pid of running) killTree(pid);
  running.clear();
}

let netInstalled = false;
function installSafetyNet() {
  if (netInstalled) return;
  netInstalled = true;
  process.on('exit', killEverything);
  for (const sig of ['SIGINT', 'SIGTERM', 'SIGHUP']) {
    process.on(sig, () => { killEverything(); process.exit(1); });
  }
}

/**
 * Spawned detached, so it leads its own process group and the whole tree can be
 * killed at once. stdio goes to a file rather than a pipe: nw is chatty, and a
 * parent that stops reading a pipe blocks the child in write() - the same
 * deadlock EXPLAINER describes for the device host.
 */
function launch(name, command, args, { cwd, logFile, env }) {
  installSafetyNet();
  const out = fs.openSync(logFile, 'a');
  const child = spawn(command, args, {
    cwd,
    detached: true,
    windowsHide: true,
    stdio: ['ignore', out, out],
    env: { ...process.env, ...(env || {}) },
  });
  child.unref();
  running.add(child.pid);
  return { name, pid: child.pid, child, logFile };
}

function stopGroup(service, signal = 'SIGTERM') {
  if (!service || !service.pid) return false;
  running.delete(service.pid);
  /* No signals to a group on Windows; the tree is ended outright. */
  if (process.platform === 'win32') return killTree(service.pid);
  try {
    process.kill(-service.pid, signal);   // the GROUP, not the leader
    return true;
  } catch {
    try { process.kill(service.pid, signal); return true; } catch { return false; }
  }
}

/* ---- CDP ----------------------------------------------------------------- */

class Page {
  constructor(ws, opts = {}) {
    this.ws = ws;
    this.nextId = 1;
    this.pending = new Map();
    this.console = [];
    /* Set by GuiSession.open() so close() can shut the WINDOW and not just the
     * socket - see close() for why that distinction cost a run. */
    this.targetId = opts.targetId || null;
    this.session = opts.session || null;

    ws.addEventListener('message', (ev) => {
      const msg = JSON.parse(ev.data);
      if (msg.id && this.pending.has(msg.id)) {
        const { resolve } = this.pending.get(msg.id);
        this.pending.delete(msg.id);
        resolve(msg);
        return;
      }
      /* The page's own console, kept so a failure can show what it said. */
      if (msg.method === 'Runtime.consoleAPICalled') {
        const args = (msg.params.args || [])
          .map((a) => (a.value !== undefined ? a.value : a.description || a.type));
        this.console.push(`${msg.params.type}: ${args.join(' ')}`);
        if (this.console.length > 500) this.console.shift();
      }
      if (msg.method === 'Runtime.exceptionThrown') {
        const d = msg.params.exceptionDetails || {};
        this.console.push(`exception: ${d.text} ${(d.exception && d.exception.description) || ''}`);
      }
    });
  }

  send(method, params = {}) {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.ws.send(JSON.stringify({ id, method, params }));
      setTimeout(() => {
        if (this.pending.has(id)) {
          this.pending.delete(id);
          reject(new Error(`CDP ${method} did not answer within 30s`));
        }
      }, 30000);
    });
  }

  /**
   * Evaluate in the page and return the value.
   *
   * awaitPromise, because most of what the app does is asynchronous and a
   * pending promise handed back as an object is the least useful answer
   * available. A thrown exception becomes a thrown Error here rather than a
   * result nobody checks.
   */
  async eval(expression, { timeoutMs = 30000 } = {}) {
    const msg = await this.send('Runtime.evaluate', {
      expression,
      awaitPromise: true,
      returnByValue: true,
      userGesture: true,
      timeout: timeoutMs,
    });
    const r = msg.result || {};
    if (r.exceptionDetails) {
      const d = r.exceptionDetails;
      throw new Error(`page threw: ${d.text} ${(d.exception && d.exception.description) || ''}`);
    }
    return r.result ? r.result.value : undefined;
  }

  /** Wait for something to become true IN the page. */
  waitFor(expression, opts = {}) {
    return waitFor(`\`${expression}\` in the page`, () => this.eval(expression), opts);
  }

  /**
   * Close the WINDOW, not merely this connection to it.
   *
   * It used to be `this.ws.close()` alone, which drops the debugger socket and
   * leaves the tab running - still loaded, still holding the device, still
   * retrying whatever it was doing. `11-password-generator` (retired 2026-09-29; no such page in web app 4.0.0)'s "closes its
   * window" test has always said the opposite ("a window left open holds a
   * device handle, and the next file's page would be fighting it for the
   * device"), and nothing noticed the difference because no file had ever opened
   * a SECOND page in one session.
   *
   * `03-gui/14-gui-encrypt-decrypt` opens five, and the failure is worth knowing
   * because it does not look like a leak: the abandoned tab's startup OKCONNECT
   * is still outstanding, so the next page's handshake dies inside Chromium with
   * **`OperationError: A request is already pending.`** - one WebAuthn request
   * at a time, per browser, not per tab. The page swallows it, the output box
   * never fills, and what a test sees is a device that was never contacted.
   *
   * Fire-and-forget by design: callers say `page.close()` in a `finally` and
   * cannot await it there, and a window that will not close is not a reason to
   * fail a test that has already made its assertions - `19-stop` takes the whole
   * browser down by process group regardless.
   */
  close() {
    if (this.session && this.targetId) {
      this.session.closeTarget(this.targetId).catch(() => { /* 19-stop is the backstop */ });
    }
    try { this.ws.close(); } catch { /* already gone */ }
  }
}

/* ---- the session --------------------------------------------------------- */

class GuiSession {
  constructor(opts = {}) {
    this.logDir = opts.logDir || KIT_ROOT;
    this.server = null;
    this.browser = null;
    this.userDataDir = opts.userDataDir || path.join(this.logDir, 'nw-udata');
  }

  /** The web app's own express server. */
  async startServer(opts = {}) {
    const already = await get(APP_PORT, '/');
    if (already.code) {
      throw new Error(
        `something is already serving on ${APP_PORT} - a previous session's ` +
        'server outliving its browser is exactly what this design avoids, so ' +
        'it is refused rather than reused'
      );
    }

    this.server = launch('web app', process.execPath, ['index.js'], {
      cwd: APP_ROOT,
      logFile: path.join(this.logDir, 'webapp.log'),
      env: { PORT: String(APP_PORT) },
    });

    await waitFor(`the web app on ${APP_PORT}`,
      async () => (await get(APP_PORT, '/')).code === 200, { timeoutMs: 30000, ...opts });
    return this.server;
  }

  /** nw.js, on the landing page - which makes no device call. */
  async startBrowser(opts = {}) {
    const already = await get(CDP_PORT, '/json/version');
    if (already.code) {
      throw new Error(`something is already answering CDP on ${CDP_PORT}`);
    }

    const nw = findNw();
    if (!nw) throw new Error(probe().why);

    this.browser = launch('nw.js', nw, [
      NW_APP,
      `--user-data-dir=${this.userDataDir}`,
      `--remote-debugging-port=${CDP_PORT}`,
      /* This VM has no GPU; Chromium is a known SIGSEGV risk without these. */
      '--disable-gpu',
      '--disable-software-rasterizer',
      '--disable-dev-shm-usage',
      /* OKT_NW_ARGS: extra Chromium switches for one run - FIDO logging, say:
       * OKT_NW_ARGS='--enable-logging=stderr --vmodule=*fido*=2,*hid*=2' */
      ...(process.env.OKT_NW_ARGS || '').split(/\s+/).filter(Boolean),
    ], {
      cwd: NW_APP,
      logFile: path.join(this.logDir, 'nwjs.log'),
    });

    await waitFor(`nw.js to answer CDP on ${CDP_PORT}`,
      async () => (await get(CDP_PORT, '/json/version')).code === 200,
      { timeoutMs: 60000, ...opts });
    return this.browser;
  }

  async version() {
    const res = await get(CDP_PORT, '/json/version');
    return res.code === 200 ? JSON.parse(res.body) : null;
  }

  async targets() {
    const res = await get(CDP_PORT, '/json/list');
    return res.code === 200 ? JSON.parse(res.body) : [];
  }

  /**
   * Open a page and attach to it.
   *
   * Never call this for an app page before the device is up and unlocked - see
   * the note at the top of this file about the native WebAuthn dialog.
   */
  async open(url, opts = {}) {
    /*
     * Target.createTarget over the BROWSER endpoint, rather than the HTTP
     * /json/new the old harness used. Chromium stopped accepting GET on that
     * route years ago - it wants PUT now - and the failure is a silent 405 that
     * arrives as "no page target ever appeared" sixty seconds later. The CDP
     * command has meant the same thing across every version this will meet.
     */
    const version = await this.version();
    if (!version || !version.webSocketDebuggerUrl) {
      throw new Error('nw.js is not answering CDP - the browser is not up');
    }

    const browserWs = new WebSocket(version.webSocketDebuggerUrl);
    await new Promise((resolve, reject) => {
      browserWs.onopen = resolve;
      browserWs.onerror = () => reject(new Error('could not attach to the browser'));
    });

    const browser = new Page(browserWs);
    let targetId;
    try {
      const created = await browser.send('Target.createTarget', { url });
      targetId = created.result && created.result.targetId;
      if (!targetId) {
        throw new Error(`Target.createTarget refused ${url}: ${JSON.stringify(created.error)}`);
      }
    } finally {
      browser.close();
    }

    /* The target exists; its debugger url appears on the list a moment later. */
    const target = await waitFor(`the page target for ${url}`, async () => {
      const list = await this.targets();
      return list.find((t) => t.id === targetId && t.webSocketDebuggerUrl);
    }, { timeoutMs: 20000, ...opts });

    const ws = new WebSocket(target.webSocketDebuggerUrl);
    await new Promise((resolve, reject) => {
      ws.onopen = resolve;
      ws.onerror = () => reject(new Error(`could not attach to ${url}`));
    });

    const page = new Page(ws, { targetId, session: this });
    await page.send('Runtime.enable');
    await page.send('Page.enable');
    /*
     * FOCUS IS EMULATED, not left to the window manager. WebAuthn only runs in
     * a focused document, and the web app checks document.hasFocus() before
     * every device request ("page lost focus - OnlyKey cannot be reached while
     * this tab is in the background"). Real X focus is not ours to keep: each
     * request raises and closes Chromium's native WebAuthn dialog, and a page
     * closed by the previous test hands focus to whichever window mutter picks,
     * so on the VM the NEXT page's request found itself in the background and
     * failed without ever reaching the device. Emulated focus is per page and
     * independent of the desktop, the same way on every host.
     */
    await page.send('Emulation.setFocusEmulationEnabled', { enabled: true });
    return page;
  }

  /**
   * Shut a target down over the BROWSER endpoint.
   *
   * The page's own connection cannot do this - `Target.closeTarget` is a browser
   * level command, and asking for it down a page socket answers "'Target.closeTarget'
   * wasn't found". So this opens the browser endpoint the same way open() does,
   * says one thing and hangs up.
   */
  async closeTarget(targetId) {
    const version = await this.version();
    if (!version || !version.webSocketDebuggerUrl) return false;

    const ws = new WebSocket(version.webSocketDebuggerUrl);
    await new Promise((resolve, reject) => {
      ws.onopen = resolve;
      ws.onerror = () => reject(new Error('could not attach to the browser'));
    });
    const browser = new Page(ws);
    try {
      await browser.send('Target.closeTarget', { targetId });
      return true;
    } finally {
      browser.close();
    }
  }

  /** Both services, by process group. Safe to call twice. */
  stop() {
    const stopped = [];
    if (this.browser && stopGroup(this.browser)) stopped.push('nw.js');
    if (this.server && stopGroup(this.server)) stopped.push('web app');
    this.browser = null;
    this.server = null;
    return stopped;
  }

  /** Did everything actually go? A stop that did not stop is worth failing on. */
  async settled(opts = {}) {
    await waitFor('the services to release their ports', async () => {
      const cdp = await get(CDP_PORT, '/json/version', 1000);
      const app = await get(APP_PORT, '/', 1000);
      return !!cdp.err && !!app.err;
    }, { timeoutMs: 15000, ...opts });
    return true;
  }
}

module.exports = {
  GuiSession, Page, probe, findNw, waitFor, get,
  APP_ROOT, NW_APP, CDP_PORT, APP_PORT,
  /*
   * For lib/app.js, which is section 4's equivalent service and must share this
   * module's safety net rather than install a second one. `running` is a
   * module-level Set, so a second copy of launch() would keep its own list and
   * an aborted run would leave whichever half the other did not know about -
   * which is precisely the leak the device host still has (see TODO).
   */
  launch, stopGroup,
};
