/*
 * app6.js - OnlyKey App 6.x, driven the way lib/gui.js drives the web app.
 *
 * lib/app.js drives the classic App (5.x): a gulp build into build/, manifest.json + app.html,
 * launched on the kit's NW.js SDK. App 6.0.0 is a rewrite: a Vite build into dist/, a React UI,
 * the key reached through chrome.hid, and its own launcher (scripts/start-desktop.mjs) on its own
 * NW.js runtime (node_modules/nw).
 *
 * THAT RUNTIME CANNOT BE DRIVEN: it is NW.js's normal flavor, which ignores
 * --remote-debugging-port (measured 2026-10-22: nw.exe ran with the flag, nothing answered).
 * So this module does what the App's launcher does - `npm run build`, package.json main =
 * dist/index.html for the run (restored after), `nw . --onlykey-dev` - on the SDK flavor of the
 * SAME NW.js version, from OKT_APP6_NW, with CDP on. Same App code, same NW.js release as its
 * installers; only the flavor adds DevTools.
 *
 * OKT_APP_DIR picks the checkout (a release's pinned copy); the default is CHECKOUTS_ROOT/OnlyKey-App.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const { Page, waitFor, get, launch, stopGroup } = require('./gui');
const { APP_DIR } = require('./app');

/* not lib/gui.js's 9222: a web-app session may be running at the same time */
const APP6_CDP_PORT = Number(process.env.OKT_APP6_CDP_PORT || 9233);
const SERVICE = 'onlykey-app6';

/** Is APP_DIR an App 6.x checkout, with its NW.js runtime installed? */
function probe() {
  let pkg;
  try { pkg = JSON.parse(fs.readFileSync(path.join(APP_DIR, 'package.json'), 'utf8')); } catch {
    return { ok: false, why: `no OnlyKey App checkout at ${APP_DIR} (OKT_APP_DIR picks one)` };
  }
  const major = Number(String(pkg.version || '').split('.')[0]);
  if (!(major >= 6)) return { ok: false, why: `${APP_DIR} is App ${pkg.version}; app6 drives 6.x (lib/app.js drives 5.x)` };
  if (!fs.existsSync(path.join(APP_DIR, 'scripts', 'start-desktop.mjs'))) {
    return { ok: false, why: `${APP_DIR} has no scripts/start-desktop.mjs` };
  }
  const nwDir = path.join(APP_DIR, 'node_modules', 'nw');
  const runtime = fs.existsSync(nwDir) && fs.readdirSync(nwDir).find((e) => /^nwjs-v/.test(e)
    && fs.statSync(path.join(nwDir, e)).isDirectory());
  if (!runtime) {
    return { ok: false, why: `App ${pkg.version} has no NW.js runtime in ${nwDir} - run npm ci there `
      + '(and the nw package\'s postinstall, if npm held install scripts back)' };
  }
  const want = runtime.replace(/^nwjs-/, '');                 // e.g. v0.104.1-win-x64
  const sdk = process.env.OKT_APP6_NW;
  if (!sdk || !fs.existsSync(sdk)) {
    return { ok: false, why: `App ${pkg.version} runs on NW.js ${want}, whose normal flavor cannot be driven `
      + `(no CDP): set OKT_APP6_NW to nw of nwjs-sdk-${want} (https://dl.nwjs.io/${want.split('-')[0]}/)` };
  }
  return { ok: true, why: null, version: pkg.version, runtime, sdk };
}

/* The App's own build, as its launcher runs it. */
function buildApp() {
  const { spawnSync } = require('child_process');
  const r = spawnSync('npm', ['run', 'build'], { cwd: APP_DIR, shell: true, encoding: 'utf8' });
  if (r.status !== 0) throw new Error(`npm run build failed in ${APP_DIR}: ${(r.stderr || r.stdout || '').slice(-400)}`);
  if (!fs.existsSync(path.join(APP_DIR, 'dist', 'index.html'))) throw new Error(`build left no ${APP_DIR}/dist/index.html`);
}

/* package.json's main must be dist/index.html for the run (the launcher's setPackageMain); restored after */
function pointMain() {
  const file = path.join(APP_DIR, 'package.json');
  const text = fs.readFileSync(file, 'utf8');
  const pkg = JSON.parse(text);
  if (pkg.main === 'dist/index.html') return null;
  pkg.main = 'dist/index.html';
  fs.writeFileSync(file, JSON.stringify(pkg, null, 2) + '\n');
  return () => fs.writeFileSync(file, text);
}

class App6Session {
  constructor(opts = {}) {
    this.logDir = opts.logDir || path.join(APP_DIR, 'tmp');
    this.userDataDir = opts.userDataDir || path.join(this.logDir, 'app6-udata');
    this.page = null;
    this.child = null;
  }

  /** Build and start the App with CDP on, and attach to its window. */
  async start({ timeoutMs = 180000 } = {}) {
    const already = await get(APP6_CDP_PORT, '/json/version');
    if (already.code) throw new Error(`something is already answering CDP on ${APP6_CDP_PORT}`);
    const p = probe();
    if (!p.ok) throw new Error(p.why);
    fs.mkdirSync(this.logDir, { recursive: true });
    buildApp();
    this.restoreMain = pointMain();
    this.child = launch(SERVICE, p.sdk, [
      '.', '--onlykey-dev',                                   // the App launcher's own arguments
      `--remote-debugging-port=${APP6_CDP_PORT}`,
      `--user-data-dir=${this.userDataDir}`,
    ], { cwd: APP_DIR, logFile: path.join(this.logDir, 'app6.log') });

    const target = await waitFor('the App 6 window to answer CDP', async () => {
      const res = await get(APP6_CDP_PORT, '/json/list');
      if (res.code !== 200) return null;
      return JSON.parse(res.body).find((t) => t.type === 'page' && /dist\/index\.html/.test(t.url)
        && t.webSocketDebuggerUrl) || null;
    }, { timeoutMs });

    const ws = new WebSocket(target.webSocketDebuggerUrl);
    await new Promise((resolve, reject) => {
      ws.onopen = resolve;
      ws.onerror = () => reject(new Error('could not attach to the App 6 window'));
    });
    this.page = new Page(ws, { targetId: target.id });
    await this.page.send('Runtime.enable');
    await this.page.send('Page.enable');
    await this.page.send('Emulation.setFocusEmulationEnabled', { enabled: true });
    await this.page.waitFor('document.readyState === "complete"', { timeoutMs: 30000 });
    return this.page;
  }

  async screenshot(file) {
    const r = await this.page.send('Page.captureScreenshot', { format: 'png' });
    fs.writeFileSync(file, Buffer.from(r.result.data, 'base64'));
    return file;
  }

  /** The visible controls, for writing and debugging tests against the UI. */
  controls() {
    return this.page.eval(`JSON.stringify([...document.querySelectorAll(
      'input,textarea,button,select,a,[role=button],[role=tab],[role=switch],[role=menuitem]')]
      .filter((e) => e.offsetParent !== null)
      .map((e) => ({ tag: e.tagName.toLowerCase(), id: e.id, role: e.getAttribute('role') || '',
        label: (e.getAttribute('aria-label') || e.innerText || e.value || e.placeholder || '').trim().slice(0, 60) })))`);
  }

  stop() {
    if (this.page) { try { this.page.close(); } catch { /* gone */ } this.page = null; }
    if (this.child) { stopGroup(this.child); this.child = null; }
    if (this.restoreMain) { this.restoreMain(); this.restoreMain = null; }
  }
}

module.exports = { App6Session, probe, APP6_CDP_PORT };
