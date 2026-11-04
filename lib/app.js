/*
 * app.js - section 4's long-lived service: the OnlyKey APP.
 *
 * SECTION 3 AND SECTION 4 ARE DIFFERENT CODEBASES AND BOTH GET CALLED "THE
 * APP". Section 3 is `onlykey.github.io`, a web app served by express and
 * opened in nw.js, reaching the device over the WebAuthn tunnel. This is
 * `OnlyKey-App`, a PACKAGED nw.js application - Chrome-App style, manifest
 * version 2 - that reaches the device with `chrome.hid`. lib/gui.js was built
 * for the first and had never been pointed at the second.
 *
 * Three things follow from that difference and shape everything here.
 *
 * IT IS AN APPLICATION, NOT A URL. nw.js is handed the build directory and the
 * app opens its OWN window, so there is nothing to navigate to and nothing to
 * create: this ATTACHES to a window that already exists. `GuiSession.open()`
 * calls `Target.createTarget` with a url; doing that here would open a second,
 * empty window beside the app's real one.
 *
 * IT REACHES THE DEVICE OVER `chrome.hid`, NOT WebAuthn. That removes the worst
 * failure mode section 3 has: there, a page whose startup handshake times out
 * makes Chromium raise a NATIVE WebAuthn dialog that no CDP command can dismiss
 * and the session is wedged until restarted. `chrome.hid` has no equivalent -
 * with nothing on the bus the app simply shows its disconnected dialog and
 * waits. So the "device up and unlocked before anything opens" rule does not
 * transfer for the reason it was written, and this module does not enforce it.
 * (Measured with an EMPTY bus. Device-up-but-LOCKED is not measured - see TODO.)
 *
 * IT HAS TO BE BUILT. `build/` is gitignored, so it is never in a fresh
 * checkout, and `gulp build` is a prerequisite rather than a convenience. It is
 * cheap - measured at 1.78s, and it is a file copy plus sourcemaps rather than a
 * bundler - so this builds every time instead of trying to decide whether a
 * previous build is stale. `clean` runs first, so nothing may be edited under
 * `build/` and expected to survive.
 *
 * THE INSTRUMENTATION SEAM IS NOT `chromeHid._sent`, whatever it looks like.
 * That array is appended to only when the connection is the mock's; the real
 * branch calls `chrome.hid.send` and records nothing, so against a real device
 * it stays empty forever. Two consequences: `recordWire()` below installs
 * wrappers instead, and - more usefully - the kit does not need it, because the
 * device end sees everything the app puts on the bus and is a better oracle
 * than the client's own account of what it sent.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

const { CHECKOUTS_ROOT } = require('./paths');
const { Page, findNw, waitFor, get, launch, stopGroup } = require('./gui');

/* OKT_APP_DIR points the kit at another App checkout - a release's pinned copy rather than the working one */
const APP_DIR = process.env.OKT_APP_DIR ? path.resolve(process.env.OKT_APP_DIR) : path.join(CHECKOUTS_ROOT, 'OnlyKey-App');
const BUILD_DIR = path.join(APP_DIR, 'build');
/* gulp's own script, run with this node: node_modules/.bin/gulp is a shell
 * script on Linux and a .cmd on Windows, and Node will not spawn a .cmd
 * without a shell. */
const GULP = path.join(APP_DIR, 'node_modules', 'gulp', 'bin', 'gulp.js');

/*
 * Section 3 uses 9222. A different port so that a stray section-3 browser can
 * never be mistaken for this one - "something is already answering CDP" is a
 * much better failure than driving the wrong Chromium for twenty minutes.
 */
const CDP_PORT = 9223;

/** @returns {{ok: boolean, why: string|null}} */
function probe() {
  if (!fs.existsSync(path.join(APP_DIR, 'package.json'))) {
    return { ok: false, why: `the OnlyKey App is not checked out at ${APP_DIR}` };
  }
  if (!fs.existsSync(GULP)) {
    return {
      ok: false,
      why: `no gulp in the App checkout - run  npm install --ignore-scripts  in ` +
        `${APP_DIR} (--ignore-scripts on purpose: nw is a RUNTIME dependency ` +
        'there and a plain install downloads a ~150MB runtime this kit does ' +
        'not use, since it drives the App with its own nw)',
    };
  }
  if (!findNw()) {
    return { ok: false, why: 'no nw.js SDK binary - see lib/gui.js probe()' };
  }
  return { ok: true, why: null };
}

/**
 * `gulp build`, which is what produces the directory nw.js is handed.
 *
 * Runs to completion and is checked: a build that half-ran leaves a build/ that
 * looks present, and the app then fails to load for a reason that reads like an
 * nw problem. Same argument as the fixture restore asserting its sizes.
 */
function build({ timeoutMs = 120000 } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [GULP, 'build'],
      { cwd: APP_DIR, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    let out = '';
    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { out += d; });

    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error(`gulp build did not finish within ${timeoutMs}ms:\n${out.slice(-2000)}`));
    }, timeoutMs);

    child.on('error', (err) => {
      clearTimeout(timer);
      reject(new Error(`could not run gulp at ${GULP}: ${err.message}`));
    });
    child.on('exit', (code) => {
      clearTimeout(timer);
      if (code !== 0) {
        reject(new Error(`gulp build exited ${code}:\n${out.slice(-2000)}`));
        return;
      }
      if (!fs.existsSync(path.join(BUILD_DIR, 'manifest.json')) ||
          !fs.existsSync(path.join(BUILD_DIR, 'app.html'))) {
        reject(new Error(`gulp build exited 0 but ${BUILD_DIR} has no manifest.json/app.html`));
        return;
      }
      resolve({ dir: BUILD_DIR, output: out });
    });
  });
}

/**
 * Is CDP target `t` the kind the callers mean by `type`?
 *
 * 'app' means THE APP'S UI WINDOW, and that window has two CDP shapes. The
 * classic App (6.0.0, NW 0.71) opened it from a Chrome-app background page
 * (package.json main: app.js -> chrome.app.window.create), which CDP lists as
 * type 'app'. From the NW 0.114 move on, NW opens app.html directly (main:
 * app.html), because on 0.114 a window created by that background page never
 * finishes loading; CDP lists it as an ordinary 'page'. Either is the same
 * window to every test, so both match - keyed on app.html, so a devtools or
 * other page never passes for it. Every other type matches exactly.
 */
function isTargetOfType(t, type) {
  if (t.type === type) return true;
  return type === 'app' && t.type === 'page' && /\/app\.html(?:[?#]|$)/.test(t.url || '');
}

class AppSession {
  constructor(opts = {}) {
    this.logDir = opts.logDir || APP_DIR;
    this.userDataDir = opts.userDataDir || path.join(this.logDir, 'nw-app-udata');
    this.app = null;
  }

  /** Launch nw.js on the packaged app. */
  async start(opts = {}) {
    const already = await get(CDP_PORT, '/json/version');
    if (already.code) {
      throw new Error(
        `something is already answering CDP on ${CDP_PORT} - a previous ` +
        "session's app outliving its run is what this refuses rather than reuses"
      );
    }

    const nw = findNw();
    if (!nw) throw new Error(probe().why);

    this.app = launch('onlykey-app', nw, [
      BUILD_DIR,
      `--user-data-dir=${this.userDataDir}`,
      `--remote-debugging-port=${CDP_PORT}`,
      /* This VM has no GPU; Chromium is a known SIGSEGV risk without these. */
      '--disable-gpu',
      '--disable-software-rasterizer',
      '--disable-dev-shm-usage',
    ], {
      cwd: BUILD_DIR,
      logFile: path.join(this.logDir, 'onlykey-app.log'),
    });

    await waitFor(`the OnlyKey App to answer CDP on ${CDP_PORT}`,
      async () => (await get(CDP_PORT, '/json/version')).code === 200,
      { timeoutMs: 60000, ...opts });
    return this.app;
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
   * Wait for a target the app opens for ITSELF, and return every one of them.
   *
   * Answering CDP and having opened a window are different events, and the gap
   * between them is real: the first run of 10-session listed targets the moment
   * /json/version answered and saw zero windows. That is the shape of bug this
   * kit exists to make legible - a snapshot of something still arriving reads
   * as an absence - so nothing here takes a target list without waiting for it.
   */
  async waitForTargets(type = 'app', opts = {}) {
    await waitFor(`the App's ${type} target to appear`, async () => {
      const list = await this.targets();
      return list.some((t) => isTargetOfType(t, type));
    }, { timeoutMs: 30000, ...opts });
    return (await this.targets()).filter((t) => isTargetOfType(t, type));
  }

  /**
   * Attach to a window the app opened for itself.
   *
   * `type` is 'app' for the window with the UI in it and 'background_page' for
   * the generated background page. They are NOT interchangeable: `chromeHid` is
   * a top-level `const` in the window's script and does not exist in the
   * background page, so anything instrumenting the transport wants 'app'.
   *
   * DELIBERATELY NO `session`/`targetId` ON THE PAGE, which inverts section 3's
   * hardest-won lesson rather than forgetting it. There, `page.close()` has to
   * shut the WINDOW - a tab left loaded holds an outstanding WebAuthn request
   * and breaks the NEXT page's handshake, which cost a run to find. Here the
   * window IS the application: closing it ends the session every later file in
   * the section depends on. So `close()` drops this connection and leaves the
   * app running, and 19-stop takes the process group down.
   *
   * Waits for the app's own scripts as well as for the target. A target that
   * exists is not a window that has run its scripts: attaching the moment one
   * appeared found `chromeHid` undefined, because app.html was still loading.
   * Same class of race as waitForTargets(), one layer further in.
   */
  async attach(type = 'app', opts = {}) {
    const target = await waitFor(`the App's ${type} target`, async () => {
      const list = await this.targets();
      return list.find((t) => isTargetOfType(t, type) && t.webSocketDebuggerUrl);
    }, { timeoutMs: 30000, ...opts });

    const ws = new WebSocket(target.webSocketDebuggerUrl);
    await new Promise((resolve, reject) => {
      ws.onopen = resolve;
      ws.onerror = () => reject(new Error(`could not attach to the App's ${type} target`));
    });

    const page = new Page(ws);
    await page.send('Runtime.enable');

    if (type === 'app') {
      await page.waitFor("typeof chromeHid !== 'undefined' && typeof chrome.hid !== 'undefined'",
        { timeoutMs: 30000, ...opts });
    }
    return page;
  }

  /**
   * Wait for the App to have (re-)found the device.
   *
   * EVERY FILE IN THIS SECTION NEEDS THIS AND NONE OF THEM CAN ASSUME IT. The
   * App outlives the run's files, but each FILE gets its own device host, so
   * between files - and after any `device.restart()` - the device is unplugged
   * and replugged as far as the App is concerned. It recovers on
   * `onDeviceAdded`, but not instantly, and how long it takes varies enough
   * that a fixed wait passes most runs and not all. Two files were flaky on
   * exactly this before it lived here.
   *
   * POLLS THE DEVICE BETWEEN CHECKS, deliberately. A page wait produces no
   * device output, so a long one spends the run's 30s inactivity budget and
   * aborts the whole run with a watchdog rather than failing the test that
   * waited. `status()` is real device traffic: it proves the device is alive
   * AND keeps the watchdog fed while the App catches up.
   */
  async waitForDevice(page, device, { signal, log = () => {}, timeoutMs = 60000 } = {}) {
    const deadline = Date.now() + timeoutMs;
    let last = null;
    for (;;) {
      last = await page.eval(
        "JSON.stringify({conn: (typeof myOnlyKey !== 'undefined' && myOnlyKey) " +
        "? myOnlyKey.connection : null, init: (typeof myOnlyKey !== 'undefined' " +
        '&& myOnlyKey) ? !!myOnlyKey.isInitialized : false})').then(JSON.parse);
      if (last.conn !== null && last.conn !== -1 && last.init) return last;

      if (Date.now() > deadline) {
        throw new Error(
          'the App never found the device - it either enumerated before the ' +
          'gadget was up or took the wrong interface. Last seen: ' +
          JSON.stringify(last));
      }
      const st = await device.status({ signal }).catch(() => null);
      if (st) log(`waiting for the App to enumerate; the device says ${st.state}`);
      await device.sleep(2000, { signal });
    }
  }

  /**
   * Wrap `chromeHid.send`/`receive` so a test can read what the app asked for.
   *
   * `chromeHid` is declared `const`, so the BINDING cannot be replaced - but it
   * holds an ordinary mutable object, so its methods can. This is patching and
   * is named as such: the row that planned section 4 believed `_sent` already
   * recorded real traffic, and it does not.
   *
   * Prefer the device end where it can answer the question. What the device
   * received is stronger evidence than what the client believes it sent, and it
   * needs no patch at all.
   */
  async recordWire(page) {
    await page.eval(`(() => {
      if (window.__oktWire) return 'already';
      const wire = { sent: [], received: [] };
      window.__oktWire = wire;

      const send = chromeHid.send.bind(chromeHid);
      chromeHid.send = function (connectionId, reportId, data, callback) {
        try {
          wire.sent.push({
            at: Date.now(), connectionId, reportId,
            bytes: Array.from(new Uint8Array(data)),
          });
        } catch (e) { wire.sent.push({ at: Date.now(), error: String(e) }); }
        return send(connectionId, reportId, data, callback);
      };

      const receive = chromeHid.receive.bind(chromeHid);
      chromeHid.receive = function (connectionId, callback) {
        return receive(connectionId, function (reportId, data) {
          try {
            wire.received.push({
              at: Date.now(), reportId,
              bytes: Array.from(new Uint8Array(data)),
            });
          } catch (e) { wire.received.push({ at: Date.now(), error: String(e) }); }
          return callback.apply(this, arguments);
        });
      };
      return 'installed';
    })()`);
    return true;
  }

  /** What the wrappers have seen so far. */
  wire(page) {
    return page.eval('JSON.stringify(window.__oktWire || {sent: [], received: []})')
      .then((s) => JSON.parse(s));
  }

  /** By process group - nw.js is a tree, and killing its leader leaves renderers. */
  stop() {
    const stopped = [];
    if (this.app && stopGroup(this.app)) stopped.push('onlykey-app');
    this.app = null;
    return stopped;
  }

  /** Did it actually go? A stop that did not stop is worth failing on. */
  async settled(opts = {}) {
    await waitFor('the App to release its debugging port', async () => {
      /* gui.get() resolves {err} on failure and {code, body} on success - the
       * port being free is the ERROR case, which is easy to get backwards. */
      const cdp = await get(CDP_PORT, '/json/version', 1000);
      return !!cdp.err;
    }, { timeoutMs: 15000, ...opts });
    return true;
  }
}

module.exports = { AppSession, probe, build, APP_DIR, BUILD_DIR, CDP_PORT };
