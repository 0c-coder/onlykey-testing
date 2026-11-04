/*
 * Section 4, the OnlyKey APP: build it, start it, and prove the instrument.
 *
 * This is the file that raises section 4's long-lived process, and it is a
 * VISIBLE test rather than a hook for the same reason 03-gui/10-session is: a
 * wedge has to stay attributable to a step somebody can point at, and a start
 * that did not happen has to be as legible as one that did. 19-stop takes it
 * down again.
 *
 * NOT THE SAME APP AS SECTION 3. That one is onlykey.github.io in a browser
 * over the WebAuthn tunnel; this is OnlyKey-App, a packaged nw.js application
 * reaching the device with chrome.hid. See lib/app.js.
 *
 * WHY THIS FILE ASKS FOR A DEVICE AT ALL, when it asserts nothing about one:
 * the App enumerates as it loads. Raising the gadget first means every later
 * file inherits an App that has already seen a device, rather than one that has
 * to be convinced to look again - and it is also how the file proves the two
 * can coexist at all, which was an open question when it was written.
 *
 * SURFACE: chrome.hid / CDP. Section 4 is a client test by construction: what
 * it asserts about is what the shipped App does, so there is no production-walk
 * question here the way there is for a console read.
 */
'use strict';

const { describe, it } = require('../../lib/harness');
const app = require('../../lib/app');

/*
 * Held across the files in this section. The runner clears the harness registry
 * between files, but the module cache persists - which is what lets 19-stop
 * take down what this file started.
 */
const session = require('../../lib/app-session-holder');

describe('section 4 app session', {
  requires: ['client-access', 'display', 'nwjs'],
  timeoutMs: 180000,
}, () => {
  it('has an App checkout, a builder and an nw.js to run it in', async ({ assert }) => {
    const found = app.probe();
    assert.ok(found.ok, found.why || 'the App is not runnable here');
  });

  it('builds the App, because build/ is gitignored and never in a checkout', async ({ assert, log }) => {
    /*
     * Not a convenience step. `build/` is in the App's .gitignore, so it is
     * absent from any fresh clone and cannot be assumed. It is cheap - a file
     * copy plus sourcemaps, no bundler - so this rebuilds every time rather
     * than trying to decide whether an existing one is stale.
     */
    const built = await app.build();
    log(`built ${built.dir}`);

    const fs = require('fs');
    const path = require('path');
    assert.ok(fs.existsSync(path.join(built.dir, 'app.html')),
      'the build produced no app.html');
    assert.ok(fs.existsSync(path.join(built.dir, 'manifest.json')),
      'the build produced no manifest.json');
  });

  it('starts the App and answers CDP', async ({ assert, log }) => {
    const s = session.create();
    const proc = await s.start();
    log(`app pid ${proc.pid}, log ${proc.logFile}`);

    const version = await s.version();
    assert.ok(version, 'the App did not answer /json/version');
    assert.ok(version.Browser, 'no browser version reported');
    log(`browser ${version.Browser}`);
  });

  it('opens its own window rather than one this kit created', async ({ assert, log }) => {
    /*
     * The difference from section 3 that shapes lib/app.js: there is no url to
     * navigate to. nw.js is handed a directory and the app opens its own
     * window, so this ATTACHES. Asking Target.createTarget for a url here would
     * open a second, empty window beside the real one and drive that.
     *
     * And it is WAITED for rather than snapshotted. Answering CDP and having
     * opened a window are separate events: the first version of this test
     * listed targets the instant /json/version answered, saw zero windows and
     * reported that the App had not opened one. A snapshot of something still
     * arriving reads exactly like an absence.
     */
    const s = session.get();
    const win = await s.waitForTargets('app');
    const targets = await s.targets();
    log(`targets: ${targets.map((t) => `[${t.type}] ${t.title}`).join(', ')}`);

    assert.equal(win.length, 1, `expected exactly one app window, got ${win.length}`);
    assert.includes(win[0].url, 'app.html',
      `the app window is not on app.html: ${win[0].url}`);
  });

  it('reaches chrome.hid from the app window, and getDevices answers', async ({ assert, log }) => {
    /*
     * PROVE THE INSTRUMENT. Everything section 4 will ever assert rests on the
     * App being able to reach the HID API under THIS nw.js - the kit's own
     * 0.114.0-sdk, not whatever runtime the App under test declares - so it is checked
     * here once, in the file that starts the session, rather than assumed by
     * every file after it.
     *
     * getDevices is CALLED rather than merely inspected. An API object that
     * exists and does not work is exactly the shape that would make every later
     * failure look like a device problem.
     */
    const s = session.get();
    const page = await s.attach('app');
    try {
      const probe = JSON.parse(await page.eval(`JSON.stringify({
        hasHid: typeof (window.chrome && chrome.hid),
        methods: (window.chrome && chrome.hid) ? Object.keys(chrome.hid).sort() : [],
        hasShim: typeof chromeHid,
        nw: (typeof process !== 'undefined' && process.versions) ? process.versions.nw : null,
      })`));
      log(`nw ${probe.nw}, chrome.hid ${probe.hasHid}, chromeHid ${probe.hasShim}`);

      assert.equal(probe.hasHid, 'object', 'chrome.hid is not available to the App');
      for (const m of ['connect', 'disconnect', 'getDevices', 'receive', 'send']) {
        assert.ok(probe.methods.includes(m), `chrome.hid has no ${m}()`);
      }

      /* The shim the App routes everything through - and the object a later
       * file's wire recorder patches, since it is a const BINDING holding a
       * mutable object. Absent from the background page, present here. */
      assert.equal(probe.hasShim, 'object',
        'the App\'s chromeHid shim is not reachable from the app window');

      const called = JSON.parse(await page.eval(`new Promise((resolve) => {
        chrome.hid.getDevices({}, (devs) => {
          const err = chrome.runtime.lastError;
          resolve(JSON.stringify({
            called: true,
            lastError: err ? String(err.message || err) : null,
            count: devs ? devs.length : null,
          }));
        });
        setTimeout(() => resolve(JSON.stringify({called: false})), 10000);
      })`));

      assert.ok(called.called, 'chrome.hid.getDevices never called back');
      assert.equal(called.lastError, null,
        `chrome.hid.getDevices reported ${called.lastError}`);
      log(`getDevices saw ${called.count} device(s)`);
    } finally {
      page.close();
    }
  });
});
