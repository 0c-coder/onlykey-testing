/*
 * The apps.crp.to router: the 2022 web app, plus the version-route plugin
 * (onlykey/onlykey.github.io PR #41), sends firmware newer than v3.0.4 to the
 * same page on apps.onlykey.io.
 *
 * The plugin only acts when location.hostname is exactly apps.crp.to, and the
 * key only answers the WebAuthn request if the browser made it for rpId
 * apps.crp.to - which it only does for a page served at https://apps.crp.to.
 * So this file makes the browser believe it is there, without Heroku:
 *
 *   - the router build (OKT_CRPTO_ROUTER, default /opt/ok/crpto-router, built
 *     with `bash BUILD.sh 1`) is served by its own index.js over HTTPS on 3000,
 *     with a throwaway certificate for apps.crp.to and apps.onlykey.io;
 *   - a stub answers for apps.onlykey.io on 3001, so the redirect has somewhere
 *     real to land and the landing can be seen;
 *   - nw.js gets --host-resolver-rules mapping both names to 127.0.0.1 and
 *     --ignore-certificate-errors-spki-list for that one certificate, so the
 *     page is a secure context and WebAuthn is allowed.
 *
 * The emulated key is DEBUG v3.0.5 (`-test`), which is "newer than v3.0.4", so
 * the expected outcome is a redirect. A v3.0.4 key staying put is covered by
 * test/version-route.test.js in the router branch; there is no v3.0.4 emulator.
 *
 * Runs on its own: it starts its own server on 3000 and browser on 9222, so do
 * not run it in the same invocation as 03-gui/10-session.
 */
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const https = require('https');
const { execFileSync } = require('child_process');

const { describe, it } = require('../../lib/harness');
const gui = require('../../lib/gui');
const { PINS } = require('../../lib/config');

const ROUTER = process.env.OKT_CRPTO_ROUTER || '/opt/ok/crpto-router';
const STUB_PORT = 3001;

function makeCert(dir) {
  const key = path.join(dir, 'key.pem');
  const cert = path.join(dir, 'cert.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2',
    '-keyout', key, '-out', cert, '-subj', '/CN=apps.crp.to',
    '-addext', 'subjectAltName=DNS:apps.crp.to,DNS:apps.onlykey.io'], { stdio: 'ignore' });
  const pub = execFileSync('openssl', ['x509', '-in', cert, '-pubkey', '-noout']);
  const der = execFileSync('openssl', ['pkey', '-pubin', '-outform', 'der'], { input: pub });
  const spki = require('crypto').createHash('sha256').update(der).digest('base64');
  return { key, cert, spki };
}

describe('apps.crp.to router', {
  state: 'initialized',
  requires: ['client-access', 'display', 'nwjs'],
  timeoutMs: 240000,
}, () => {
  it('sends a v3.0.5 key from apps.crp.to/app/decrypt to apps.onlykey.io/app/decrypt',
    async ({ device, assert, signal, log, skip }) => {
      if (!fs.existsSync(path.join(ROUTER, 'docs', 'app'))) {
        skip(`no router build at ${ROUTER}/docs - build it with  bash BUILD.sh 1`);
      }
      const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'okt-crpto-'));
      const { key, cert, spki } = makeCert(tmp);
      fs.copyFileSync(key, path.join(ROUTER, '_._server.key'));
      fs.copyFileSync(cert, path.join(ROUTER, '_._server.cert'));

      const stub = https.createServer({ key: fs.readFileSync(key), cert: fs.readFileSync(cert) }, (req, res) => {
        res.writeHead(200, { 'content-type': 'text/html' });
        res.end(`<!doctype html><title>apps.onlykey.io stub</title><p id="stub">stub ${req.url}</p>`);
      });
      await new Promise((r) => stub.listen(STUB_PORT, '127.0.0.1', r));

      const s = new gui.GuiSession({ logDir: tmp, userDataDir: path.join(tmp, 'udata') });
      let page = null;
      try {
        s.server = gui.launch('crpto router', process.execPath, ['index.js'], {
          cwd: ROUTER, logFile: path.join(tmp, 'router.log'), env: { PORT: '' },
        });
        await gui.waitFor('the router on 3000', async () => new Promise((resolve) => {
          const req = https.get({ host: '127.0.0.1', port: 3000, path: '/', rejectUnauthorized: false },
            (res) => { res.resume(); resolve(res.statusCode === 200); });
          req.on('error', () => resolve(false));
        }), { timeoutMs: 30000, signal });

        s.browser = gui.launch('nw.js', gui.findNw(), [
          gui.NW_APP,
          `--user-data-dir=${path.join(tmp, 'udata')}`,
          `--remote-debugging-port=${gui.CDP_PORT}`,
          '--disable-gpu', '--disable-software-rasterizer', '--disable-dev-shm-usage',
          `--host-resolver-rules=MAP apps.crp.to:443 127.0.0.1:3000, MAP apps.onlykey.io:443 127.0.0.1:${STUB_PORT}`,
          `--ignore-certificate-errors-spki-list=${spki}`,
        ], { cwd: gui.NW_APP, logFile: path.join(tmp, 'nwjs.log') });
        await gui.waitFor('nw.js on CDP', async () => (await gui.get(gui.CDP_PORT, '/json/version')).code === 200,
          { timeoutMs: 60000, signal });

        /* Device up and unlocked BEFORE the app page opens (native WebAuthn dialog). */
        await device.ensureUnlocked(PINS.primary, { signal });

        page = await s.open('https://apps.crp.to/app/decrypt', { timeoutMs: 60000, signal });
        const seen = [];
        const landed = await gui.waitFor('the page to reach apps.onlykey.io', async () => {
          const t = (await s.targets()).find((x) => x.id === page.targetId);
          const url = t && t.url;
          if (url && seen[seen.length - 1] !== url) { seen.push(url); log(`page: ${url}`); }
          if (url && url.startsWith('https://apps.crp.to')) {
            const msg = await page.eval(`(document.getElementById('header_messages')||{}).innerText || ''`).catch(() => '');
            if (msg && seen.indexOf('msg:' + msg) === -1) { seen.push('msg:' + msg); log(`apps.crp.to says: ${msg.replace(/\s+/g, ' ').trim()}`); }
          }
          return url && url.startsWith('https://apps.onlykey.io') ? url : null;
        }, { timeoutMs: 60000, pollMs: 500 }).catch(async (e) => {
          log(`no redirect: ${e.message}`);
          const diag = await page.eval(`JSON.stringify({secure: window.isSecureContext, host: location.hostname,
            webauthn: typeof (navigator.credentials && navigator.credentials.get),
            header: (document.getElementById('header_messages')||{}).innerHTML || '',
            body: document.body ? document.body.innerText.slice(0, 400) : ''})`).catch((x) => 'eval failed: ' + x.message);
          log(`page state: ${diag}`);
          log(`console: ${JSON.stringify((page.console || []).slice(-25)).slice(0, 3000)}`);
          return null;
        });

        /* The 2022 decrypt page adds ?type=dv to its own URL on load; the route
         * keeps the query, so that is where it lands. */
        assert.ok(landed && /^https:\/\/apps\.onlykey\.io\/app\/decrypt(\?|$)/.test(landed),
          `the router did not send the v3.0.5 key to apps.onlykey.io/app/decrypt (pages seen: ${JSON.stringify(seen)})`);
        log(`landed on ${landed}`);
      } finally {
        if (page) { try { page.close(); } catch { /* going */ } }
        s.stop();
        stub.close();
        for (const f of ['_._server.key', '_._server.cert']) { try { fs.unlinkSync(path.join(ROUTER, f)); } catch { /* */ } }
      }
    });
});
