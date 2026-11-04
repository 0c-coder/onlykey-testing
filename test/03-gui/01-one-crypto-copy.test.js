/*
 * Section 3: the web app carries no crypto library of its own.
 *
 * ONE COPY (audit #2). The web app used to vendor @noble 2.2.0 while the kit
 * and node-onlykey-lib ran 2.4.0, and this file's predecessor
 * (01-age-pqc-parity) caught the drift: the web app's own maths against the
 * kit's. Since the port (2026-09-29) the web app runs node-onlykey-lib, whose
 * vendored @noble (src/vendor/VENDORED.md) is the project's one copy - so the
 * check becomes the rule itself: the checkout under test has NO copy of its
 * own, neither vendored in its source nor declared as a dependency. A copy
 * that comes back is a second copy to drift, and fails here by name.
 */
'use strict';

const fs = require('fs');
const path = require('path');

const { describe, it } = require('../../lib/harness');
const webenv = require('../../lib/webenv');

const OWN_COPIES = ['@noble', 'openpgp', 'kbpgp', 'forge', 'nacl', 'tweetnacl'];

/** Directories under `dir` whose name is one of OWN_COPIES (or starts with it), node_modules excluded. */
function vendoredCopies(dir, out = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.name === 'node_modules' || e.name.startsWith('.')) continue;
    const full = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (OWN_COPIES.some((n) => e.name === n || e.name.startsWith(`${n}-`))) out.push(full);
      else vendoredCopies(full, out);
    } else if (/^(kbpgp|forge|nacl)[.-].*\.js$/.test(e.name)) {
      out.push(full);
    }
  }
  return out;
}

describe('the web app carries no crypto library of its own', {
  requires: ['webapp-lib'],
}, () => {
  it('vendors none in its source', async ({ assert, log }) => {
    const found = vendoredCopies(webenv.WEBAPP_SRC);
    log(`scanned ${webenv.WEBAPP_SRC}: ${found.length ? found.join(', ') : 'none'}`);
    assert.equal(found.length, 0,
      `the web app vendors its own copy (${found.join(', ')}) - node-onlykey-lib's is the one copy (src/vendor/VENDORED.md)`);
  });

  it('declares none as a dependency, and does declare the library', async ({ assert }) => {
    const pkg = JSON.parse(fs.readFileSync(path.join(webenv.WEBAPP_SRC, '..', 'package.json'), 'utf8'));
    const deps = { ...pkg.dependencies, ...pkg.devDependencies };
    const own = Object.keys(deps).filter((d) => /^@noble\/|^(tweetnacl|openpgp|kbpgp|node-forge)$/.test(d));
    assert.equal(own.length, 0, `the web app depends on its own crypto: ${own.join(', ')}`);
    assert.match(String(deps['node-onlykey-lib'] || ''), /node-onlykey-lib#[0-9a-f]{40}$/,
      'the web app does not pin node-onlykey-lib by commit hash');
  });
});
