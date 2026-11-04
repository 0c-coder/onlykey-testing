/*
 * The bundle that actually ships carries no test hooks and no key logging.
 *
 * WHY THE BUNDLE AND NOT THE SOURCE. `docs/` is generated, tracked, and served -
 * BUILD.sh's last act is to write the CNAME into it - so it, not `src/`, is what
 * a visitor executes. A fix that lands in src/ and never reaches docs/ is not
 * deployed, and nothing else in this kit would notice: every other test loads
 * the library straight from src/. This file is the only thing standing between
 * "we fixed it" and "the served page still does it".
 *
 * It caught exactly that. After the transit key stopped being logged in src/,
 * the committed bundle still contained four "Transit shared secret" strings,
 * four "AES Key", and the window test hook, because docs/ had last been built
 * before the strip.
 *
 * WHY `NODE_ENV === "production"` IS NOT THE ANSWER for the test hook, which is
 * the trap worth recording: `BUILD.sh` with no argument runs `build-site`, which
 * is `NODE_ENV=development`, and that is what has been committed to docs/ (the
 * bundle carries the string "development"). `BUILD.sh 1` is the production
 * build and is what heroku-postbuild runs. So gating a debug global on a
 * production check leaves it present in the artifact this repo actually serves.
 * Removing it is the only fix that reaches the deployed page.
 *
 * `device: false` - the subject is a build artifact.
 */
'use strict';

const fs = require('fs');
const path = require('path');

const { describe, it } = require('../../lib/harness');
const { CHECKOUTS_ROOT } = require('../../lib/paths');

const APP_DIR = path.join(CHECKOUTS_ROOT, 'onlykey.github.io', 'docs', 'app');

/* Substrings that must not appear in a shipped bundle, and why. */
const FORBIDDEN = [
  ['__pgpPqcTestHooks',
    'a debug global handing openpgp, the composite module and the live `ok` '
    + 'device transport to any script running in the page origin'],
  ['Transit shared secret',
    'the OKCONNECT transit key, printed to the console'],
  ['"AES Key"',
    'the AES-256 session key derived from the transit key, printed to the console'],
  ['ONLYLEY: derivedBits raw',
    'a raw derived shared secret, printed to the console'],
  ['ctaphid_request:',
    'a dump of every request buffer sent to the device'],
  ['ctaphid_response:',
    'a dump of every response buffer returned by the device'],
];

describe('the shipped bundle carries no debug hooks or key logging', {
  device: false,
  negative: true,
}, () => {
  let bundle = null;
  let name = null;

  it('finds the built bundle that docs/ serves', async ({ assert, skip, log }) => {
    if (!fs.existsSync(APP_DIR)) skip(`no built app at ${APP_DIR}`);

    const bundles = fs.readdirSync(APP_DIR)
      .filter((f) => /^bundle\.[0-9a-f]+\.js$/.test(f));
    assert.equal(bundles.length, 1,
      `expected exactly one bundle in docs/app, found ${JSON.stringify(bundles)}`);

    name = bundles[0];
    bundle = fs.readFileSync(path.join(APP_DIR, name), 'utf8');
    log(`${name}, ${(bundle.length / 1048576).toFixed(1)} MiB`);

    /*
     * CONTROL: this is the application bundle and not some other artifact.
     * A marker unique to the page under test proves the search below is
     * looking at code that contains this feature at all - an absence found in
     * the wrong file is the emptiest kind of pass.
     */
    assert.control('the bundle is the app bundle and contains the pgp-pqc page',
      bundle.includes('pgp_setpqc_cmd') && bundle.includes('composite'));
  });

  it('contains none of the debug surface', async ({ assert, skip, log }) => {
    /*
     * NO BUNDLE, NO VERDICT. When the test above skipped (no built app here -
     * a CI runner never checks one out), `bundle` is still null, and reading it
     * crashed this test with a TypeError - a failure of the kit reported as a
     * failure of the bundle (the GitHub Actions gate, 2026-09-30). Skip with
     * the same reason instead.
     */
    if (bundle === null) skip(`no bundle was read - no built app at ${APP_DIR}`);

    /*
     * CONTROL: the matcher works on this haystack. Without it, a bundle read
     * as an empty string would report six clean absences.
     */
    assert.control('a substring that IS present is found in the bundle',
      bundle.includes('pgp_setpqc_cmd'));

    for (const [needle, why] of FORBIDDEN) {
      const count = bundle.split(needle).length - 1;
      assert.absent(count === 0,
        `the shipped bundle (${name}) contains ${count}x ${JSON.stringify(needle)} - ${why}. `
        + 'Rebuild docs/ with BUILD.sh after fixing src/, or the served page keeps doing it.');
    }
    log(`none of the ${FORBIDDEN.length} forbidden strings appear in ${name}`);
  });
});
