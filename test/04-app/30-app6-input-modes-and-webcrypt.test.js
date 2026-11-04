/*
 * OnlyKey App 6.x: Preferences > Advanced - User Input Modes and Webcrypt Access, end to end on a
 * physical DEVELOPER key, driven over CDP (lib/app6.js) with every press and PIN going through the
 * key's debug console. Nobody touches the key.
 *
 * What is checked, each twice - in the App (its LAST MESSAGES strip shows the firmware's own reply)
 * and on the key (its console logs each EEPROM write):
 *   - outside config mode the firmware refuses: "Error not in config mode";
 *   - in config mode, Save User Input Modes writes three fields (okcore.cpp cases 21, 22, 30) and
 *     Save Webcrypt Access writes one (case 31), each "Successfully set ...";
 *   - the original settings are put back, and the key leaves config mode by restarting.
 *
 * NEVER CLICKED: "Set Full Wipe Mode" and "Lock Backup Key" - the App says both "cannot be changed".
 *
 * Runs against the key whose debug console is found by usage page 0xffc9 on a real USB interface
 * (interface number >= 0: never the emulator driver's look-alikes). One key only. Its PIN must be
 * the kit's primary PIN (lib/config.js) - a fixture-provisioned developer key.
 *
 *   OKT_APP_DIR=<App 6 checkout> OKT_APP6_NW=<nwjs-sdk-v0.104.1 nw> okt run test/04-app/30-app6-input-modes-and-webcrypt.test.js
 */
'use strict';

const path = require('path');
const { describe, it } = require('../../lib/harness');
const { PINS } = require('../../lib/config');
const { App6Session } = require('../../lib/app6');
const { KIT_ROOT } = require('../../lib/paths');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/* the key's debug console: read every line, write a line as 32-byte reports behind report ID 0 */
/*
 * The handle is REOPENED when the key restarts or re-enumerates (a restart, the config-mode relock):
 * the old one errors and goes deaf, and a reader that stays on it hears nothing after - measured: the
 * EEPROM writes went unheard after the run's opening restart. Old handles are kept referenced
 * (closing one inside its own error callback can abort node on Windows - lib/device/hardware.js).
 */
function openConsole() {
  const HID = require('node-hid');
  const find = () => HID.devices().filter((d) => d.vendorId === 0x1d50 && d.usagePage === 0xffc9 && d.interface >= 0);
  const first = find();
  if (first.length !== 1) throw new Error(`need exactly one physical key's debug console, found ${first.length}`);
  const con = { lines: [], buf: '', h: null, closed: false, dead: [] };
  const onData = (b) => {
    con.buf += Buffer.from(b).toString('latin1').replace(/\0+/g, '');
    let i;
    while ((i = con.buf.indexOf('\n')) >= 0) {
      con.lines.push(con.buf.slice(0, i).replace(/\r$/, ''));
      con.buf = con.buf.slice(i + 1);
    }
  };
  const attach = () => {
    if (con.closed) return;
    const found = find();
    if (found.length !== 1) { setTimeout(attach, 500); return; }
    try {
      const h = new HID.HID(found[0].path);
      h.on('data', onData);
      h.on('error', () => {
        h.removeAllListeners('data');
        con.dead.push(h);
        if (con.h === h) con.h = null;
        setTimeout(attach, 500);
      });
      con.h = h;
    } catch { setTimeout(attach, 500); }
  };
  attach();
  con.line = (text) => {
    const report = Buffer.alloc(33);
    Buffer.from(`${text}\n`, 'latin1').copy(report, 1);
    try { con.h.write([...report]); } catch {
      /* mid re-enumeration: write through a fresh handle, and let attach() restore the reader */
      const again = find()[0];
      const w = new HID.HID(again.path);
      w.write([...report]);
      con.dead.push(w);
    }
  };
  con.since = (n) => con.lines.slice(n).join('\n');
  con.close = () => { con.closed = true; try { if (con.h) con.h.close(); } catch { /* gone */ } };
  return con;
}

describe('App 6: User Input Modes and Webcrypt Access on a developer key', {
  device: false,
  requires: ['app6'],
  timeoutMs: 600000,
}, () => {
  let session = null;
  let con = null;
  let page = null;
  const original = {};

  const text = () => page.eval('document.body.innerText');
  /* under the runner's 30 s no-progress watchdog */
  /* a wait that fails leaves its evidence: a screenshot, the App's message strip, the key's console */
  const waitText = (re, what, timeoutMs = 25000) => page.waitFor(
    `${re}.test(document.body.innerText)`, { timeoutMs }).catch(async () => {
    const shot = path.join(KIT_ROOT, 'runs', 'app6', `fail-${Date.now()}.png`);
    try { await session.screenshot(shot); } catch { /* the window may be gone */ }
    let strip = '';
    try {
      strip = await page.eval(`(() => { const t = document.body.innerText; const i = t.indexOf('LAST MESSAGES');
        return i >= 0 ? t.slice(i, i + 400) : t.slice(-400); })()`);
    } catch { /* gone */ }
    throw new Error(`the App never showed ${what}. Screenshot: ${shot}. App messages: ${JSON.stringify(strip)}. `
      + `Key console: ${JSON.stringify(con ? con.lines.slice(-12).join(' | ') : '')}`);
  });
  /* a button by its text (the sidebar's emoji line dropped); tab: true picks a role="tab" -
   * "Advanced" is both a Preferences tab and a sidebar page */
  const click = (label, { tab = false } = {}) => page.eval(`(() => { const want = ${JSON.stringify(label)};
    const el = [...document.querySelectorAll(${JSON.stringify(tab ? '[role=tab]' : 'button:not([role=tab])')})]
      .find((e) => e.offsetParent !== null && (e.innerText || '').trim().replace(/^\\S+\\s*\\n/, '') === want);
    if (!el) return false; el.click(); return true; })()`);
  const radios = (name) => page.eval(`[...document.querySelectorAll('input[name=${name}]')].map((e) => e.checked)`);
  const pickRadio = (name, i) => page.eval(`(() => { document.querySelectorAll('input[name=${name}]')[${i}].click(); return true; })()`);
  const box = (label) => page.eval(`(() => { const l = [...document.querySelectorAll('label')]
    .find((x) => (x.innerText || '').trim().startsWith(${JSON.stringify(label)})); const i = l && l.querySelector('input');
    return i ? i.checked : null; })()`);
  const setBox = (label, on) => page.eval(`(() => { const l = [...document.querySelectorAll('label')]
    .find((x) => (x.innerText || '').trim().startsWith(${JSON.stringify(label)})); const i = l.querySelector('input');
    if (i.checked !== ${on}) i.click(); return i.checked; })()`);
  /*
   * AFTER AN UNLOCK THE APP GOES TO SLOTS BY ITSELF while it reads the labels (measured: a click on
   * Preferences landed first and was overridden - the save then hit a page that was not showing). So
   * the App is let settle, and the page is checked visible before anything is clicked; retried.
   */
  const advancedShowing = () => page.eval(`(() => { const b = [...document.querySelectorAll('button')]
    .find((e) => (e.innerText || '').trim() === 'Save User Input Modes'); return !!(b && b.offsetParent !== null); })()`);
  const openAdvancedPrefs = async () => {
    for (let attempt = 1; attempt <= 5; attempt++) {
      await click('Preferences');
      await sleep(800);
      await click('Advanced', { tab: true });
      await sleep(1200);
      if (await advancedShowing()) return;
    }
    await waitText('/(?!)/', 'the Advanced preferences after 5 attempts');
  };
  /* the App's post-unlock work (label reads, its own navigation) is done once the strip stops moving */
  const settle = async () => {
    let last = '';
    for (let i = 0; i < 12; i++) {
      const now = await page.eval(`(() => { const t = document.body.innerText; const i = t.indexOf('LAST MESSAGES');
        return i >= 0 ? t.slice(i, i + 300) : ''; })()`);
      if (now === last) return;
      last = now;
      await sleep(1000);
    }
  };

  it('starts App 6 from its own build and finds the key', async ({ log }) => {
    con = openConsole();
    session = new App6Session({ logDir: path.join(KIT_ROOT, 'runs', 'app6') });
    page = await session.start({ progress: log });   // the build and the window take a while: say so
    await waitText('/OnlyKey Locked|Unlocked|Config mode/', 'the key');
    const { APP_DIR } = require('../../lib/app');
    const version = JSON.parse(require('fs').readFileSync(path.join(APP_DIR, 'package.json'), 'utf8')).version;
    log(`App ${version} (${APP_DIR}): ${(await text()).match(/OnlyKey Locked|Unlocked|Config mode/)[0]}`);
  });

  it('unlocks through the key console, and the App follows', async ({ assert, log }) => {
    /*
     * ALWAYS RESTARTED FIRST, so every run starts from the same state. Config mode ends only with a
     * restart, and the App cannot be asked about it: connecting to a key that an interrupted run left
     * in config mode, App 6 showed "Unlocked" - and a save "outside" config mode then succeeded
     * (measured 2026-10-22).
     */
    log('restarting the key through its console (a known start: not in config mode)');
    con.line('8');
    await sleep(6000);
    await waitText('/OnlyKey Locked/', 'the key back, locked, after the restart');
    con.line(PINS.primary);
    await waitText('/\\bUnlocked\\b/', 'Unlocked');
    await settle();
    assert.ok(true);
  });

  it('refuses User Input Modes outside config mode: "Error not in config mode"', async ({ assert }) => {
    await openAdvancedPrefs();
    original.derived = await radios('derivedKeyInput');
    original.stored = await radios('storedKeyInput');
    original.web = await radios('webAgentDeriveInput');
    original.allowStored = await box('Allow Webcrypt to use my stored keys');
    original.webcryptOff = await box('Turn off Webcrypt entirely');
    assert.ok(await click('Save User Input Modes'), 'no Save User Input Modes button');
    await waitText('/Error not in config mode/', '"Error not in config mode"');
  });

  it('enters config mode through the console (hold 6, then the PIN), and the App shows it', async () => {
    con.line('6#80');
    await waitText('/OnlyKey Locked/', 'the key locking after the config-mode hold');
    await sleep(1500);
    con.line(PINS.primary);
    await waitText('/Config mode/', 'Config mode', 25000);
    await settle();
  });

  it('saves User Input Modes: the firmware writes all three fields', async ({ assert, log }) => {
    await openAdvancedPrefs();
    /* a combination unlike the original in every family: the other choice of each */
    const flip = (cur) => (cur.indexOf(true) === 0 ? 1 : 0);
    await pickRadio('derivedKeyInput', flip(original.derived));
    await pickRadio('storedKeyInput', flip(original.stored));
    await pickRadio('webAgentDeriveInput', flip(original.web));
    const mark = con.lines.length;
    assert.ok(await click('Save User Input Modes'));
    for (const reply of ['Successfully set derived key challenge mode', 'Successfully set stored key challenge mode',
      'Successfully set web and agent derived key mode']) {
      await waitText(`/${reply}/`, `"${reply}"`);
    }
    await sleep(1000);
    const wrote = con.since(mark);
    for (const field of ['derived_key_challenge_mode', 'stored_key_challenge_mode', 'web_agent_derive_mode']) {
      assert.ok(wrote.includes(`Writing ${field} to EEPROM`), `the key's console did not log the ${field} write`);
    }
    log('App and key agree: three fields written');
  });

  it('saves Webcrypt Access: the firmware writes the policy', async ({ assert }) => {
    await setBox('Allow Webcrypt to use my stored keys', !original.allowStored);
    const mark = con.lines.length;
    assert.ok(await click('Save Webcrypt Access'));
    await waitText('/Successfully set webcrypt policy/', '"Successfully set webcrypt policy"');
    await sleep(1000);
    assert.ok(con.since(mark).includes('Writing webcrypt_policy to EEPROM'), 'the key\'s console did not log the policy write');
  });

  it('puts the original settings back', async ({ assert }) => {
    await pickRadio('derivedKeyInput', original.derived.indexOf(true));
    await pickRadio('storedKeyInput', original.stored.indexOf(true));
    await pickRadio('webAgentDeriveInput', original.web.indexOf(true));
    let mark = con.lines.length;
    assert.ok(await click('Save User Input Modes'));
    await sleep(3000);
    assert.equal((con.since(mark).match(/Writing \w+ to EEPROM/g) || []).length, 3, 'three writes back');
    await setBox('Allow Webcrypt to use my stored keys', original.allowStored);
    await setBox('Turn off Webcrypt entirely', original.webcryptOff);
    mark = con.lines.length;
    assert.ok(await click('Save Webcrypt Access'));
    await sleep(3000);
    assert.ok(con.since(mark).includes('Writing webcrypt_policy to EEPROM'), 'policy written back');
  });

  it('leaves config mode by restarting the key, and it unlocks again', async () => {
    con.line('8');
    await sleep(6000);
    await waitText('/OnlyKey Locked/', 'the key back, locked, after the restart', 25000);
    con.line(PINS.primary);
    await waitText('/\\bUnlocked\\b/', 'Unlocked after the restart', 25000);
  });

  /* a visible last step, not a hook (lib/harness.js); the kit's safety net ends the App if a run aborts */
  it('closes the App and the console', async ({ assert }) => {
    session.stop();
    con.close();
    assert.ok(true);
  });
});
