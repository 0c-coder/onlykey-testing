/*
 * TC-07: decrypting with no device attached must FAIL, cleanly.
 *
 * The negative half of TC-05, and the one the old kit could not really run. It
 * needed a hand on the cable - it printed "please UNPLUG the OnlyKey now" and
 * waited up to two minutes for a human - so it was skipped unless somebody set
 * ONLYKEY_TEST_PHYSICAL_UNPLUG=yes, which in practice meant it did not run.
 *
 * The gadget can unplug itself. Unbinding it from its UDC is a real bus-level
 * disconnect: the host tears down the hidraw nodes, and hidapi - which is how
 * python-onlykey finds anything - sees no device at all. The firmware keeps
 * running with its RAM intact throughout, which a hand on the cable could not
 * have arranged either, since an OnlyKey is bus-powered and unplugging it cuts
 * power too. So this is not merely the old test automated; it is a cleaner
 * experiment than the old test could perform.
 *
 * What is under test is the FAILURE, and there are three ways to get it wrong
 * that all look like "it didn't work": hanging until something kills it,
 * exiting zero having produced nothing, and writing a truncated or empty output
 * file. A test that only checked the exit code would pass on the third.
 */
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');

const { describe, it } = require('../../lib/harness');
const { PINS } = require('../../lib/config');
const cli = require('../../lib/cli');
const pqc = require('../../lib/pqc');

const SLOT = 101;

describe('decrypting with no device on the bus', {
  state: 'initialized',
  requires: ['crypto', 'client-access', 'bus-detach'],
  timeoutMs: 240000,
}, () => {
  let dir = null;

  const at = (name) => path.join(dir, name);

  it('prepares a file that only this device can read',
    async ({ device, assert, signal, log }) => {
      /*
       * The setup has to happen WITH the device, which is the shape of the
       * test: an identity that was perfectly good a moment ago has to stop
       * working for one reason only - the device is gone.
       */
      dir = fs.mkdtempSync(path.join(os.tmpdir(), 'okt-tc07-'));
      fs.writeFileSync(at('plaintext.txt'), 'TC-07: readable only with the device.\n');
      log(`working in ${dir}`);

      const gen = await pqc.generate(device, ['--generate', '--slot', String(SLOT)], { signal });
      assert.equal(gen.code, 0, `--generate failed: ${gen.stderr}`);

      await device.restart({ signal });
      await device.unlock(PINS.primary, { signal });

      const identity = await cli.run('age-plugin-onlykey',
        ['--identity', '--slot', String(SLOT)], { timeoutMs: 30000, signal });
      assert.equal(identity.code, 0, `--identity failed: ${identity.stderr}`);
      fs.writeFileSync(at('identity.txt'), identity.stdout);

      const recipient = pqc.parseGenerated(gen).recipient;
      const enc = await pqc.encrypt(recipient, at('plaintext.txt'), at('secret.age'), { signal });
      assert.equal(enc.code, 0, `age encrypt failed: ${enc.stderr}`);
      assert.ok(fs.existsSync(at('secret.age')), 'age produced no output file');
    });

  it('takes the device off the bus', async ({ device, assert, signal }) => {
    /*
     * A visible step, not a hook, and it asserts the thing it is for: hidapi
     * must see nothing. Checking that rather than the write that caused it is
     * the difference between this test and a race - the unbind is asynchronous
     * on the kernel side, and a client that enumerates in that window still
     * finds a device.
     */
    await device.unplug({ signal });

    const seen = await cli.run('python3', ['-c', [
      'import hid, json',
      'ds = [d for d in hid.enumerate(0, 0)',
      '      if d["vendor_id"] == 0x1d50 and d["product_id"] == 0x60fc]',
      'print(json.dumps(len(ds)))',
    ].join('\n')], { timeoutMs: 20000, signal });

    assert.equal(seen.code, 0, `enumeration failed: ${seen.stderr}`);
    assert.equal(seen.stdout.trim(), '0',
      'hidapi can still see an OnlyKey after the gadget was unbound');
  });

  it('fails, rather than hanging or lying', async ({ assert, signal }) => {
    const result = await cli.run('age',
      ['-d', '-i', at('identity.txt'), '-o', at('decrypted.txt'), at('secret.age')],
      { timeoutMs: 45000, signal, env: cli.venvPathEnv() });

    /*
     * Three separate failures, because they are three different bugs.
     *
     * A hang is the worst of them and the reason the old kit's comment kept
     * saying "no crash/hang": a plugin that blocks forever on a device that
     * will never answer takes the whole agent down with it, and looks like a
     * slow decrypt right up until the timeout.
     */
    assert.ok(!result.timedOut,
      `age -d hung and had to be killed instead of failing: ${result.stderr}`);
    assert.notEqual(result.code, 0,
      `age -d exited 0 with no device attached: ${result.stdout}`);
    assert.ok(!fs.existsSync(at('decrypted.txt')),
      'age -d wrote an output file for a decryption that could not have happened');

    /*
     * And it has to SAY something. age does not relay the plugin's stderr, so
     * the plugin's own "Is it plugged in and unlocked?" never arrives - what
     * reaches here is age's own wrapper. Both are accepted, since this same
     * assertion should hold if it is ever pointed at the plugin directly.
     */
    assert.match(result.stderr,
      /age: error: onlykey plugin|could not connect to onlykey|no identity matched|plugged in/i,
      `expected a clean "no device" error, got: ${result.stderr}`);
  });

  it('puts it back, and the same file decrypts again',
    async ({ device, assert, signal }) => {
      /*
       * The control. Without it, every assertion above is also satisfied by an
       * identity that was broken from the start, a device that never had the
       * key, or a plugin that fails on everything - and the test would pass
       * just as happily while proving nothing about the cable.
       *
       * The device did not reboot, so this also shows what a bus detach is:
       * the firmware kept its RAM, including the fact that it is unlocked.
       */
      await device.plug({ signal });

      const result = await pqc.decrypt(device, {
        ageFile: at('secret.age'),
        identityFile: at('identity.txt'),
        output: at('decrypted.txt'),
      }, { signal });

      assert.equal(result.code, 0,
        `the same decrypt failed after replugging: ${result.stderr}`);
      assert.bytes(
        fs.readFileSync(at('decrypted.txt')),
        fs.readFileSync(at('plaintext.txt')),
        'the file recovered after replugging'
      );
    });

  it('cleans up after itself', async ({ assert }) => {
    fs.rmSync(dir, { recursive: true, force: true });
    assert.ok(!fs.existsSync(dir), `${dir} is still there`);
  });
});
