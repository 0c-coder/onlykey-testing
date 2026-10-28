/*
 * The debug console (SEREMU, interface 3) and its line protocol.
 *
 * This is the channel every other file in this section drives the device
 * through, so its guarantees are worth pinning down: one echo per completed
 * line carrying that line's first byte, and a firmware-side parser with two
 * limits that the host side has to respect rather than discover.
 */
'use strict';

const { describe, it } = require('../../lib/harness');

describe('debug console', { state: 'blank' }, () => {
  it('echoes the first byte of a completed line', async ({ device, assert, signal }) => {
    device.log.clear();
    device.press(1);

    /* okcore.cpp prints "I received from DEBUG: <code>" once per completed
     * line, carrying the line's first byte - '1' is 49. It is the one universal
     * acknowledgement this channel has. */
    const match = await device.log.waitFor(/I received from DEBUG: 49(?!\d)/, { signal });
    assert.ok(match, 'no echo for a pressed button');
  });

  it('echoes once per line, not once per press', async ({ device, assert, signal }) => {
    device.log.clear();

    /* Six presses in ONE line: the firmware replays them one per loop()
     * iteration, so the whole burst is one command and gets one echo. This is
     * exactly why PIN entry can be a single write with no host-side delay
     * between digits to get wrong. Buttons 1-3, which every model has. */
    device.pressLine([1, 2, 3, 1, 2, 3]);
    await device.log.waitFor(/I received from DEBUG: 49(?!\d)/, { signal });

    /* Give any further echoes time to arrive before counting - asserting a
     * count immediately after the first match would pass even if the firmware
     * were about to send five more. */
    await device.sleep(500, { signal });
    assert.equal(device.log.count(/I received from DEBUG:/g), 1,
      'one line should produce exactly one echo');
  });

  it('counts every echo in a burst of separate lines', async ({ device, assert, signal }) => {
    device.log.clear();
    device.press(2);
    device.press(2);
    device.press(2);

    /*
     * waitForCount, not waitFor. The firmware acknowledges per line, so a
     * first-match wait returns while two more are still in flight - and the
     * next test then starts against a device that is still working through
     * this one's input.
     */
    const seen = await device.log.waitForCount(/I received from DEBUG: 50(?!\d)/g, 3,
      { timeoutMs: 8000, signal });
    assert.ok(seen >= 3, `expected 3 echoes, saw ${seen}`);
  });

  it('matches retroactively against output that already arrived',
    async ({ device, assert, signal }) => {
      device.log.clear();
      device.press(3);
      await device.log.waitFor(/I received from DEBUG: 51(?!\d)/, { signal });

      /* Armed long after the fact, and still satisfied: half the waits in this
       * kit are for something the device has already said. */
      const again = await device.log.waitFor(/I received from DEBUG: 51(?!\d)/,
        { timeoutMs: 10, signal });
      assert.ok(again, 'a wait must match what is already in the accumulator');
    });

  it('clears only when the caller asks', async ({ device, assert, signal }) => {
    device.log.clear();
    device.press(3);   /* a button every model has */
    await device.log.waitFor(/I received from DEBUG: 51(?!\d)/, { signal });
    assert.ok(device.log.text.length > 0, 'the accumulator should hold what arrived');

    device.log.clear();
    assert.equal(device.log.count(/I received from DEBUG:/g), 0, 'clear() should empty it');
  });

  it('refuses a press line the firmware could not parse', async ({ device, assert }) => {
    /* DBG_LINE_MAX is 32 bytes, one SEREMU OUT report, and the hold modifiers
     * can exhaust it before the queue does - sixteen 'longest' holds is 64
     * bytes. Failing here, on the host, beats sending something the firmware
     * silently truncates. */
    await assert.rejects(
      async () => device.pressLine(new Array(16).fill({ button: 1, hold: 'longest' })),
      /press line is \d+ bytes/
    );

    /* DBG_QUEUE_MAX is 16; past that the firmware drops the tail. */
    await assert.rejects(
      async () => device.pressLine(new Array(17).fill(1)),
      /at most 16 presses/
    );

    await assert.rejects(async () => device.press(7), /button must be 1\.\.6/);
    await assert.rejects(async () => device.press(0), /button must be 1\.\.6/);
  });
});
