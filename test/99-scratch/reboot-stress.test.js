'use strict';
/* Scratch, not part of the kit: reboot a hard key many times in one process, to reproduce the Windows
 * native crash (V8 array_buffer_allocator) the kit hits around device reconnects. */
const { describe, it } = require('../../lib/harness');
const N = Number(process.env.OKT_STRESS_REBOOTS || 60);
describe('reboot stress', { requires: ['device'], timeoutMs: 1800000 }, () => {
  it(`reboots ${N} times`, async ({ device, log, signal }) => {
    for (let i = 1; i <= N; i++) {
      await device.restart({ signal });
      if (i % 10 === 0) log(`reboot ${i}/${N} ok (generation ${device.generation})`);
    }
  });
});
