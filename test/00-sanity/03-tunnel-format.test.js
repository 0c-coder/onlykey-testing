/*
 * The WebAuthn tunnel's credential-ID format, against the layout the firmware
 * looks for.
 *
 * is_extension_request() decides whether an assertion is a vendor request by
 * looking for four magic bytes at a fixed offset. Get the offset wrong and the
 * device does not reject the request - it treats it as an ordinary credential
 * id, fails to find the credential, and answers NO_CREDENTIALS. Which is to say
 * a framing bug here looks exactly like a device that has forgotten your
 * credential, so it is worth pinning the bytes down away from the device.
 */
'use strict';

const { describe, it } = require('../../lib/harness');
const tunnel = require('../../lib/device/tunnel');

describe('tunnel format', { device: false }, () => {
  it('puts the magic where is_extension_request() looks for it',
    async ({ assert }) => {
      const out = tunnel.encodeRequest({ cmd: 0xE4 });

      assert.equal(out[0], 0xE4, 'command first');
      assert.equal(out.subarray(4, 8).toString('hex'), '8c2790f6', 'the magic at 4..8');
      assert.equal(out[8], 0);
      assert.equal(out[9], 0, 'an empty payload declares length 0');
    });

  it('declares the real payload length, not the padded one',
    async ({ assert }) => {
      /*
       * The padding exists because the firmware wants at least sixteen bytes of
       * data; the LENGTH byte still has to describe what was actually sent, or
       * the device reads sixteen bytes of request where three were meant.
       */
      const out = tunnel.encodeRequest({ cmd: 0xEC, data: Buffer.from([1, 2, 3]) });

      assert.equal(out[9], 3, 'length is 3');
      assert.equal(out.length, 26, '10 header + 16 minimum data');
      assert.equal(out.subarray(10, 13).toString('hex'), '010203');
      assert.equal(out[13], 0, 'and the rest is padding');
    });

  it('does not pad a payload that is already long enough', async ({ assert }) => {
    const data = Buffer.alloc(32, 0xAA);
    const out = tunnel.encodeRequest({ cmd: 0xEC, data });
    assert.equal(out.length, 10 + 32);
    assert.equal(out[9], 32);
  });

  it('carries the option bytes through', async ({ assert }) => {
    const out = tunnel.encodeRequest({ cmd: 0xED, opt1: 1, opt2: 2, opt3: 3 });
    assert.equal(out[1], 1);
    assert.equal(out[2], 2);
    assert.equal(out[3], 3);
  });

  it('refuses a payload too big for a credential id', async ({ assert }) => {
    await assert.rejects(
      async () => tunnel.encodeRequest({ cmd: 0xE4, data: Buffer.alloc(250) }),
      // The LIMIT, not the wording: the encoder is node-onlykey-lib's now, and
      // its message ("... the maximum payload is 245. Chunk the request ...")
      // is not the kit's old one. 245 is what the firmware's credential ID holds.
      /245/
    );
  });

  it('reads the answer out of the signature, not the authData',
    async ({ assert }) => {
      /*
       * The response convention: the signature's first byte is a CTAP1 status
       * and everything after it is the payload. authData is still a real
       * authData - its signature counter is the only part the reference client
       * reads.
       */
      const authData = Buffer.alloc(37);
      authData.writeUInt32BE(0x2A, 33);

      const assertion = new Map([
        [2, authData],
        [3, Buffer.concat([Buffer.from([0x00]), Buffer.from('payload')])],
      ]);

      const decoded = tunnel.decodeResponse(assertion);
      assert.equal(decoded.status, 'SUCCESS');
      assert.equal(decoded.data.toString('latin1'), 'payload');
      assert.equal(decoded.count, 0x2A, 'the signature counter comes from authData');
      assert.equal(decoded.error, null);
    });

  it('surfaces a device error string as an error', async ({ assert }) => {
    /* The device answers some failures with short ASCII rather than binary,
     * the same convention the vendor interface uses on its own wire. */
    const assertion = new Map([
      [2, Buffer.alloc(37)],
      [3, Buffer.concat([
        Buffer.from([0x00]), Buffer.from('Error device locked\0'),
      ])],
    ]);

    const decoded = tunnel.decodeResponse(assertion);
    assert.equal(decoded.error, 'Error device locked');
  });

  it('names a non-zero status', async ({ assert }) => {
    const assertion = new Map([[2, Buffer.alloc(37)], [3, Buffer.from([0x01])]]);
    const decoded = tunnel.decodeResponse(assertion);
    assert.equal(decoded.status, 'INVALID_COMMAND');
    assert.equal(decoded.data, null, 'a bare status carries no payload');
  });
});
