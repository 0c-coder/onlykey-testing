/*
 * keyboard.js - HID keyboard reports back into the text the device typed.
 *
 * The emulator surfaces the keyboard interface as an EVENT rather than as a
 * device node to be read with elevated privileges, and that is what makes a
 * whole class of tests possible at all: everything OnlyKey does by typing -
 * passwords, backups, TOTP - is observable here with no root and no /dev/hidraw.
 *
 * The report is the stock 8-byte boot-protocol layout that
 * core-override/okemu_usb.cpp fills:
 *
 *   [0] modifier bitmap   [1] reserved(0)   [2..7] up to six keycodes
 *
 * A key is "pressed" in one report and released by the next report that omits
 * it, so a naive decoder that reads every report emits every character twice.
 * Decoding is therefore edge-triggered: only keycodes not present in the
 * previous report count.
 *
 * THE DECODING NOW COMES FROM node-onlykey-lib (device.keystrokes - one lib,
 * any GUI; the test CLI is a GUI). The library's decoder is built by inverting
 * the FIRMWARE'S OWN character table (keylayouts.c), so it knows exactly the
 * reports the device can send, per keyboard layout, dead keys included. It
 * differs from the generic US map this file used to carry on four keys, all
 * deliberately (owner's decision, 2026-09-27; no kit test depended on them):
 *   - Shift+Space: the firmware never sends it (ASCII_20 = KEY_SPACE, unshifted
 *     in every layout); the library reports it as unmapped, not as a space
 *   - 0x32, the ISO #/~ key: layout-dependent, not on a US board
 *   - Escape and Backspace: named keys with no text, rather than \x1b / \b
 *
 * What stays here is the kit's interface: a KeystrokeDecoder whose clear()
 * empties the text but KEEPS the held-key state - a clear() between two
 * reports of one keystroke must not make a still-held key count again - and a
 * report counter the decoder tests read.
 */
'use strict';

const { keystrokes } = require('node-onlykey-lib/device');

/* Modifier bits, by the names the kit's tests use (the library's are
 * LCTRL/LSHIFT/..., same values). */
const MOD = {
  LEFT_CTRL: 0x01,
  LEFT_SHIFT: 0x02,
  LEFT_ALT: 0x04,
  LEFT_GUI: 0x08,
  RIGHT_CTRL: 0x10,
  RIGHT_SHIFT: 0x20,
  RIGHT_ALT: 0x40,
  RIGHT_GUI: 0x80,
};

/** The character one keycode types under these modifiers ('' if none). */
function charFor(code, modifiers) {
  const d = keystrokes.createDecoder();
  d.push([modifiers, 0, code, 0, 0, 0, 0, 0]);
  return d.text;
}

class KeystrokeDecoder {
  constructor() {
    this._decoder = keystrokes.createDecoder();
    this._from = 0;       // where text starts, after the last clear()
    this.reports = 0;
  }

  /** Everything typed since construction or the last clear(). */
  get text() {
    return this._decoder.text.slice(this._from);
  }

  /** Feed one report; returns the characters it produced. */
  feed(report) {
    if (!report || report.length < 3) return '';
    this.reports++;
    return this._decoder.push(report).map((e) => e.text).join('');
  }

  /* Text only - the library's reset() would also forget the held keys. */
  clear() {
    this._from = this._decoder.text.length;
  }
}

module.exports = { KeystrokeDecoder, charFor, MOD };
