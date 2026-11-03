'use strict';
/*
 * WHICH MODEL is under test - an OnlyKey (classic) or an OnlyKey DUO.
 *
 * One firmware image serves both: it tells them apart itself at boot
 * (okcore.cpp calibratecaptouch(): the chip's package ID, then analog pin A12).
 * The kit has to know too, because the two are driven differently:
 *
 *                   classic                    DUO
 *   buttons         1..6                       1..3 (3 is both pads)
 *   PIN digits 4-6  tap 4..6                   hold 1..3 21+ rounds, while locked
 *   config mode     hold 6 (>= 72)             hold 1 (>= 180)
 *   PIN setup       OKSETPIN + presses, x3     OKSETPIN 0xFF + PINs as digits (the App's sendPinDUO)
 *   model letter    'c'                        'p' or 'n'
 *
 * Asked once, from what describes the device rather than from the device:
 *
 *   OKT_MODEL=duo|classic      says so outright - the only way for a hard key;
 *   OKEMU_HARDWARE=duo         the emulator's board (node-onlykey-emulator
 *                              index.js HARDWARE), read by its device host from
 *                              the same environment;
 *   .stage/build.json model    an emulator built with OKEMU_MODEL=duo, which
 *                              compiles the firmware's DEFINED_HWID override in.
 *
 * The device's own answer (the model letter after UNLOCKED, the -D after
 * INITIALIZED) is what the DUO tests check this against.
 */
const fs = require('node:fs');
const path = require('node:path');

let cached = null;

function deviceModel() {
  if (cached) return cached;
  const said = String(process.env.OKT_MODEL || '').toLowerCase();
  if (said === 'duo' || said === 'classic') return (cached = said);
  if (said) throw new Error(`OKT_MODEL must be duo or classic, got ${process.env.OKT_MODEL}`);
  if (String(process.env.OKEMU_HARDWARE || '').toLowerCase() === 'duo') return (cached = 'duo');
  try {
    const { emulatorRoot } = require('./paths');
    const built = JSON.parse(fs.readFileSync(path.join(emulatorRoot().dir, '.stage', 'build.json'), 'utf8'));
    if (built.model === 'duo') return (cached = 'duo');
  } catch (_) { /* no emulator, or no build.json: classic */ }
  return (cached = 'classic');
}

const isDuo = () => deviceModel() === 'duo';

/*
 * The presses that type a PIN on this model, as pressLine() items. On a DUO,
 * payload() (OnlyKey.ino) turns a press of 21+ rounds into button + 3 while the
 * key is locked; 40 rounds sits in the middle of 21..71, where
 * node-onlykey-lib's PRESS_TICKS.HOLD sits.
 */
const DUO_DIGIT_TICKS = 40;

function pinPresses(pin) {
  const digits = String(pin).split('').map(Number);
  if (digits.some((d) => !Number.isInteger(d) || d < 1 || d > 6)) {
    throw new RangeError(`PIN digits are 1..6, got ${pin}`);
  }
  if (!isDuo()) return digits;
  return digits.map((d) => (d > 3 ? { button: d - 3, ticks: DUO_DIGIT_TICKS } : d));
}

/* The model letter HW_MODEL() appends after UNLOCKED. */
const MODEL_LETTER = { classic: /c$/, duo: /[pn]$/ };

module.exports = { deviceModel, isDuo, pinPresses, MODEL_LETTER, DUO_DIGIT_TICKS };
