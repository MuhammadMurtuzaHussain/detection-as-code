// The dashboard evaluates rules in the browser with dac/web/engine.js, a port of the Python engine.
// These tests fail CI if the two ever disagree.
//   1. engine_vectors.json: shared unit vectors run through the JS engine.
//   2. every rule against every test log: Python's verdicts (from `python -m dac parity`) vs JS.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const DAC = require('../dac/web/engine.js');
const root = path.resolve(__dirname, '..');

const vectors = JSON.parse(fs.readFileSync(path.join(__dirname, 'engine_vectors.json'), 'utf8'));
for (const vector of vectors) {
  test(`vector: ${vector.name}`, () => {
    if (vector.error === 'unsupported') {
      assert.throws(() => DAC.compileDetection(vector.detection), DAC.UnsupportedFeature);
    } else if (vector.error === 'malformed') {
      assert.throws(
        () => DAC.compileDetection(vector.detection),
        (err) => err instanceof DAC.SigmaError && !(err instanceof DAC.UnsupportedFeature),
      );
    } else {
      assert.strictEqual(DAC.compileDetection(vector.detection)(vector.event), vector.match);
    }
  });
}

const python = process.env.PYTHON || 'python3';
const payload = JSON.parse(
  execFileSync(python, ['-m', 'dac', 'parity'], { cwd: root, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 }),
);

test('the repository has rules and logs to compare', () => {
  assert.ok(payload.rules.length > 0);
  assert.ok(payload.events.length > 0);
});

for (const rule of payload.rules) {
  test(`JS and Python agree on every log for ${rule.slug}`, () => {
    const matcher = DAC.compileDetection(rule.detection);
    payload.events.forEach((entry, index) => {
      assert.strictEqual(matcher(entry.event), rule.verdicts[index], `${rule.slug} on ${entry.name}`);
    });
  });
}
