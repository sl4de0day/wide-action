import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { parseFailOn, parseBoolean } from '../src/config.js';

describe('Configuration Parser', () => {
  it('parses valid fail-on thresholds correctly', () => {
    assert.equal(parseFailOn('CRITICAL'), 'CRITICAL');
    assert.equal(parseFailOn('high'), 'HIGH');
    assert.equal(parseFailOn('MEDIUM'), 'MEDIUM');
    assert.equal(parseFailOn('low'), 'LOW');
    assert.equal(parseFailOn('never'), 'NEVER');
  });

  it('defaults to HIGH for invalid thresholds', () => {
    assert.equal(parseFailOn('INVALID_SEVERITY'), 'HIGH');
    assert.equal(parseFailOn(''), 'HIGH');
  });

  it('parses boolean strings accurately', () => {
    assert.equal(parseBoolean('true', false), true);
    assert.equal(parseBoolean('1', false), true);
    assert.equal(parseBoolean('yes', false), true);
    assert.equal(parseBoolean('false', true), false);
    assert.equal(parseBoolean('0', true), false);
    assert.equal(parseBoolean('no', true), false);
    assert.equal(parseBoolean('', true), true);
    assert.equal(parseBoolean('', false), false);
  });
});
