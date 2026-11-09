import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { RuleLoader } from '../src/engine/loader.js';

describe('Action RuleLoader', () => {
  it('loads embedded rules by default', async () => {
    const rules = await RuleLoader.loadRules('embedded');
    assert.ok(Array.isArray(rules));
    assert.ok(rules.length >= 20);
  });

  it('falls back to embedded rules when custom file is missing', async () => {
    const rules = await RuleLoader.loadRules('non_existent_rules.json');
    assert.ok(Array.isArray(rules));
    assert.ok(rules.length >= 20);
  });
});
