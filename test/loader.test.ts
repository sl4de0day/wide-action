import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { RuleLoader } from '../src/engine/loader.js';
import { SecurityScanner } from '../src/engine/scanner.js';

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

  it('parses not-match rules and suppresses matching lines in scanner', async () => {
    const tmpDir = mkdtempSync(join(tmpdir(), 'wide-action-loader-'));
    try {
      const customRulesPath = join(tmpDir, 'custom-rules.json');
      writeFileSync(
        customRulesPath,
        JSON.stringify([
          {
            id: 'wide/test-not-match',
            cwe: 'CWE-999',
            category: 'Test',
            severity: 'HIGH',
            languages: ['ts'],
            pattern: 'dangerousOp\\(',
            'not-match': 'trustedArg',
            message: 'Dangerous operation'
          }
        ]),
        'utf8'
      );
      writeFileSync(
        join(tmpDir, 'target.ts'),
        'dangerousOp(userInput);\ndangerousOp(trustedArg);\n',
        'utf8'
      );

      const loaded = await RuleLoader.loadRules(customRulesPath, tmpDir);
      assert.equal(loaded.length, 1);
      assert.ok(loaded[0].notMatch instanceof RegExp);

      const scanner = new SecurityScanner(tmpDir);
      const res = await scanner.scan({ onlyDiff: false, rules: loaded });
      const hits = res.findings.filter(f => f.ruleId === 'wide/test-not-match');
      assert.equal(hits.length, 1);
      assert.equal(hits[0].line, 1);

      const advisories = await RuleLoader.loadAdvisories('embedded', tmpDir);
      assert.ok(advisories && typeof advisories === 'object');
      assert.ok(Array.isArray(advisories.npm));
    } finally {
      rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});
