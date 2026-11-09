import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { SecurityScanner } from '../src/engine/scanner.js';

describe('SecurityScanner Engine', () => {
  const tmpDir = resolve('./test_tmp_scanner');

  before(() => {
    mkdirSync(tmpDir, { recursive: true });
  });

  after(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it('detects sql injection and command injection correctly', async () => {
    const filePath = join(tmpDir, 'vuln.ts');
    const content = [
      'import express from "express";',
      'const query = "SELECT * FROM users WHERE name = \'" + req.query.name + "\'";',
      'const safe = 42;'
    ].join('\n');

    writeFileSync(filePath, content, 'utf8');

    const scanner = new SecurityScanner(tmpDir);
    const result = await scanner.scan({ onlyDiff: false });

    assert.ok(result.findings.length >= 1);
    const sqlFinding = result.findings.find(f => f.ruleId === 'WIDE-SEC-001');
    assert.ok(sqlFinding);
    assert.equal(sqlFinding.line, 2);
    assert.equal(sqlFinding.severity, 'CRITICAL');
  });

  it('filters out findings outside modified lines when onlyDiff is true', async () => {
    const filePath = join(tmpDir, 'diff_test.ts');
    const content = [
      'const preExisting = "SELECT * FROM data WHERE id = " + req.query.id;',
      'const normalLine = 1;',
      'const newVuln = "AKIA1234567890123456";',
      'const endLine = 2;'
    ].join('\n');

    writeFileSync(filePath, content, 'utf8');

    const scanner = new SecurityScanner(tmpDir);
    const modifiedLines = new Set<number>([3]);
    const modifiedMap = new Map<string, Set<number>>([['diff_test.ts', modifiedLines]]);

    const diffResult = await scanner.scan({
      onlyDiff: true,
      modifiedFiles: modifiedMap
    });

    assert.equal(diffResult.findings.length, 1);
    assert.equal(diffResult.findings[0].line, 3);
    assert.equal(diffResult.findings[0].ruleId, 'WIDE-SEC-008');

    const fullResult = await scanner.scan({ onlyDiff: false });
    assert.ok(fullResult.findings.length >= 2);
  });
});
