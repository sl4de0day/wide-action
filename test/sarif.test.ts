import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, rmSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import {
  generateSarifReport,
  writeSarifReport,
  severityToSarifLevel,
  severityToProblemSeverity
} from '../src/sarif.js';
import { VulnerabilityFinding } from '../src/types.js';

describe('SARIF 2.1.0 Generator', () => {
  const tmpSarifPath = resolve('./test_output.sarif');

  after(() => {
    if (existsSync(tmpSarifPath)) {
      rmSync(tmpSarifPath, { force: true });
    }
  });

  it('maps severity levels to SARIF levels correctly', () => {
    assert.equal(severityToSarifLevel('CRITICAL'), 'error');
    assert.equal(severityToSarifLevel('HIGH'), 'error');
    assert.equal(severityToSarifLevel('MEDIUM'), 'warning');
    assert.equal(severityToSarifLevel('LOW'), 'note');
    assert.equal(severityToSarifLevel('INFO'), 'none');

    assert.equal(severityToProblemSeverity('CRITICAL'), 'error');
    assert.equal(severityToProblemSeverity('HIGH'), 'error');
    assert.equal(severityToProblemSeverity('MEDIUM'), 'warning');
    assert.equal(severityToProblemSeverity('LOW'), 'recommendation');
  });

  it('generates fully compliant SARIF report structure', () => {
    const findings: VulnerabilityFinding[] = [
      {
        id: 'f1',
        ruleId: 'WIDE-SEC-001',
        title: 'SQL Injection',
        description: 'Unescaped user input in query',
        severity: 'CRITICAL',
        file: 'src/api/users.ts',
        line: 42,
        snippet: 'SELECT * FROM users WHERE id = ' + 1,
        cwe: 'CWE-89',
        remediation: 'Use parameters'
      }
    ];

    const report = generateSarifReport(findings);

    assert.equal(report.version, '2.1.0');
    assert.ok(report.$schema.includes('sarif-schema-2.1.0.json'));
    assert.equal(report.runs.length, 1);
    assert.equal(report.runs[0].tool.driver.name, 'Wide Security');
    assert.ok(report.runs[0].tool.driver.rules.length >= 20);

    const results = report.runs[0].results;
    assert.equal(results.length, 1);
    assert.equal(results[0].ruleId, 'WIDE-SEC-001');
    assert.equal(results[0].level, 'error');
    assert.equal(results[0].locations[0].physicalLocation.artifactLocation.uri, 'src/api/users.ts');
    assert.equal(results[0].locations[0].physicalLocation.region.startLine, 42);
  });

  it('writes SARIF file to disk and reads back valid JSON', () => {
    const findings: VulnerabilityFinding[] = [
      {
        id: 'f2',
        ruleId: 'WIDE-SEC-008',
        title: 'Hardcoded Secret',
        description: 'Hardcoded token detected',
        severity: 'HIGH',
        file: 'config.ts',
        line: 15,
        cwe: 'CWE-798',
        remediation: 'Move to env'
      }
    ];

    writeSarifReport(tmpSarifPath, findings);

    assert.ok(existsSync(tmpSarifPath));
    const content = JSON.parse(readFileSync(tmpSarifPath, 'utf8'));
    assert.equal(content.version, '2.1.0');
    assert.equal(content.runs[0].results.length, 1);
    assert.equal(content.runs[0].results[0].ruleId, 'WIDE-SEC-008');
  });
});
