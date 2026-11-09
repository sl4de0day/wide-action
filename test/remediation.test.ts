import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { RemediationEngine } from '../src/remediation/engine.js';
import { formatInlineComment } from '../src/reporter/markdown.js';
import { VulnerabilityFinding } from '../src/types.js';

describe('AI Remediation Engine', () => {
  it('extracts code cleanly from suggestion blocks', () => {
    const engine = new RemediationEngine({ provider: 'gemini', apiKey: 'test' });

    const rawWithSuggestion = [
      'Here is the fix:',
      '```suggestion',
      'const query = pool.query("SELECT * FROM users WHERE id = $1", [req.query.id]);',
      '```'
    ].join('\n');

    const patch = engine.extractSuggestionCode(rawWithSuggestion);
    assert.equal(
      patch,
      'const query = pool.query("SELECT * FROM users WHERE id = $1", [req.query.id]);'
    );
  });

  it('extracts code from generic language fences if model omitted suggestion keyword', () => {
    const engine = new RemediationEngine({ provider: 'claude', apiKey: 'test' });

    const rawWithCodeFence = [
      '```typescript',
      'execFile("ping", ["-c", "1", host]);',
      '```'
    ].join('\n');

    const patch = engine.extractSuggestionCode(rawWithCodeFence);
    assert.equal(patch, 'execFile("ping", ["-c", "1", host]);');
  });

  it('returns null when raw response is empty', () => {
    const engine = new RemediationEngine({ provider: 'openai', apiKey: 'test' });
    assert.equal(engine.extractSuggestionCode(''), null);
  });

  it('returns null and skips execution gracefully when API key is missing', async () => {
    const engine = new RemediationEngine({ provider: 'gemini', apiKey: '' });
    const finding: VulnerabilityFinding = {
      id: 'f1',
      ruleId: 'WIDE-SEC-001',
      title: 'SQL Injection',
      description: 'SQLi',
      severity: 'CRITICAL',
      file: 'src/app.ts',
      line: 10,
      snippet: 'const q = "SELECT * FROM users WHERE id = " + id;',
      remediation: 'Parameterize'
    };

    const patch = await engine.generatePatch(finding);
    assert.equal(patch, null);
  });

  it('renders interactive suggestion block in inline markdown comment', () => {
    const finding: VulnerabilityFinding = {
      id: 'f1',
      ruleId: 'WIDE-SEC-001',
      title: 'SQL Injection',
      description: 'SQLi',
      severity: 'CRITICAL',
      file: 'src/app.ts',
      line: 10,
      snippet: 'const q = "SELECT * FROM users WHERE id = " + id;',
      suggestedPatch: 'const q = await db.query("SELECT * FROM users WHERE id = $1", [id]);',
      remediation: 'Parameterize'
    };

    const md = formatInlineComment(finding);
    assert.ok(md.includes('**AI Suggested Fix (Click "Commit suggestion" to apply):**'));
    assert.ok(md.includes('```suggestion'));
    assert.ok(md.includes('const q = await db.query("SELECT * FROM users WHERE id = $1", [id]);'));
  });
});
