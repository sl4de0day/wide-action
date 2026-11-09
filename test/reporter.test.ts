import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { formatSummaryComment, formatInlineComment } from '../src/reporter/markdown.js';
import { PrCommenter } from '../src/reporter/pr-commenter.js';
import { ScanResult, VulnerabilityFinding } from '../src/types.js';

describe('Reporter Markdown Generator', () => {
  const sampleFindings: VulnerabilityFinding[] = [
    {
      id: 'WIDE-SEC-001-app.ts-12',
      ruleId: 'WIDE-SEC-001',
      title: 'SQL Injection',
      description: 'Dynamic SQL query constructed with unescaped user input.',
      severity: 'CRITICAL',
      file: 'src/app.ts',
      line: 12,
      snippet: 'const sql = "SELECT * FROM users WHERE id = " + req.query.id;',
      cwe: 'CWE-89',
      remediation: 'Use parameterized queries.'
    }
  ];

  const sampleScanResult: ScanResult = {
    totalFilesScanned: 5,
    findings: sampleFindings,
    summary: {
      total: 1,
      critical: 1,
      high: 0,
      medium: 0,
      low: 0,
      info: 0
    }
  };

  it('generates summary comment with tracking marker and failure status', () => {
    const markdown = formatSummaryComment(sampleScanResult, 'HIGH', true);

    assert.ok(markdown.includes('## Wide Security Audit Summary'));
    assert.ok(markdown.includes('<div data-wide-action="summary"></div>'));
    assert.ok(markdown.includes('**Status:** BLOCKED'));
    assert.ok(markdown.includes('| CRITICAL | 1 |'));
    assert.ok(markdown.includes('CWE-89'));
    assert.ok(markdown.includes('`src/app.ts:12`'));
  });

  it('generates clean passing status when zero findings are reported', () => {
    const emptyResult: ScanResult = {
      totalFilesScanned: 10,
      findings: [],
      summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    };

    const markdown = formatSummaryComment(emptyResult, 'HIGH', false);
    assert.ok(markdown.includes('**Status:** PASSED - No security vulnerabilities detected'));
    assert.ok(!markdown.includes('### Detected Findings'));
  });

  it('generates inline review comment with rule-id marker and snippet', () => {
    const inlineMd = formatInlineComment(sampleFindings[0]);

    assert.ok(inlineMd.includes('### Wide Security: [CRITICAL] SQL Injection (CWE-89)'));
    assert.ok(inlineMd.includes('<div data-wide-action="finding" data-rule-id="WIDE-SEC-001"></div>'));
    assert.ok(inlineMd.includes('const sql = "SELECT * FROM users WHERE id = " + req.query.id;'));
    assert.ok(inlineMd.includes('Use parameterized queries.'));
  });
});

describe('PrCommenter Anti-Spam and Review Logic', () => {
  it('updates existing summary comment instead of creating duplicate', async () => {
    let updateCalled = false;
    let createCalled = false;

    const mockOctokit = {
      paginate: async () => [
        {
          id: 999,
          body: 'Previous text\n<div data-wide-action="summary"></div>'
        }
      ],
      rest: {
        issues: {
          listComments: {},
          updateComment: async (args: { comment_id: number }) => {
            if (args.comment_id === 999) updateCalled = true;
          },
          createComment: async () => {
            createCalled = true;
          }
        }
      }
    };

    const commenter = new PrCommenter({
      octokit: mockOctokit as any,
      owner: 'test-owner',
      repo: 'test-repo',
      pullNumber: 1,
      commitSha: 'sha123'
    });

    const emptyResult: ScanResult = {
      totalFilesScanned: 1,
      findings: [],
      summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    };

    await commenter.postOrUpdateSummary(emptyResult, 'HIGH', false);
    assert.equal(updateCalled, true);
    assert.equal(createCalled, false);
  });

  it('skips duplicate review comments that already exist on the same line and rule', async () => {
    let reviewSubmitted = false;

    const mockOctokit = {
      paginate: async () => [
        {
          path: 'src/app.ts',
          line: 12,
          body: 'Review\n<div data-wide-action="finding" data-rule-id="WIDE-SEC-001"></div>'
        }
      ],
      rest: {
        pulls: {
          listReviewComments: {},
          createReview: async () => {
            reviewSubmitted = true;
          }
        }
      }
    };

    const commenter = new PrCommenter({
      octokit: mockOctokit as any,
      owner: 'test-owner',
      repo: 'test-repo',
      pullNumber: 1,
      commitSha: 'sha123'
    });

    const finding: VulnerabilityFinding = {
      id: 'f1',
      ruleId: 'WIDE-SEC-001',
      title: 'SQL Injection',
      description: 'SQLi',
      severity: 'CRITICAL',
      file: 'src/app.ts',
      line: 12,
      remediation: 'Fix'
    };

    const count = await commenter.postInlineReviewComments([finding]);
    assert.equal(count, 0);
    assert.equal(reviewSubmitted, false);
  });
});
