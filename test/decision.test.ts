import { describe, it } from 'node:test';
import assert from 'node:assert';
import { WeightedScorer, Criterion, Commitment } from '../src/remediation/decision.js';
import { RemediationEngine } from '../src/remediation/engine.js';

describe('DecisionCore in Action Remediation', () => {
  it('ranks candidates using WeightedScorer', () => {
    const scorer = new WeightedScorer(
      new Criterion(0.7, (c) => (c === 0 ? 0.9 : 0.4)),
      new Criterion(0.3, (c) => (c === 0 ? 0.8 : 0.95))
    );

    const selection = scorer.trySelect(2, 0.6);
    assert.strictEqual(selection.success, true);
    assert.strictEqual(selection.best, 0);
  });

  it('manages replacement margin in Commitment', () => {
    const commitment = new Commitment(10.0, 3.0);
    commitment.adopt(0.75, 100.0);

    assert.strictEqual(commitment.shouldReplace(0.99, 0.1, 102.0), false);
    assert.strictEqual(commitment.shouldReplace(0.80, 0.1, 104.0), false);
    assert.strictEqual(commitment.shouldReplace(0.90, 0.1, 104.0), true);
  });

  it('scores candidate patch quality via RemediationEngine', () => {
    const engine = new RemediationEngine({ provider: 'gemini', apiKey: 'test-key' });
    const scoreGood = engine.scoreCandidatePatch('db.prepare(query, [id])', 'db.query(query + id)');
    const scoreBad = engine.scoreCandidatePatch('db.query(query + id)', 'db.query(query + id)');

    assert.ok(scoreGood > scoreBad);
  });
});
