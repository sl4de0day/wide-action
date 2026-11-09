import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { parsePatch, parseUnifiedDiff } from '../src/git.js';

describe('Diff Parser', () => {
  it('parses single addition hunk correctly', () => {
    const patch = [
      '@@ -10,3 +10,4 @@',
      ' const a = 1;',
      '+const b = 2;',
      ' const c = 3;',
      ' const d = 4;'
    ].join('\n');

    const changed = parsePatch(patch);
    assert.equal(changed.size, 1);
    assert.ok(changed.has(11));
  });

  it('parses multiple hunks with additions and deletions', () => {
    const patch = [
      '@@ -1,3 +1,4 @@',
      '+import db from "db";',
      ' const x = 10;',
      ' const y = 20;',
      '@@ -15,4 +16,5 @@',
      '-const oldVal = 5;',
      '+const newVal = 10;',
      '+const extraVal = 20;',
      ' return newVal;'
    ].join('\n');

    const changed = parsePatch(patch);
    assert.equal(changed.size, 3);
    assert.ok(changed.has(1));
    assert.ok(changed.has(16));
    assert.ok(changed.has(17));
  });

  it('handles empty or deletion-only patches', () => {
    assert.equal(parsePatch('').size, 0);

    const deletionPatch = [
      '@@ -5,3 +5,1 @@',
      '-const dead = 1;',
      '-const code = 2;',
      ' const keep = 3;'
    ].join('\n');

    const changed = parsePatch(deletionPatch);
    assert.equal(changed.size, 0);
  });

  it('parses raw unified diff into structured ModifiedFileDiff array', () => {
    const rawDiff = [
      'diff --git a/src/app.ts b/src/app.ts',
      'index 1234567..89abcdef 100644',
      '--- a/src/app.ts',
      '+++ b/src/app.ts',
      '@@ -5,2 +5,3 @@',
      ' const app = express();',
      '+app.get("/vuln", (req, res) => {});',
      ' export default app;'
    ].join('\n');

    const diffs = parseUnifiedDiff(rawDiff);
    assert.equal(diffs.length, 1);
    assert.equal(diffs[0].filename, 'src/app.ts');
    assert.equal(diffs[0].additions, 1);
    assert.equal(diffs[0].deletions, 0);
    assert.ok(diffs[0].changedLines.has(6));
  });
});
