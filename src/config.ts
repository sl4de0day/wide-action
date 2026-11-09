import * as core from '@actions/core';
import { ActionConfig, FailOnThreshold } from './types.js';

const VALID_FAIL_THRESHOLDS: readonly FailOnThreshold[] = [
  'CRITICAL',
  'HIGH',
  'MEDIUM',
  'LOW',
  'NEVER'
];

export function parseFailOn(raw: string): FailOnThreshold {
  const normalized = raw.trim().toUpperCase() as FailOnThreshold;
  if (VALID_FAIL_THRESHOLDS.includes(normalized)) {
    return normalized;
  }
  core.warning(`Invalid fail-on value: ${raw}. Defaulting to HIGH.`);
  return 'HIGH';
}

export function parseBoolean(value: string, defaultValue: boolean): boolean {
  if (!value) return defaultValue;
  const lower = value.trim().toLowerCase();
  if (lower === 'true' || lower === '1' || lower === 'yes') return true;
  if (lower === 'false' || lower === '0' || lower === 'no') return false;
  return defaultValue;
}

export function getConfig(): ActionConfig {
  const githubToken = core.getInput('github-token', { required: false }) || process.env.GITHUB_TOKEN || '';
  const failOnRaw = core.getInput('fail-on', { required: false }) || 'HIGH';
  const onlyDiffRaw = core.getInput('only-diff', { required: false }) || 'true';
  const aiRemediationRaw = core.getInput('ai-remediation', { required: false }) || 'false';
  const provider = (core.getInput('provider', { required: false }) || 'gemini').trim().toLowerCase();
  const apiKey = core.getInput('api-key', { required: false }) || '';
  const sarifRaw = core.getInput('sarif', { required: false }) || 'true';
  const outputPath = (core.getInput('output-path', { required: false }) || 'wide-results.sarif').trim();
  const rules = (core.getInput('rules', { required: false }) || 'embedded').trim();

  return {
    githubToken,
    failOn: parseFailOn(failOnRaw),
    onlyDiff: parseBoolean(onlyDiffRaw, true),
    aiRemediation: parseBoolean(aiRemediationRaw, false),
    provider,
    apiKey,
    sarif: parseBoolean(sarifRaw, true),
    outputPath,
    rules
  };
}
