import * as core from '@actions/core';
import * as github from '@actions/github';
import { getConfig } from './config.js';

export async function run(): Promise<void> {
  try {
    const config = getConfig();
    const { eventName, sha, ref, repo } = github.context;

    core.info('Wide Action initializing...');
    core.info(`Repository: ${repo.owner}/${repo.repo}`);
    core.info(`Trigger Event: ${eventName}`);
    core.info(`Git Reference: ${ref}`);
    core.info(`Commit SHA: ${sha}`);
    core.info(`Fail-On Threshold: ${config.failOn}`);
    core.info(`Only Diff: ${config.onlyDiff}`);
    core.info(`SARIF Output: ${config.sarif ? config.outputPath : 'disabled'}`);
    core.info(`AI Remediation: ${config.aiRemediation ? config.provider : 'disabled'}`);

    const prNumber = github.context.payload.pull_request?.number;
    if (prNumber) {
      core.info(`Pull Request: #${prNumber}`);
    }

    core.setOutput('findings-count', '0');
    core.setOutput('critical-count', '0');
    core.setOutput('high-count', '0');
    core.setOutput('medium-count', '0');
    core.setOutput('low-count', '0');
    core.setOutput('sarif-path', config.outputPath);

    core.info('Wide Action Phase 1 initialization completed successfully.');
  } catch (error) {
    if (error instanceof Error) {
      core.setFailed(error.message);
    } else {
      core.setFailed(String(error));
    }
  }
}

void run();
