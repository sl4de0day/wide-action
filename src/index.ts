import * as core from '@actions/core';
import * as github from '@actions/github';
import { getConfig } from './config.js';
import { getPullRequestDiff, getLocalGitDiff } from './git.js';
import { SecurityScanner } from './engine/scanner.js';
import { PrCommenter } from './reporter/pr-commenter.js';
import { SeverityLevel } from './types.js';

const SEVERITY_RANKS: Record<SeverityLevel, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  INFO: 0
};

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

    const prNumber = github.context.payload.pull_request?.number;
    const prHeadSha = github.context.payload.pull_request?.head?.sha || sha;
    const modifiedFilesMap = new Map<string, Set<number>>();
    const octokit = config.githubToken ? github.getOctokit(config.githubToken) : null;

    if (config.onlyDiff) {
      if (prNumber && octokit) {
        core.info(`Fetching diff for Pull Request #${prNumber}...`);
        const prDiffs = await getPullRequestDiff(octokit, repo.owner, repo.repo, prNumber);
        for (const file of prDiffs) {
          modifiedFilesMap.set(file.filename, file.changedLines);
        }
        core.info(`Retrieved ${prDiffs.length} modified file(s) from Pull Request.`);
      } else {
        core.info('Detecting local git diff...');
        const localDiffs = await getLocalGitDiff();
        for (const file of localDiffs) {
          modifiedFilesMap.set(file.filename, file.changedLines);
        }
        core.info(`Detected ${localDiffs.length} modified file(s) via git diff.`);
      }
    }

    core.info('Running Wide Security Scanner...');
    const scanner = new SecurityScanner(process.cwd());
    const scanResult = await scanner.scan({
      onlyDiff: config.onlyDiff,
      modifiedFiles: modifiedFilesMap
    });

    core.info(`Scanned ${scanResult.totalFilesScanned} file(s). Found ${scanResult.findings.length} issue(s).`);
    core.info(`Severity Breakdown: [CRITICAL: ${scanResult.summary.critical}] [HIGH: ${scanResult.summary.high}] [MEDIUM: ${scanResult.summary.medium}] [LOW: ${scanResult.summary.low}]`);

    core.setOutput('findings-count', scanResult.summary.total.toString());
    core.setOutput('critical-count', scanResult.summary.critical.toString());
    core.setOutput('high-count', scanResult.summary.high.toString());
    core.setOutput('medium-count', scanResult.summary.medium.toString());
    core.setOutput('low-count', scanResult.summary.low.toString());
    core.setOutput('sarif-path', config.outputPath);

    for (const finding of scanResult.findings) {
      const location = `${finding.file}:${finding.line}`;
      const msg = `[${finding.severity}] ${finding.title} (${finding.cwe}): ${finding.description}`;
      if (finding.severity === 'CRITICAL' || finding.severity === 'HIGH') {
        core.error(`${location} - ${msg}`);
      } else if (finding.severity === 'MEDIUM') {
        core.warning(`${location} - ${msg}`);
      } else {
        core.notice(`${location} - ${msg}`);
      }
    }

    let isBlocked = false;
    if (config.failOn !== 'NEVER') {
      const thresholdRank = SEVERITY_RANKS[config.failOn as SeverityLevel] || 3;
      isBlocked = scanResult.findings.some(
        f => SEVERITY_RANKS[f.severity] >= thresholdRank
      );
    }

    if (prNumber && octokit) {
      core.info('Publishing PR review and summary comments...');
      const commenter = new PrCommenter({
        octokit,
        owner: repo.owner,
        repo: repo.repo,
        pullNumber: prNumber,
        commitSha: prHeadSha
      });

      await commenter.postOrUpdateSummary(scanResult, config.failOn, isBlocked);
      await commenter.postInlineReviewComments(scanResult.findings);
    }

    if (isBlocked) {
      const thresholdRank = SEVERITY_RANKS[config.failOn as SeverityLevel] || 3;
      const blockingCount = scanResult.findings.filter(
        f => SEVERITY_RANKS[f.severity] >= thresholdRank
      ).length;
      core.setFailed(
        `Wide Security Gate: Found ${blockingCount} issue(s) at or above ${config.failOn} threshold.`
      );
      return;
    }

    core.info('Wide Security Gate: All checks passed.');
  } catch (error) {
    if (error instanceof Error) {
      core.setFailed(error.message);
    } else {
      core.setFailed(String(error));
    }
  }
}

void run();
