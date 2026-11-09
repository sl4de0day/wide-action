import * as core from '@actions/core';
import type { getOctokit } from '@actions/github';
import { ScanResult, VulnerabilityFinding } from '../types.js';
import { formatSummaryComment, formatInlineComment } from './markdown.js';

export interface CommenterOptions {
  octokit: ReturnType<typeof getOctokit>;
  owner: string;
  repo: string;
  pullNumber: number;
  commitSha: string;
}

export class PrCommenter {
  private octokit: ReturnType<typeof getOctokit>;
  private owner: string;
  private repo: string;
  private pullNumber: number;
  private commitSha: string;

  constructor(options: CommenterOptions) {
    this.octokit = options.octokit;
    this.owner = options.owner;
    this.repo = options.repo;
    this.pullNumber = options.pullNumber;
    this.commitSha = options.commitSha;
  }

  public async postOrUpdateSummary(
    scanResult: ScanResult,
    failOn: string,
    isBlocked: boolean
  ): Promise<void> {
    try {
      const body = formatSummaryComment(scanResult, failOn, isBlocked);
      const comments = await this.octokit.paginate(
        this.octokit.rest.issues.listComments,
        {
          owner: this.owner,
          repo: this.repo,
          issue_number: this.pullNumber,
          per_page: 100
        }
      );

      const existingComment = comments.find(
        c => c.body && c.body.includes('data-wide-action="summary"')
      );

      if (existingComment) {
        core.info(`Updating existing PR summary comment (ID: ${existingComment.id})...`);
        await this.octokit.rest.issues.updateComment({
          owner: this.owner,
          repo: this.repo,
          comment_id: existingComment.id,
          body
        });
      } else {
        core.info('Posting new PR summary comment...');
        await this.octokit.rest.issues.createComment({
          owner: this.owner,
          repo: this.repo,
          issue_number: this.pullNumber,
          body
        });
      }
    } catch (error) {
      core.warning(`Failed to post or update PR summary comment: ${String(error)}`);
    }
  }

  public async postInlineReviewComments(
    findings: VulnerabilityFinding[]
  ): Promise<number> {
    if (findings.length === 0) return 0;

    try {
      const existingReviews = await this.octokit.paginate(
        this.octokit.rest.pulls.listReviewComments,
        {
          owner: this.owner,
          repo: this.repo,
          pull_number: this.pullNumber,
          per_page: 100
        }
      );

      const existingKeys = new Set<string>();
      for (const review of existingReviews) {
        const match = review.body?.match(/data-rule-id="([^"]+)"/);
        const ruleId = match ? match[1] : '';
        const key = `${review.path}:${review.line || review.original_line || 0}:${ruleId}`;
        existingKeys.add(key);
      }

      const newComments: Array<{ path: string; line: number; body: string }> = [];

      for (const finding of findings) {
        const normalizedPath = finding.file.replace(/\\/g, '/');
        const key = `${normalizedPath}:${finding.line}:${finding.ruleId}`;

        if (existingKeys.has(key)) {
          continue;
        }

        existingKeys.add(key);
        newComments.push({
          path: normalizedPath,
          line: finding.line,
          body: formatInlineComment(finding)
        });
      }

      if (newComments.length === 0) {
        core.info('No new inline review comments to post.');
        return 0;
      }

      core.info(`Submitting ${newComments.length} inline review comment(s)...`);

      const batchSize = 25;
      for (let i = 0; i < newComments.length; i += batchSize) {
        const batch = newComments.slice(i, i + batchSize);
        try {
          await this.octokit.rest.pulls.createReview({
            owner: this.owner,
            repo: this.repo,
            pull_number: this.pullNumber,
            commit_id: this.commitSha,
            event: 'COMMENT',
            comments: batch
          });
        } catch (batchError) {
          core.warning(`Batch inline review failed, trying individually: ${String(batchError)}`);
          for (const item of batch) {
            try {
              await this.octokit.rest.pulls.createReviewComment({
                owner: this.owner,
                repo: this.repo,
                pull_number: this.pullNumber,
                commit_id: this.commitSha,
                path: item.path,
                line: item.line,
                body: item.body
              });
            } catch (singleError) {
              core.warning(`Failed to comment on ${item.path}:${item.line} - ${String(singleError)}`);
            }
          }
        }
      }

      return newComments.length;
    } catch (error) {
      core.warning(`Failed to submit inline review comments: ${String(error)}`);
      return 0;
    }
  }
}
