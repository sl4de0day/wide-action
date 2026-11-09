import { exec } from 'node:child_process';
import { promisify } from 'node:util';
import * as core from '@actions/core';
import type { getOctokit } from '@actions/github';
import { ModifiedFileDiff } from './types.js';

const execAsync = promisify(exec);

const HUNK_REGEX = /^@@\s+-(?<oldStart>\d+)(?:,(?<oldLines>\d+))?\s+\+(?<newStart>\d+)(?:,(?<newLines>\d+))?\s+@@/;

export function parsePatch(patch: string): Set<number> {
  const changedLines = new Set<number>();
  if (!patch) return changedLines;

  const lines = patch.split('\n');
  let currentNewLine = 0;
  let inHunk = false;

  for (const line of lines) {
    const match = line.match(HUNK_REGEX);
    if (match && match.groups) {
      inHunk = true;
      currentNewLine = parseInt(match.groups.newStart, 10);
      continue;
    }

    if (!inHunk) continue;

    if (line.startsWith('+') && !line.startsWith('+++')) {
      changedLines.add(currentNewLine);
      currentNewLine++;
    } else if (line.startsWith('-') && !line.startsWith('---')) {
      continue;
    } else if (line.startsWith(' ') || line === '') {
      currentNewLine++;
    }
  }

  return changedLines;
}

export function parseUnifiedDiff(rawDiff: string): ModifiedFileDiff[] {
  const result: ModifiedFileDiff[] = [];
  if (!rawDiff.trim()) return result;

  const fileChunks = rawDiff.split(/^diff --git\s+/m).filter(Boolean);

  for (const chunk of fileChunks) {
    const lines = chunk.split('\n');
    let filename = '';

    for (const line of lines) {
      if (line.startsWith('+++ b/')) {
        filename = line.slice(6).trim();
        break;
      }
    }

    if (!filename) {
      const match = lines[0].match(/a\/(.+?)\s+b\/(.+)/);
      if (match) {
        filename = match[2].trim();
      }
    }

    if (!filename || filename === '/dev/null') continue;

    const changedLines = parsePatch(chunk);
    let additions = 0;
    let deletions = 0;

    for (const line of lines) {
      if (line.startsWith('+') && !line.startsWith('+++')) additions++;
      if (line.startsWith('-') && !line.startsWith('---')) deletions++;
    }

    result.push({
      filename,
      status: deletions > 0 && additions === 0 ? 'removed' : additions > 0 && deletions === 0 ? 'added' : 'modified',
      additions,
      deletions,
      changedLines,
      patch: chunk
    });
  }

  return result;
}

export async function getPullRequestDiff(
  octokit: ReturnType<typeof getOctokit>,
  owner: string,
  repo: string,
  pullNumber: number
): Promise<ModifiedFileDiff[]> {
  try {
    const files = await octokit.paginate(octokit.rest.pulls.listFiles, {
      owner,
      repo,
      pull_number: pullNumber,
      per_page: 100
    });

    return files.map(file => ({
      filename: file.filename,
      status: file.status,
      additions: file.additions,
      deletions: file.deletions,
      changedLines: parsePatch(file.patch || ''),
      patch: file.patch
    }));
  } catch (error) {
    core.warning(`Failed to fetch pull request files via GitHub API: ${String(error)}`);
    return getLocalGitDiff();
  }
}

export async function getLocalGitDiff(baseRef?: string): Promise<ModifiedFileDiff[]> {
  try {
    const targetRef = baseRef || 'HEAD~1';
    const { stdout } = await execAsync(`git diff -U0 ${targetRef} HEAD`);
    return parseUnifiedDiff(stdout);
  } catch {
    try {
      const { stdout } = await execAsync('git diff -U0 HEAD');
      return parseUnifiedDiff(stdout);
    } catch (err) {
      core.warning(`Failed to extract local git diff: ${String(err)}`);
      return [];
    }
  }
}
