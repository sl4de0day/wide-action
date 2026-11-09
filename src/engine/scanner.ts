import { readFileSync, existsSync, readdirSync } from 'node:fs';
import { resolve, relative, extname, join } from 'node:path';
import { SECURITY_RULES, SecurityRule } from './rules.js';
import {
  ScanResult,
  ScanOptions,
  SeverityLevel,
  ScanSummary,
  VulnerabilityFinding
} from '../types.js';

const EXTENSION_MAP: Record<string, string> = {
  '.js': 'js',
  '.jsx': 'js',
  '.mjs': 'js',
  '.cjs': 'js',
  '.ts': 'ts',
  '.tsx': 'ts',
  '.py': 'py',
  '.php': 'php',
  '.java': 'java',
  '.cs': 'cs',
  '.go': 'go',
  '.rb': 'rb',
  '.rs': 'rs',
  '.c': 'c',
  '.cpp': 'c',
  '.h': 'c'
};

const SEVERITY_RANKS: Record<SeverityLevel, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  INFO: 0
};

const IGNORED_DIRECTORIES = new Set([
  'node_modules',
  '.git',
  'dist',
  'build',
  'vendor',
  '.next',
  'target',
  'coverage',
  '.gemini',
  '.vscode'
]);

export class SecurityScanner {
  private workspaceDir: string;

  constructor(workspaceDir = process.cwd()) {
    this.workspaceDir = resolve(workspaceDir);
  }

  public async scan(options: ScanOptions = {}): Promise<ScanResult> {
    const minSeverity = options.minSeverity || 'LOW';
    const minRank = minSeverity === 'ALL' ? 0 : SEVERITY_RANKS[minSeverity] || 1;
    const activeRules: readonly SecurityRule[] = (options.rules && options.rules.length > 0) ? options.rules : SECURITY_RULES;
    const findings: VulnerabilityFinding[] = [];
    let scannedFilesCount = 0;

    if (options.onlyDiff && options.modifiedFiles && options.modifiedFiles.size > 0) {
      for (const [rawFilePath, changedLines] of options.modifiedFiles.entries()) {
        const normalizedRel = rawFilePath.replace(/\\/g, '/');
        const fullPath = resolve(this.workspaceDir, normalizedRel);

        if (!existsSync(fullPath)) continue;

        scannedFilesCount++;
        this.scanSingleFile(fullPath, normalizedRel, changedLines, minRank, activeRules, findings);
      }
    } else {
      const allFiles = this.collectWorkspaceFiles(this.workspaceDir);
      scannedFilesCount = allFiles.length;

      for (const fullPath of allFiles) {
        const relPath = relative(this.workspaceDir, fullPath).replace(/\\/g, '/');
        this.scanSingleFile(fullPath, relPath, undefined, minRank, activeRules, findings);
      }
    }

    const summary: ScanSummary = {
      total: findings.length,
      critical: findings.filter(f => f.severity === 'CRITICAL').length,
      high: findings.filter(f => f.severity === 'HIGH').length,
      medium: findings.filter(f => f.severity === 'MEDIUM').length,
      low: findings.filter(f => f.severity === 'LOW').length,
      info: findings.filter(f => f.severity === 'INFO').length
    };

    return {
      totalFilesScanned: scannedFilesCount,
      findings,
      summary
    };
  }

  private scanSingleFile(
    fullPath: string,
    relPath: string,
    changedLines: Set<number> | undefined,
    minRank: number,
    rules: readonly SecurityRule[],
    findings: VulnerabilityFinding[]
  ): void {
    const ext = extname(fullPath).toLowerCase();
    const lang = EXTENSION_MAP[ext] || 'all';

    let content = '';
    try {
      content = readFileSync(fullPath, 'utf8');
    } catch {
      return;
    }

    const lines = content.split('\n');
    const applicableRules = rules.filter(r =>
      r.languages.includes('all') || r.languages.includes(lang)
    );

    for (let i = 0; i < lines.length; i++) {
      const lineNum = i + 1;

      if (changedLines && !changedLines.has(lineNum)) {
        continue;
      }

      const lineText = lines[i];
      if (lineText.length > 1500) continue;

      for (const rule of applicableRules) {
        if (SEVERITY_RANKS[rule.severity] < minRank) continue;

        if (rule.pattern.test(lineText)) {
          let confirmed = true;
          if (rule.sourcePattern) {
            const windowStart = Math.max(0, i - 15);
            const windowText = lines.slice(windowStart, i + 1).join('\n');
            confirmed = rule.sourcePattern.test(windowText);
          }

          if (confirmed) {
            findings.push({
              id: `${rule.id}-${relPath}-${lineNum}`,
              ruleId: rule.id,
              cwe: rule.cwe,
              title: rule.category,
              description: rule.message,
              severity: rule.severity,
              file: relPath,
              line: lineNum,
              snippet: lineText.trim(),
              remediation: rule.remediation
            });
          }
        }
      }
    }
  }

  private collectWorkspaceFiles(dir: string): string[] {
    const results: string[] = [];
    if (!existsSync(dir)) return results;

    const entries = readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      if (IGNORED_DIRECTORIES.has(entry.name)) continue;

      const fullPath = join(dir, entry.name);
      if (entry.isDirectory()) {
        results.push(...this.collectWorkspaceFiles(fullPath));
      } else if (entry.isFile()) {
        const ext = extname(entry.name).toLowerCase();
        if (ext in EXTENSION_MAP) {
          results.push(fullPath);
        }
      }
    }

    return results;
  }
}
