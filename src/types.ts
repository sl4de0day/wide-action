export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type FailOnThreshold = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NEVER';

export interface ActionConfig {
  githubToken: string;
  failOn: FailOnThreshold;
  onlyDiff: boolean;
  aiRemediation: boolean;
  provider: string;
  apiKey: string;
  sarif: boolean;
  outputPath: string;
  rules: string;
}

export interface VulnerabilityFinding {
  id: string;
  ruleId: string;
  title: string;
  description: string;
  severity: SeverityLevel;
  file: string;
  line: number;
  endLine?: number;
  column?: number;
  snippet?: string;
  cwe?: string;
  remediation?: string;
  suggestedPatch?: string;
}

export interface ScanSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface DiffHunk {
  oldStart: number;
  oldLines: number;
  newStart: number;
  newLines: number;
  lines: string[];
}

export interface ModifiedFileDiff {
  filename: string;
  status: string;
  additions: number;
  deletions: number;
  changedLines: Set<number>;
  patch?: string;
}

export interface ScanResult {
  totalFilesScanned: number;
  findings: VulnerabilityFinding[];
  summary: ScanSummary;
}

export interface ScanOptions {
  targetPath?: string;
  onlyDiff?: boolean;
  modifiedFiles?: Map<string, Set<number>>;
  minSeverity?: SeverityLevel | 'ALL';
  rules?: any[];
}
