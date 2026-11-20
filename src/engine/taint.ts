import { VulnerabilityFinding } from '../types.js';
import {
  analyzeFileTaint as engineAnalyzeFileTaint,
  analyzeProjectFlows as engineAnalyzeProjectFlows,
  buildLogicalSpans
} from '../vendor/wide-engine/index.js';
import type { EngineFinding, LogicalSpan, SourceFile } from '../vendor/wide-engine/index.js';

export { buildLogicalSpans };
export type { LogicalSpan };

function toVulnerabilityFinding(f: EngineFinding): VulnerabilityFinding {
  const finding: VulnerabilityFinding = {
    id: `${f.ruleId}-${f.file}-${f.line}`,
    ruleId: f.ruleId,
    cwe: f.cwe,
    title: f.category,
    description: f.message,
    severity: f.severity,
    file: f.file,
    line: f.line,
    endLine: f.endLine,
    snippet: f.snippet,
    remediation: f.remediation,
    source: 'taint'
  };
  if (f.crossFile !== undefined) finding.crossFile = f.crossFile;
  return finding;
}

export function analyzeFileTaint(
  content: string,
  lang: string,
  filePath: string,
  seedTainted: readonly string[] = []
): VulnerabilityFinding[] {
  return engineAnalyzeFileTaint(content, lang, filePath, { seedTainted }).map(toVulnerabilityFinding);
}

export function analyzeProjectFlows(files: readonly SourceFile[]): VulnerabilityFinding[] {
  return engineAnalyzeProjectFlows(files).map(toVulnerabilityFinding);
}
