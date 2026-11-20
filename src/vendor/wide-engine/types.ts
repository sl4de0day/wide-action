export type EngineSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

export interface LogicalSpan {
  startLine: number;
  endLine: number;
  text: string;
}

export interface EngineFinding {
  id: string;
  ruleId: string;
  cwe: string;
  category: string;
  severity: EngineSeverity;
  file: string;
  line: number;
  endLine: number;
  snippet: string;
  message: string;
  remediation: string;
  source: "taint";
  crossFile?: boolean;
}

export interface SourceFile {
  file: string;
  lang?: string;
  content: string;
}

export interface TaintOptions {
  seedTainted?: readonly string[];
}
