export { buildLogicalSpans, analyzeFileTaint, analyzeProjectFlows } from "./taint.js";
export { shannonEntropy, isLikelyRealSecret, containsKnownToken } from "./secrets.js";
export type { EngineFinding, EngineSeverity, LogicalSpan, SourceFile, TaintOptions } from "./types.js";
