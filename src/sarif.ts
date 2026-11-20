import { writeFileSync, readFileSync, mkdirSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import * as core from '@actions/core';
import { SECURITY_RULES } from './engine/rules.js';
import { SeverityLevel, VulnerabilityFinding } from './types.js';

const DEFAULT_ACTION_VERSION = '0.7211126';

function resolveToolVersion(): string {
  const envVersion = process.env.npm_package_version;
  if (envVersion) return envVersion;
  try {
    const pkgPath = resolve(dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1')), '../package.json');
    const pkg = JSON.parse(readFileSync(pkgPath, 'utf8')) as { version?: string };
    if (pkg.version) return pkg.version;
  } catch {}
  return DEFAULT_ACTION_VERSION;
}

const KNOWN_SECRET_VALUE_RE = /\b(gh[pous]_[A-Za-z0-9]{10,}|github_pat_[A-Za-z0-9_]{16,}|sk-(?:ant-|proj-)?[A-Za-z0-9_-]{12,}|AKIA[0-9A-Z]{12,}|AIza[0-9A-Za-z_-]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})\b/g;
const ASSIGNED_SECRET_RE = /((?:api[_-]?key|secret|token|password|passwd|pwd|auth[_-]?token|private[_-]?key|bearer)\s*[:=]\s*['"`])([^'"`\r\n]{4,})(['"`])/gi;
const BEARER_RE = /\b(Bearer\s+)([A-Za-z0-9._~+/-]{8,}=*)/gi;
const URL_CREDENTIALS_RE = /([a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^:\s/@]+:)([^@\s]+)(@)/g;

export function maskSensitiveSnippet(text: string): string {
  if (!text) return text;
  return text
    .replace(KNOWN_SECRET_VALUE_RE, '[REDACTED]')
    .replace(ASSIGNED_SECRET_RE, '$1[REDACTED]$3')
    .replace(BEARER_RE, '$1[REDACTED]')
    .replace(URL_CREDENTIALS_RE, '$1[REDACTED]$3');
}

export interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  defaultConfiguration: { level: 'error' | 'warning' | 'note' | 'none' };
  help: { text: string; markdown: string };
  properties: {
    tags: string[];
    precision: string;
    'problem.severity': 'error' | 'warning' | 'recommendation';
  };
}

export interface SarifResult {
  ruleId: string;
  ruleIndex?: number;
  level: 'error' | 'warning' | 'note' | 'none';
  message: { text: string };
  locations: Array<{
    physicalLocation: {
      artifactLocation: {
        uri: string;
        uriBaseId: string;
      };
      region: {
        startLine: number;
        startColumn?: number;
        snippet?: { text: string };
      };
    };
  }>;
}

export interface SarifReport {
  $schema: string;
  version: string;
  runs: Array<{
    tool: {
      driver: {
        name: string;
        version: string;
        informationUri: string;
        rules: SarifRule[];
      };
    };
    results: SarifResult[];
  }>;
}

export function severityToSarifLevel(
  severity: SeverityLevel
): 'error' | 'warning' | 'note' | 'none' {
  switch (severity) {
    case 'CRITICAL':
    case 'HIGH':
      return 'error';
    case 'MEDIUM':
      return 'warning';
    case 'LOW':
      return 'note';
    case 'INFO':
    default:
      return 'none';
  }
}

export function severityToProblemSeverity(
  severity: SeverityLevel
): 'error' | 'warning' | 'recommendation' {
  switch (severity) {
    case 'CRITICAL':
    case 'HIGH':
      return 'error';
    case 'MEDIUM':
      return 'warning';
    case 'LOW':
    default:
      return 'recommendation';
  }
}

export function generateSarifReport(
  findings: VulnerabilityFinding[],
  customRules?: any[]
): SarifReport {
  const rulesMap = new Map<string, SarifRule>();
  const rulesToMap = (customRules && customRules.length > 0) ? customRules : SECURITY_RULES;

  for (const rule of rulesToMap) {
    const rawCwe = typeof rule?.cwe === 'string' && rule.cwe.trim() ? rule.cwe.trim() : 'N/A';
    const cweTag = rawCwe.toLowerCase();
    const categoryText = typeof rule?.category === 'string' && rule.category.trim() ? rule.category.trim() : 'Security';
    const messageText = typeof rule?.message === 'string' ? rule.message : '';
    const remediationText = typeof rule?.remediation === 'string' ? rule.remediation : '';
    rulesMap.set(rule.id, {
      id: rule.id,
      name: categoryText.replace(/[^a-zA-Z0-9]/g, '') || rule.id.replace(/[^a-zA-Z0-9]/g, ''),
      shortDescription: { text: categoryText },
      fullDescription: { text: messageText },
      defaultConfiguration: { level: severityToSarifLevel(rule.severity) },
      help: {
        text: `${messageText}\nRemediation: ${remediationText}`,
        markdown: `**${categoryText}** (${rawCwe})\n\n${messageText}\n\n### Remediation\n${remediationText}`
      },
      properties: {
        tags: ['security', 'sast', cweTag],
        precision: 'high',
        'problem.severity': severityToProblemSeverity(rule.severity)
      }
    });
  }

  const results: SarifResult[] = [];

  for (const finding of findings) {
    const normalizedUri = finding.file.replace(/\\/g, '/');
    const sarifLevel = severityToSarifLevel(finding.severity);
    const maskedSnippet = finding.snippet ? maskSensitiveSnippet(finding.snippet) : undefined;

    results.push({
      ruleId: finding.ruleId,
      level: sarifLevel,
      message: {
        text: `[${finding.severity}] ${finding.title}: ${finding.description}`
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: normalizedUri,
              uriBaseId: '%SRCROOT%'
            },
            region: {
              startLine: Math.max(1, finding.line),
              startColumn: 1,
              ...(maskedSnippet ? { snippet: { text: maskedSnippet } } : {})
            }
          }
        }
      ]
    });
  }

  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'Wide Security',
            version: resolveToolVersion(),
            informationUri: 'https://github.com/sl4de0day/wide-action',
            rules: Array.from(rulesMap.values())
          }
        },
        results
      }
    ]
  };
}

export function writeSarifReport(
  outputPath: string,
  findings: VulnerabilityFinding[],
  workspaceDir = process.cwd(),
  customRules?: any[]
): string {
  const fullPath = resolve(workspaceDir, outputPath);
  const dir = dirname(fullPath);

  mkdirSync(dir, { recursive: true });

  const sarifData = generateSarifReport(findings, customRules);
  writeFileSync(fullPath, JSON.stringify(sarifData, null, 2), 'utf8');

  core.info(`Generated SARIF 2.1.0 report at: ${outputPath}`);
  return fullPath;
}
