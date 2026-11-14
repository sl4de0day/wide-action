import { writeFileSync, mkdirSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import * as core from '@actions/core';
import { SECURITY_RULES } from './engine/rules.js';
import { SeverityLevel, VulnerabilityFinding } from './types.js';

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
    const cweTag = rule.cwe.toLowerCase();
    rulesMap.set(rule.id, {
      id: rule.id,
      name: rule.category.replace(/[^a-zA-Z0-9]/g, ''),
      shortDescription: { text: rule.category },
      fullDescription: { text: rule.message },
      defaultConfiguration: { level: severityToSarifLevel(rule.severity) },
      help: {
        text: `${rule.message}\nRemediation: ${rule.remediation}`,
        markdown: `**${rule.category}** (${rule.cwe})\n\n${rule.message}\n\n### Remediation\n${rule.remediation}`
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
              ...(finding.snippet ? { snippet: { text: finding.snippet } } : {})
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
            version: '0.3141126',
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
