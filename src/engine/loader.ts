import { createHash } from 'node:crypto';
import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import * as core from '@actions/core';
import { SECURITY_RULES, DEFAULT_AGENT_RULES, SecurityRule } from './rules.js';

const REMOTE_RULES_URL = 'https://raw.githubusercontent.com/sl4de0day/wide-rules/main/dist/rules.json';
const REMOTE_OSV_URL = 'https://raw.githubusercontent.com/sl4de0day/wide-rules/main/dist/osv-bundle.json';
const REMOTE_CHECKSUMS_URL = 'https://raw.githubusercontent.com/sl4de0day/wide-rules/main/dist/SHA256SUMS';

function parseChecksums(raw: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const line of String(raw || '').split(/\r?\n/)) {
    const m = /^([a-fA-F0-9]{64})\s+\*?(.+)$/.exec(line.trim());
    if (m) out.set(m[2].trim(), m[1].toLowerCase());
  }
  return out;
}

export class RuleLoader {
  public static async loadRules(
    source = 'embedded',
    workspaceDir = process.cwd()
  ): Promise<SecurityRule[]> {
    const trimmed = source.trim();

    if (trimmed.toLowerCase() === 'latest') {
      try {
        core.info(`Fetching latest security rules from ${REMOTE_RULES_URL}...`);
        let checksums = new Map<string, string>();
        try {
          const sumRes = await fetch(REMOTE_CHECKSUMS_URL);
          if (sumRes.ok) checksums = parseChecksums(await sumRes.text());
        } catch {
          void 0;
        }
        const response = await fetch(REMOTE_RULES_URL);
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        const raw = await response.text();
        const expectedSha = checksums.get('rules.json');
        if (expectedSha) {
          const actualSha = createHash('sha256').update(raw).digest('hex');
          if (actualSha !== expectedSha) {
            throw new Error('SHA-256 mismatch while downloading rules.json');
          }
        }
        const data = JSON.parse(raw) as any;
        const list = Array.isArray(data) ? data : (data?.rules || []);
        const converted = this.parseRulesList(list);
        if (converted.length > 0) {
          core.info(`Successfully loaded ${converted.length} rules dynamically from wide-rules.`);
          return converted;
        }
      } catch (error) {
        core.warning(`Failed to fetch latest rules dynamically: ${String(error)}. Falling back to embedded rules.`);
      }
      return [...SECURITY_RULES];
    }

    if (trimmed.toLowerCase() !== 'embedded') {
      const fullPath = resolve(workspaceDir, trimmed);
      if (existsSync(fullPath)) {
        try {
          const raw = readFileSync(fullPath, 'utf8');
          const data = JSON.parse(raw);
          const list = Array.isArray(data) ? data : (data?.rules || []);
          const converted = this.parseRulesList(list);
          if (converted.length > 0) {
            core.info(`Loaded ${converted.length} custom rules from ${trimmed}.`);
            return converted;
          }
        } catch (err) {
          core.warning(`Failed to parse custom rules from ${trimmed}: ${String(err)}. Using embedded rules.`);
        }
      } else {
        core.warning(`Custom rules path not found: ${trimmed}. Using embedded rules.`);
      }
    }

    const siblingRules = resolve(workspaceDir, '../wide-rules/dist/rules.json');
    if (existsSync(siblingRules)) {
      try {
        const raw = readFileSync(siblingRules, 'utf8');
        const data = JSON.parse(raw);
        const list = Array.isArray(data) ? data : (data?.rules || []);
        const converted = this.parseRulesList(list);
        if (converted.length > 0) {
          return converted;
        }
      } catch {
        void 0;
      }
    }

    return [...SECURITY_RULES];
  }

  public static async loadAgentRules(
    source = 'embedded',
    workspaceDir = process.cwd()
  ): Promise<SecurityRule[]> {
    const allRules = await this.loadRules(source, workspaceDir);
    const filtered = allRules.filter(r => r.category === 'AI_SECURITY' || r.id.includes('ai-'));
    if (filtered.length > 0) {
      return filtered;
    }
    return [...DEFAULT_AGENT_RULES];
  }

  public static buildAgentInstructions(rules?: SecurityRule[]): string {
    const targetRules = Array.isArray(rules) && rules.length > 0 ? rules : [...DEFAULT_AGENT_RULES];
    const lines: string[] = [];
    for (const r of targetRules) {
      const text = (r.instruction || r.message || '').trim();
      if (text) {
        lines.push(`- ${text}`);
      }
    }
    return lines.join('\n');
  }

  public static sanitizeOutput(text: string, rules?: SecurityRule[]): string {
    if (!text || typeof text !== 'string') return '';
    const targetRules = Array.isArray(rules) && rules.length > 0 ? rules : [...DEFAULT_AGENT_RULES];
    let result = text;
    for (const r of targetRules) {
      if (r.id === 'wide/ai-no-emojis' || r.id.includes('emoji')) {
        result = result.replace(/(?:[\uD800-\uDBFF][\uDC00-\uDFFF]|[\u2600-\u27BF])/g, '');
        result = result.replace(/\p{Extended_Pictographic}/gu, '');
      }
    }
    return result;
  }

  private static parseRulesList(list: any[]): SecurityRule[] {
    const result: SecurityRule[] = [];
    for (const item of list) {
      if (!item.id || !item.pattern) continue;
      try {
        const notMatchRaw = item['not-match'] || item.notMatch;
        result.push({
          id: item.id,
          cwe: item.cwe || 'N/A',
          category: item.category || 'General Security',
          severity: item.severity || 'MEDIUM',
          languages: item.languages || ['all'],
          pattern: new RegExp(item.pattern, 'i'),
          notMatch: typeof notMatchRaw === 'string' && notMatchRaw ? new RegExp(notMatchRaw, 'i') : undefined,
          sourcePattern: item['source-pattern'] ? new RegExp(item['source-pattern'], 'i') : undefined,
          message: item.message || '',
          remediation: item.remediation || '',
          instruction: item.instruction || item.message || ''
        });
      } catch {
        continue;
      }
    }
    return result;
  }

  public static async loadAdvisories(
    source = 'embedded',
    workspaceDir = process.cwd()
  ): Promise<Record<string, any>> {
    if (source.trim().toLowerCase() === 'latest') {
      try {
        let checksums = new Map<string, string>();
        try {
          const sumRes = await fetch(REMOTE_CHECKSUMS_URL);
          if (sumRes.ok) checksums = parseChecksums(await sumRes.text());
        } catch {
          void 0;
        }
        const res = await fetch(REMOTE_OSV_URL);
        if (res.ok) {
          const raw = await res.text();
          const expectedSha = checksums.get('osv-bundle.json');
          if (expectedSha) {
            const actualSha = createHash('sha256').update(raw).digest('hex');
            if (actualSha !== expectedSha) {
              throw new Error('SHA-256 mismatch while downloading osv-bundle.json');
            }
          }
          return JSON.parse(raw);
        }
      } catch (err) {
        core.warning(`Failed to fetch latest OSV advisories: ${String(err)}.`);
      }
    }
    const candidates = [
      resolve(workspaceDir, '.wide', 'osv.json'),
      resolve(workspaceDir, '../wide-rules/dist/osv-bundle.json')
    ];
    for (const file of candidates) {
      if (existsSync(file)) {
        try {
          return JSON.parse(readFileSync(file, 'utf8'));
        } catch {
          void 0;
        }
      }
    }
    return { npm: [], pip: [], maven: [], go: [] };
  }
}
