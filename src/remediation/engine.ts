import * as core from '@actions/core';
import { VulnerabilityFinding } from '../types.js';

export interface RemediationOptions {
  provider: string;
  apiKey: string;
  timeoutMs?: number;
}

export class RemediationEngine {
  private provider: string;
  private apiKey: string;
  private timeoutMs: number;

  constructor(options: RemediationOptions) {
    this.provider = options.provider.trim().toLowerCase();
    this.apiKey = options.apiKey || this.resolveApiKey(this.provider);
    this.timeoutMs = options.timeoutMs || 15000;
  }

  public async generatePatch(
    finding: VulnerabilityFinding,
    surroundingContext = ''
  ): Promise<string | null> {
    if (!this.apiKey) {
      core.info(`AI Remediation skipped: No API key provided for provider '${this.provider}'.`);
      return null;
    }

    const prompt = this.buildPrompt(finding, surroundingContext);

    try {
      let rawResponse: string | null = null;

      if (this.provider === 'gemini') {
        rawResponse = await this.callGemini(prompt);
      } else if (this.provider === 'claude') {
        rawResponse = await this.callClaude(prompt);
      } else if (this.provider === 'deepseek') {
        rawResponse = await this.callOpenAiCompatible(
          'https://api.deepseek.com',
          'deepseek-chat',
          prompt
        );
      } else if (this.provider === 'openai') {
        rawResponse = await this.callOpenAiCompatible(
          'https://api.openai.com/v1',
          'gpt-4o-mini',
          prompt
        );
      } else {
        core.warning(`Unsupported AI provider for remediation: ${this.provider}`);
        return null;
      }

      if (!rawResponse) return null;
      return this.extractSuggestionCode(rawResponse);
    } catch (error) {
      core.warning(`AI Remediation error with ${this.provider}: ${String(error)}`);
      return null;
    }
  }

  private resolveApiKey(provider: string): string {
    switch (provider) {
      case 'gemini':
        return process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY || '';
      case 'claude':
        return process.env.ANTHROPIC_API_KEY || process.env.CLAUDE_API_KEY || '';
      case 'deepseek':
        return process.env.DEEPSEEK_API_KEY || '';
      case 'openai':
        return process.env.OPENAI_API_KEY || '';
      default:
        return '';
    }
  }

  private buildPrompt(finding: VulnerabilityFinding, context: string): string {
    return [
      'You are an automated secure code remediation assistant.',
      `Vulnerability Detected: ${finding.title} (${finding.cwe || 'CWE'})`,
      `Severity: ${finding.severity}`,
      `File: ${finding.file} at line ${finding.line}`,
      `Description: ${finding.description}`,
      `Standard Remediation: ${finding.remediation}`,
      '',
      'Vulnerable Snippet:',
      finding.snippet || '',
      '',
      context ? `Surrounding Context:\n${context}\n` : '',
      'Provide a direct, production-ready replacement for ONLY the vulnerable line or minimal code block.',
      'Wrap your replacement inside a GitHub suggested change block:',
      '```suggestion',
      '<replacement code here>',
      '```',
      'Do not include any explanations, prose, or commentary outside the suggestion block.'
    ].join('\n');
  }

  private async callGemini(prompt: string): Promise<string | null> {
    const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${this.apiKey}`;
    const payload = {
      contents: [{ role: 'user', parts: [{ text: prompt }] }],
      generationConfig: { temperature: 0.2, maxOutputTokens: 1024 }
    };

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        signal: controller.signal
      });

      if (!response.ok) {
        const text = await response.text();
        throw new Error(`Gemini HTTP ${response.status}: ${text}`);
      }

      const data = await response.json() as any;
      return data?.candidates?.[0]?.content?.parts?.[0]?.text || null;
    } finally {
      clearTimeout(timeout);
    }
  }

  private async callClaude(prompt: string): Promise<string | null> {
    const url = 'https://api.anthropic.com/v1/messages';
    const payload = {
      model: 'claude-3-5-sonnet-20241022',
      max_tokens: 1024,
      temperature: 0.2,
      messages: [{ role: 'user', content: prompt }]
    };

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': this.apiKey,
          'anthropic-version': '2023-06-01'
        },
        body: JSON.stringify(payload),
        signal: controller.signal
      });

      if (!response.ok) {
        const text = await response.text();
        throw new Error(`Claude HTTP ${response.status}: ${text}`);
      }

      const data = await response.json() as any;
      return data?.content?.[0]?.text || null;
    } finally {
      clearTimeout(timeout);
    }
  }

  private async callOpenAiCompatible(
    baseUrl: string,
    model: string,
    prompt: string
  ): Promise<string | null> {
    const url = `${baseUrl.replace(/\/+$/, '')}/chat/completions`;
    const payload = {
      model,
      temperature: 0.2,
      max_tokens: 1024,
      messages: [{ role: 'user', content: prompt }]
    };

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${this.apiKey}`
        },
        body: JSON.stringify(payload),
        signal: controller.signal
      });

      if (!response.ok) {
        const text = await response.text();
        throw new Error(`${model} HTTP ${response.status}: ${text}`);
      }

      const data = await response.json() as any;
      return data?.choices?.[0]?.message?.content || null;
    } finally {
      clearTimeout(timeout);
    }
  }

  public extractSuggestionCode(raw: string): string | null {
    if (!raw) return null;

    const match = raw.match(/```suggestion\r?\n([\s\S]*?)\r?\n```/);
    if (match && match[1] !== undefined) {
      return match[1].trimEnd();
    }

    const codeBlockMatch = raw.match(/```(?:[a-zA-Z0-9_\-]+)?\r?\n([\s\S]*?)\r?\n```/);
    if (codeBlockMatch && codeBlockMatch[1] !== undefined) {
      return codeBlockMatch[1].trimEnd();
    }

    const trimmed = raw.trim();
    if (trimmed && !trimmed.includes('```')) {
      return trimmed;
    }

    return null;
  }
}
