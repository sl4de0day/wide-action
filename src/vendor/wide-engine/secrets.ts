const KNOWN_SECRET_PREFIX_RE = /^(?:AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|AIza[0-9A-Za-z\-_]{30,}|sk-(?:proj-|ant-)?[A-Za-z0-9\-_]{20,}|xox[baprs]-[0-9A-Za-z-]{10,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)/;
const KNOWN_TOKEN_INLINE_RE = /\b(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|AIza[0-9A-Za-z\-_]{30,}|sk-(?:proj-|ant-)?[A-Za-z0-9\-_]{20,}|xox[baprs]-[0-9A-Za-z-]{10,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)/;
const KNOWN_PREFIX_DUMMY_RE = /(?:example|dummy|placeholder|your[_-]|changeme|replace[_-]?me|xxxxxx|000000)/i;
const PLACEHOLDER_RE = /(?:example|sample|dummy|placeholder|your[_-]|changeme|replace[_-]?me|test[_-]?(?:key|token|secret)|fake|redacted|localhost|000000|123456|xxxxxx|\$\{\{?|<[A-Z0-9_]+>)/i;
const ENV_REFERENCE_RE = /process\.env\.|os\.environ|import\.meta\.env\.|\$\{\{?\s*secrets\./i;
const TEST_PATH_RE = /(?:^|[/\\])(?:test|tests|__tests__|spec|specs|fixtures?|mocks?)(?:[/\\]|$)|\.(?:test|spec)\.[jt]sx?$|(?:^|[/\\])test_[^/\\]*\.py$/i;

export function shannonEntropy(value: string): number {
  const s = String(value || "");
  if (!s) return 0;
  const counts = new Map<string, number>();
  for (const ch of s) {
    counts.set(ch, (counts.get(ch) || 0) + 1);
  }
  let entropy = 0;
  for (const c of counts.values()) {
    const p = c / s.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

export function containsKnownToken(lineText: string): boolean {
  return KNOWN_TOKEN_INLINE_RE.test(String(lineText || ""));
}

export function isLikelyRealSecret(lineText: string, filePath = ""): boolean {
  const line = String(lineText || "");
  if (!line.trim()) return false;
  if (ENV_REFERENCE_RE.test(line)) return false;

  const isTestFile = TEST_PATH_RE.test(filePath);
  const literalMatch = /["'`]([^"'`\r\n]{8,})["'`]/.exec(line) || /[:=]\s*([A-Za-z0-9_+/=-]{12,})/.exec(line);
  const candidate = literalMatch ? literalMatch[1].trim() : line.trim();

  if (KNOWN_SECRET_PREFIX_RE.test(candidate) || KNOWN_SECRET_PREFIX_RE.test(line) || KNOWN_TOKEN_INLINE_RE.test(line)) {
    return !KNOWN_PREFIX_DUMMY_RE.test(candidate);
  }

  if (PLACEHOLDER_RE.test(candidate)) return false;
  if (/^(.)\1{5,}$/.test(candidate)) return false;

  const entropy = shannonEntropy(candidate);
  if (candidate.length >= 16 && entropy < 2.8) return false;
  if (isTestFile && entropy < 3.4) return false;
  return true;
}
