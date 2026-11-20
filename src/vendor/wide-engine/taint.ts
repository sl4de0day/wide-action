import type { EngineFinding, EngineSeverity, LogicalSpan, SourceFile, TaintOptions } from "./types.js";

const SOURCE_RE = new RegExp([
  "\\breq(?:uest)?\\.(?:query|params|body|headers|cookies|args|form|values|files|data|param)\\b",
  "\\blocation\\.(?:search|hash|href)\\b",
  "\\bdocument\\.(?:referrer|URL|cookie)\\b",
  "\\.searchParams\\b",
  "searchParams\\.get\\s*\\(",
  "\\bevent\\.data\\b",
  "\\bprocess\\.argv\\b",
  "\\brequest\\.(?:GET|POST|args|form|values|json|data|params|cookies|headers|files|query_params|body)\\b",
  "\\brequest\\.get_json\\s*\\(",
  "\\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\\b",
  "\\bfile_get_contents\\s*\\(\\s*['\"]php://input",
  "\\br\\.URL\\.Query\\s*\\(",
  "\\br\\.FormValue\\s*\\(",
  "\\br\\.PostFormValue\\s*\\(",
  "\\bc\\.(?:Query|Param|PostForm|DefaultQuery|GetHeader)\\s*\\(",
  "\\bmux\\.Vars\\s*\\(",
  "@(?:RequestParam|PathVariable|RequestHeader|RequestBody)\\b",
  "\\.getParameter(?:Values)?\\s*\\(",
  "\\bstd::env::args\\b",
  "\\bos\\.environ\\b"
].join("|"));

const SANITISER_RE = /\b(?:sanitiz|sanitis|escapeHtml|htmlEscape|escape(?:ShellArg)?|encodeURI(?:Component)?|DOMPurify|purify|htmlspecialchars|htmlentities|escapeshellarg|shlex\.quote|Number|parseInt|parseFloat|Boolean|basename|realpath|allowlist|whitelist|validator|bindparam|bind_param|PreparedStatement|prepare|Integer\.parseInt|Integer\.valueOf|intval|is_numeric|commonpath|ConstantTimeCompare|timingSafeEqual|hash_equals)\b/i;

const IDENT_RE = /\b[A-Za-z_][A-Za-z0-9_]*\b/g;

const HASH_COMMENT_LANGS = new Set(["py", "rb", "yaml", "yml", "tf", "hcl", "sh"]);
const BRACE_FUNCTION_LANGS = new Set(["js", "ts", "jsx", "tsx", "mjs", "cjs", "mts", "cts"]);

interface TaintSinkDef {
  id: string;
  cwe: string;
  category: string;
  severity: EngineSeverity;
  message: string;
  re: RegExp;
}

const TAINT_SINKS: readonly TaintSinkDef[] = [
  {
    id: "wide/taint-sql",
    cwe: "CWE-89",
    category: "INJECTION",
    severity: "CRITICAL",
    message: "Tainted user input reaches a SQL execution sink without parameterization.",
    re: /(?:(?:\.|->)(?:query|queryRaw|execute|executeQuery|executeUpdate|raw|rawQuery|find_by_sql)\s*\(|\b(?:createStatement|db\.Query|db\.Exec|cursor\.execute)\s*\()/
  },
  {
    id: "wide/taint-command",
    cwe: "CWE-78",
    category: "INJECTION",
    severity: "CRITICAL",
    message: "Tainted user input reaches an OS command execution sink.",
    re: /\b(?:exec|execSync|spawn|spawnSync|shell_exec|passthru|popen|proc_open|os\.system|subprocess\.(?:run|Popen|call)|Runtime\.getRuntime\(\)\.exec|ProcessBuilder|Command::new)\s*\(/
  },
  {
    id: "wide/taint-xss",
    cwe: "CWE-79",
    category: "XSS",
    severity: "HIGH",
    message: "Tainted user input reaches an unescaped HTML or DOM rendering sink.",
    re: /(?:\.(?:innerHTML|outerHTML)\s*=|insertAdjacentHTML\s*\(|document\.write\s*\(|dangerouslySetInnerHTML\s*[:=]|\bres\.(?:send|write)\s*\()/
  },
  {
    id: "wide/taint-ssrf",
    cwe: "CWE-918",
    category: "NETWORK",
    severity: "HIGH",
    message: "Tainted user input controls the target URL of an outbound network request.",
    re: /\b(?:fetch|axios(?:\.(?:get|post|put|delete|request))?|got|http\.(?:get|Get|Post|NewRequest)|https\.get|requests\.(?:get|post|put|delete|request)|urllib\.request\.urlopen|curl_exec)\s*\(/
  },
  {
    id: "wide/taint-path",
    cwe: "CWE-22",
    category: "FILESYSTEM",
    severity: "HIGH",
    message: "Tainted user input reaches a filesystem path operation without normalization or boundary checks.",
    re: /\b(?:fs\.(?:readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream|unlink|unlinkSync|rm|rmSync)|file_get_contents|file_put_contents|readfile|os\.(?:Open|ReadFile|Create)|ioutil\.ReadFile|Files\.(?:readString|readAllBytes|write)|open)\s*\(/
  },
  {
    id: "wide/taint-redirect",
    cwe: "CWE-601",
    category: "NETWORK",
    severity: "MEDIUM",
    message: "Tainted user input controls an HTTP redirect destination without origin validation.",
    re: /\b(?:res\.redirect|redirect_to|sendRedirect|http\.Redirect)\s*\(/
  },
  {
    id: "wide/taint-code-exec",
    cwe: "CWE-94",
    category: "INJECTION",
    severity: "CRITICAL",
    message: "Tainted user input reaches dynamic code or template evaluation.",
    re: /\b(?:eval|Function|vm\.runInNewContext|render_template_string|jinja2\.Template|unserialize|pickle\.loads|yaml\.unsafe_load)\s*\(/
  }
];

function isCommentSpan(text: string, lang: string): boolean {
  const t = String(text || "").trim();
  if (!t) return true;
  if (t.startsWith("//") || t.startsWith("/*") || t.startsWith("* ") || t === "*" || t.startsWith("<!--")) return true;
  if (HASH_COMMENT_LANGS.has(lang) && t.startsWith("#")) return true;
  return false;
}

function delimiterDelta(line: string): number {
  let delta = 0;
  let inSingle = false;
  let inDouble = false;
  let escaped = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (ch === "\\") {
      escaped = true;
      continue;
    }
    if (ch === "'" && !inDouble) inSingle = !inSingle;
    else if (ch === "\"" && !inSingle) inDouble = !inDouble;
    else if (!inSingle && !inDouble) {
      if (ch === "(" || ch === "[") delta++;
      else if (ch === ")" || ch === "]") delta--;
    }
  }
  return delta;
}

export function buildLogicalSpans(lines: readonly string[], maxSpanLines = 8): LogicalSpan[] {
  const spans: LogicalSpan[] = [];
  let i = 0;
  while (i < lines.length) {
    const lineText = String(lines[i] || "");
    if (!lineText.trim()) {
      i++;
      continue;
    }
    let depth = delimiterDelta(lineText);
    let end = i;
    while (depth > 0 && end + 1 < lines.length && end - i + 1 < maxSpanLines) {
      end++;
      depth += delimiterDelta(String(lines[end] || ""));
    }
    const text = lines.slice(i, end + 1).map((l) => String(l).trim()).join(" ");
    spans.push({
      startLine: i + 1,
      endLine: end + 1,
      text: text.slice(0, 3000)
    });
    i = end + 1;
  }
  return spans;
}

function hasTaintedIdentifier(expr: string, tainted: ReadonlySet<string>): boolean {
  if (!expr || tainted.size === 0) return false;
  IDENT_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = IDENT_RE.exec(expr)) !== null) {
    if (tainted.has(m[0])) return true;
  }
  return false;
}

function isExpressionTainted(rhs: string, tainted: ReadonlySet<string>): boolean {
  if (!rhs) return false;
  if (SANITISER_RE.test(rhs)) return false;
  if (SOURCE_RE.test(rhs)) return true;
  return hasTaintedIdentifier(rhs, tainted);
}

function trackAssignments(spanText: string, tainted: Set<string>): void {
  const destruct = /^(?:const|let|var)\s*\{\s*([^}]+)\}\s*=\s*([^;]+)/.exec(spanText);
  if (destruct) {
    const isTainted = isExpressionTainted(destruct[2], tainted);
    for (const part of destruct[1].split(",")) {
      const name = (part.split(":").pop() || "").replace(/\s*=.*$/, "").trim();
      if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) {
        if (isTainted) tainted.add(name);
        else tainted.delete(name);
      }
    }
    return;
  }

  const decl = /^(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*([^;]+)/.exec(spanText);
  if (decl) {
    if (isExpressionTainted(decl[2], tainted)) tainted.add(decl[1]);
    else tainted.delete(decl[1]);
    return;
  }

  const goAssign = /^([A-Za-z_][A-Za-z0-9_]*)\s*:=\s*(.+)$/.exec(spanText);
  if (goAssign) {
    if (isExpressionTainted(goAssign[2], tainted)) tainted.add(goAssign[1]);
    else tainted.delete(goAssign[1]);
    return;
  }

  const assign = /^\$?([A-Za-z_][A-Za-z0-9_]*)\s*(?:\+?=)\s*([^=].*)$/.exec(spanText);
  if (assign) {
    if (isExpressionTainted(assign[2], tainted)) tainted.add(assign[1]);
    else if (!spanText.includes("+=")) tainted.delete(assign[1]);
  }
}

function isParameterizedSqlCall(spanText: string): boolean {
  if (!/(?:query|execute|prepare)\s*\(/i.test(spanText)) return false;
  const hasPlaceholder = /\$\d+|\?|%s|%d|:\w+/.test(spanText);
  const hasArgsArray = /,\s*[\[(]/.test(spanText);
  const hasConcat = /\+\s*[A-Za-z_$]|\$\{[^}]+\}|\.format\s*\(|f["']/.test(spanText);
  return hasPlaceholder && hasArgsArray && !hasConcat;
}

function hasPathBoundaryGuard(spanText: string, contextWindow: string): boolean {
  return /(?:commonpath|path\.relative\b|startsWith\([^)]*sep\b|realpath\b|Path\.normalize\b)/.test(`${contextWindow}\n${spanText}`);
}

function hasUrlAllowlistGuard(spanText: string, contextWindow: string): boolean {
  return /(?:ALLOWED_HOSTS|allowedHosts|new URL\([^)]*\)\.hostname\s*===|url\.Parse\b)/.test(`${contextWindow}\n${spanText}`) &&
    !/\bfetch\s*\(\s*req\./.test(spanText);
}

export function analyzeFileTaint(
  content: string,
  lang: string,
  filePath = "",
  options: TaintOptions = {}
): EngineFinding[] {
  const lines = String(content || "").split(/\r?\n/);
  const spans = buildLogicalSpans(lines);
  const tainted = new Set<string>(options.seedTainted || []);
  const findings: EngineFinding[] = [];
  const emitted = new Set<string>();

  for (let idx = 0; idx < spans.length; idx++) {
    const span = spans[idx];
    if (isCommentSpan(span.text, lang)) continue;

    trackAssignments(span.text, tainted);

    const hasSource = SOURCE_RE.test(span.text) || hasTaintedIdentifier(span.text, tainted);
    if (!hasSource) continue;
    if (SANITISER_RE.test(span.text) && !/\+\s*[A-Za-z_$]|\$\{/.test(span.text)) continue;

    const prevWindow = spans.slice(Math.max(0, idx - 6), idx).map((s) => s.text).join("\n");

    for (const sink of TAINT_SINKS) {
      if (!sink.re.test(span.text)) continue;
      if (sink.cwe === "CWE-89" && isParameterizedSqlCall(span.text)) continue;
      if (sink.cwe === "CWE-22" && hasPathBoundaryGuard(span.text, prevWindow)) continue;
      if (sink.cwe === "CWE-918" && hasUrlAllowlistGuard(span.text, prevWindow)) continue;
      if (sink.cwe === "CWE-78" && /\b(?:execFile|spawn|spawnSync)\s*\([^,]+,\s*\[/.test(span.text)) continue;
      if (sink.cwe === "CWE-78" && /\bsubprocess\.run\s*\(\s*\[/.test(span.text) && !/shell\s*=\s*True/.test(span.text)) continue;
      if (sink.cwe === "CWE-79" && /\bres\.send\s*\(/.test(span.text)) {
        const looksHtml = /<[a-zA-Z/]|text\/html/.test(span.text) && /\+\s*[A-Za-z_$]|\$\{/.test(span.text);
        if (!looksHtml) continue;
      }

      const key = `${filePath}:${span.startLine}:${sink.cwe}`;
      if (emitted.has(key)) continue;
      emitted.add(key);

      findings.push({
        id: sink.id,
        ruleId: sink.id,
        cwe: sink.cwe,
        category: sink.category,
        severity: sink.severity,
        file: filePath,
        line: span.startLine,
        endLine: span.endLine,
        snippet: span.text.slice(0, 220),
        message: sink.message,
        remediation: `Validate, escape, or parameterize untrusted input before passing it into ${sink.cwe} sinks.`,
        source: "taint"
      });
    }
  }

  return findings;
}

interface FunctionDef {
  file: string;
  lang: string;
  name: string;
  params: string[];
  startLine: number;
  body: string;
}

interface FnSummary {
  file: string;
  fnName: string;
  paramIdx: number;
  cwe: string;
  category: string;
  severity: EngineSeverity;
  sinkLine: number;
}

function extractCallSites(text: string): Array<{ fnName: string; argsRaw: string }> {
  const calls: Array<{ fnName: string; argsRaw: string }> = [];
  const headRe = /\b([A-Za-z_][A-Za-z0-9_]*)\s*\(/g;
  let m: RegExpExecArray | null;
  while ((m = headRe.exec(text)) !== null) {
    const fnName = m[1];
    const openIdx = headRe.lastIndex - 1;
    let depth = 0;
    let inSingle = false;
    let inDouble = false;
    let escaped = false;
    let closeIdx = -1;
    for (let i = openIdx; i < text.length; i++) {
      const ch = text[i];
      if (escaped) {
        escaped = false;
        continue;
      }
      if (ch === "\\") {
        escaped = true;
        continue;
      }
      if (ch === "'" && !inDouble) inSingle = !inSingle;
      else if (ch === "\"" && !inSingle) inDouble = !inDouble;
      else if (!inSingle && !inDouble) {
        if (ch === "(") depth++;
        else if (ch === ")") {
          depth--;
          if (depth === 0) {
            closeIdx = i;
            break;
          }
        }
      }
    }
    if (closeIdx > openIdx) {
      calls.push({ fnName, argsRaw: text.slice(openIdx + 1, closeIdx) });
    }
  }
  return calls;
}

function splitTopLevelArgs(argListStr: string): string[] {
  const args: string[] = [];
  let cur = "";
  let depth = 0;
  let inSingle = false;
  let inDouble = false;
  let escaped = false;
  for (let i = 0; i < argListStr.length; i++) {
    const ch = argListStr[i];
    if (escaped) {
      cur += ch;
      escaped = false;
      continue;
    }
    if (ch === "\\") {
      cur += ch;
      escaped = true;
      continue;
    }
    if (ch === "'" && !inDouble) {
      inSingle = !inSingle;
      cur += ch;
    } else if (ch === "\"" && !inSingle) {
      inDouble = !inDouble;
      cur += ch;
    } else if (!inSingle && !inDouble) {
      if (ch === "(" || ch === "[" || ch === "{") {
        depth++;
        cur += ch;
      } else if (ch === ")" || ch === "]" || ch === "}") {
        depth = Math.max(0, depth - 1);
        cur += ch;
      } else if (ch === "," && depth === 0) {
        args.push(cur.trim());
        cur = "";
      } else {
        cur += ch;
      }
    } else {
      cur += ch;
    }
  }
  if (cur.trim()) args.push(cur.trim());
  return args;
}

function extractBraceFunctions(lines: readonly string[], file: string, lang: string): FunctionDef[] {
  const defs: FunctionDef[] = [];
  const fnRe = /(?:export\s+(?:default\s+)?)?(?:async\s+)?function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)|(?:export\s+)?const\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>/;

  for (let i = 0; i < lines.length; i++) {
    const m = fnRe.exec(lines[i]);
    if (!m) continue;
    const name = m[1] || m[3];
    const rawParams = m[2] !== undefined ? m[2] : (m[4] || "");
    if (!name || name.length < 2) continue;

    const params = rawParams
      .split(",")
      .map((p) => p.replace(/:\s*[^=]+/, "").replace(/\s*=.*$/, "").trim().replace(/^\.\.\./, ""))
      .filter((p) => /^[A-Za-z_][A-Za-z0-9_]*$/.test(p));
    if (params.length === 0) continue;

    let braceDepth = 0;
    let started = false;
    let end = i;
    for (let j = i; j < Math.min(lines.length, i + 120); j++) {
      for (const ch of lines[j]) {
        if (ch === "{") {
          braceDepth++;
          started = true;
        } else if (ch === "}") {
          braceDepth--;
        }
      }
      end = j;
      if (started && braceDepth <= 0) break;
    }
    defs.push({ file, lang, name, params, startLine: i + 1, body: lines.slice(i, end + 1).join("\n") });
  }
  return defs;
}

function extractPythonFunctions(lines: readonly string[], file: string): FunctionDef[] {
  const defs: FunctionDef[] = [];
  const pyDefRe = /^(\s*)(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*(?:->[^:]+)?:/;
  for (let i = 0; i < lines.length; i++) {
    const m = pyDefRe.exec(lines[i]);
    if (!m) continue;
    const indent = m[1].length;
    const name = m[2];
    const params = (m[3] || "")
      .split(",")
      .map((p) => p.split(":")[0].split("=")[0].trim().replace(/^\*+/, ""))
      .filter((p) => /^[A-Za-z_][A-Za-z0-9_]*$/.test(p) && p !== "self" && p !== "cls");
    if (params.length === 0) continue;

    let end = i;
    for (let j = i + 1; j < Math.min(lines.length, i + 120); j++) {
      const t = lines[j];
      if (!t.trim()) continue;
      const curIndent = (/^(\s*)/.exec(t)?.[1] || "").length;
      if (curIndent <= indent) break;
      end = j;
    }
    defs.push({ file, lang: "py", name, params, startLine: i + 1, body: lines.slice(i, end + 1).join("\n") });
  }
  return defs;
}

export function analyzeProjectFlows(files: readonly SourceFile[]): EngineFinding[] {
  const entries = Array.isArray(files) ? files : [];
  const summariesByName = new Map<string, FnSummary[]>();
  const allFindings: EngineFinding[] = [];
  const parsedFiles: Array<{ file: string; lang: string; spans: LogicalSpan[] }> = [];

  for (const item of entries) {
    if (!item || !item.content || !item.file) continue;
    const lang = item.lang || "js";
    const lines = String(item.content).split(/\r?\n/);
    allFindings.push(...analyzeFileTaint(item.content, lang, item.file));
    parsedFiles.push({ file: item.file, lang, spans: buildLogicalSpans(lines) });

    const fns = lang === "py"
      ? extractPythonFunctions(lines, item.file)
      : BRACE_FUNCTION_LANGS.has(lang)
        ? extractBraceFunctions(lines, item.file, lang)
        : [];

    for (const fn of fns) {
      for (let paramIdx = 0; paramIdx < fn.params.length; paramIdx++) {
        const param = fn.params[paramIdx];
        if (param.length <= 1) continue;
        const sinkFindings = analyzeFileTaint(fn.body, lang, fn.file, { seedTainted: [param] });
        if (sinkFindings.length === 0) continue;
        let list = summariesByName.get(fn.name);
        if (!list) {
          list = [];
          summariesByName.set(fn.name, list);
        }
        for (const sf of sinkFindings) {
          list.push({
            file: fn.file,
            fnName: fn.name,
            paramIdx,
            cwe: sf.cwe,
            category: sf.category,
            severity: sf.severity,
            sinkLine: fn.startLine + sf.line - 1
          });
        }
      }
    }
  }

  const emitted = new Set<string>();
  for (const entry of parsedFiles) {
    const localTainted = new Set<string>();
    for (const span of entry.spans) {
      if (isCommentSpan(span.text, entry.lang)) continue;
      trackAssignments(span.text, localTainted);
      if (/\b(?:function|def)\s+/.test(span.text)) continue;

      for (const call of extractCallSites(span.text)) {
        const sumList = summariesByName.get(call.fnName);
        if (!sumList || sumList.length === 0) continue;
        const args = splitTopLevelArgs(call.argsRaw);

        for (const sum of sumList) {
          const argExpr = args[sum.paramIdx];
          if (!argExpr || !isExpressionTainted(argExpr, localTainted)) continue;

          const isCrossFile = sum.file !== entry.file;
          const key = `${entry.file}:${span.startLine}:${sum.cwe}:${call.fnName}`;
          if (emitted.has(key)) continue;
          emitted.add(key);

          const ruleId = isCrossFile ? `wide/flow-cross-${sum.cwe.toLowerCase()}` : `wide/flow-local-${sum.cwe.toLowerCase()}`;
          allFindings.push({
            id: ruleId,
            ruleId,
            cwe: sum.cwe,
            category: sum.category,
            severity: sum.severity,
            file: entry.file,
            line: span.startLine,
            endLine: span.endLine,
            snippet: span.text.slice(0, 220),
            message: isCrossFile
              ? `Cross-file taint flow: untrusted input passed to ${call.fnName}() reaches ${sum.cwe} sink at ${sum.file}:${sum.sinkLine}.`
              : `Inter-procedural taint flow: untrusted input passed to ${call.fnName}() reaches ${sum.cwe} sink at line ${sum.sinkLine}.`,
            remediation: `Validate or sanitize the argument passed to ${call.fnName}() or parameterize the sink in ${sum.file}:${sum.sinkLine}.`,
            source: "taint",
            crossFile: isCrossFile
          });
        }
      }
    }
  }

  return allFindings;
}
