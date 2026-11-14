import { SeverityLevel } from '../types.js';

export interface SecurityRule {
  id: string;
  cwe: string;
  category: string;
  severity: SeverityLevel;
  languages: string[];
  pattern: RegExp;
  sourcePattern?: RegExp;
  message: string;
  remediation: string;
  instruction?: string;
}

export const SECURITY_RULES: readonly SecurityRule[] = [
  {
    id: 'WIDE-SEC-001',
    cwe: 'CWE-89',
    category: 'SQL Injection',
    severity: 'CRITICAL',
    languages: ['js', 'ts', 'py', 'php', 'java', 'cs', 'go', 'rb'],
    pattern: /(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE).*?(?:\+|%s|\$|\.format\(|f['"]).*?(?:req\.|params|body|query|input|\$_(?:GET|POST|REQUEST)|request\.)/i,
    sourcePattern: /(?:req\.(?:query|params|body)|request\.(?:args|form|GET|POST)|\$_(?:GET|POST))/i,
    message: 'Dynamic SQL query constructed with unescaped user input.',
    remediation: 'Use parameterized queries or prepared statements (e.g. pool.query(\'SELECT * FROM users WHERE id = $1\', [id])).'
  },
  {
    id: 'WIDE-SEC-002',
    cwe: 'CWE-78',
    category: 'Command Injection',
    severity: 'CRITICAL',
    languages: ['js', 'ts', 'py', 'php', 'java', 'cs', 'go', 'rb'],
    pattern: /(?:child_process|exec|execSync|spawn|subprocess\.Popen|subprocess\.run|os\.system|shell_exec|system|passthru|Runtime\.getRuntime\(\)\.exec)\s*\(\s*(?:`[^`]*\$\{|['"].*?\+\s*|f['"][^'"]*\{)/i,
    sourcePattern: /(?:req\.|request\.|input|param|\$_)/i,
    message: 'System command execution sink receives unescaped parameters.',
    remediation: 'Avoid passing user input to shell commands. Use execFile or spawn with argument arrays without invoking a subshell.'
  },
  {
    id: 'WIDE-SEC-003',
    cwe: 'CWE-79',
    category: 'Cross-Site Scripting (XSS)',
    severity: 'HIGH',
    languages: ['js', 'ts', 'php'],
    pattern: /(?:innerHTML|outerHTML|document\.write|dangerouslySetInnerHTML|v-html|\becho\s+\$_(?:GET|POST)|print\s+\$_)\s*(?:=|\()\s*(?:.*?\b(?:query|param|body|req|location|search|URLSearchParams)\b)/i,
    message: 'Unsanitized user input rendered directly into the DOM or HTML output.',
    remediation: 'Use textContent, framework-native safe bindings, or sanitize HTML using DOMPurify before rendering.'
  },
  {
    id: 'WIDE-SEC-004',
    cwe: 'CWE-918',
    category: 'Server-Side Request Forgery (SSRF)',
    severity: 'HIGH',
    languages: ['js', 'ts', 'py', 'php', 'go', 'java'],
    pattern: /(?:fetch|axios\.(?:get|post|request)|http\.get|urllib\.request|requests\.(?:get|post)|curl_exec)\s*\(\s*(?:req\.|params|query|body|request\.)/i,
    message: 'Outbound HTTP request targeting a user-supplied URL without destination validation.',
    remediation: 'Validate destination URLs against an explicit domain allowlist and block private IP ranges (127.0.0.1, 10.0.0.0/8, 169.254.169.254).'
  },
  {
    id: 'WIDE-SEC-005',
    cwe: 'CWE-22',
    category: 'Path Traversal',
    severity: 'HIGH',
    languages: ['js', 'ts', 'py', 'php', 'java', 'go'],
    pattern: /(?:readFile|readFileSync|createReadStream|open|file_get_contents|readfile|FileInputStream)\s*\(\s*(?:.*?path\.join.*?req\.|.*?\+\s*(?:req\.|params|query|\$_)|f['"].*?\{request)/i,
    message: 'File system access with untrusted path concatenation vulnerable to directory traversal.',
    remediation: 'Resolve the path with path.resolve() and verify that it starts with the intended base directory.'
  },
  {
    id: 'WIDE-SEC-006',
    cwe: 'CWE-502',
    category: 'Insecure Deserialization',
    severity: 'CRITICAL',
    languages: ['js', 'ts', 'py', 'php', 'java'],
    pattern: /(?:pickle\.loads|yaml\.load\([^,)]+\)|unserialize\s*\(|node-serialize|serialize\.unserialize|XMLDecoder|ObjectInputStream)/i,
    message: 'Untrusted deserialization can lead to arbitrary code execution.',
    remediation: 'Never deserialize untrusted input with unsafe serializers. Use JSON.parse, safe_load in PyYAML, or HMAC verification.'
  },
  {
    id: 'WIDE-SEC-007',
    cwe: 'CWE-611',
    category: 'XML External Entity (XXE)',
    severity: 'HIGH',
    languages: ['js', 'ts', 'py', 'php', 'java'],
    pattern: /(?:xml2js|DOMParser|SimpleXMLElement|libxml_disable_entity_loader\s*\(\s*false|DocumentBuilderFactory.*?setFeature.*?external-general-entities.*?true)/i,
    message: 'XML parser configured without disabling external entity resolution.',
    remediation: 'Disable external DTDs and external entity expansion (e.g. setFeature(\'http://apache.org/xml/features/disallow-doctype-decl\', true)).'
  },
  {
    id: 'WIDE-SEC-008',
    cwe: 'CWE-798',
    category: 'Hardcoded Secret',
    severity: 'HIGH',
    languages: ['all'],
    pattern: /(?:(?:api_?key|secret|password|access_?token|jwt_?secret|private_?key)\s*[:=]\s*['"][a-zA-Z0-9_\-\.]{16,}['"]|AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36}|AIza[0-9A-Za-z\-_]{35})/i,
    message: 'High-entropy API token, private key, or credential hardcoded in source.',
    remediation: 'Extract secrets to environment variables or an external secret manager (AWS Secrets Manager, Vault).'
  },
  {
    id: 'WIDE-SEC-009',
    cwe: 'CWE-327',
    category: 'Broken Cryptography',
    severity: 'MEDIUM',
    languages: ['js', 'ts', 'py', 'php', 'java', 'cs', 'go'],
    pattern: /(?:createHash\s*\(\s*['"](?:md5|sha1)['"]|hashlib\.(?:md5|sha1)|MD5\.Create|DES|RC4|crypto\.createCipheriv\s*\(\s*['"][^'"]*ecb)/i,
    message: 'Collision-prone or deprecated cryptographic algorithm (MD5/SHA1/DES/ECB mode).',
    remediation: 'Use SHA-256/SHA-512 for integrity, bcrypt/argon2 for passwords, and AES-256-GCM for symmetric encryption.'
  },
  {
    id: 'WIDE-SEC-010',
    cwe: 'CWE-94',
    category: 'Code Injection (eval)',
    severity: 'CRITICAL',
    languages: ['js', 'ts', 'py', 'php'],
    pattern: /(?:\beval\s*\(|new\s+Function\s*\(|setTimeout\s*\(\s*['"`]|setInterval\s*\(\s*['"`])/i,
    sourcePattern: /(?:req\.|params|query|input|\$_)/i,
    message: 'Dynamic code evaluation sink called with user-influenced string.',
    remediation: 'Remove eval and dynamic Function calls. Refactor logic to use structured mappings or data structures.'
  },
  {
    id: 'WIDE-SEC-011',
    cwe: 'CWE-1333',
    category: 'Regular Expression Denial of Service (ReDoS)',
    severity: 'MEDIUM',
    languages: ['js', 'ts', 'py', 'java'],
    pattern: /\/(?:[a-zA-Z0-9_]*\+)+[a-zA-Z0-9_]*\+/i,
    message: 'Catastrophic backtracking vulnerability detected in nested regex quantifier.',
    remediation: 'Refactor regex to eliminate overlapping nested repetitions, or enforce string length limits before matching.'
  },
  {
    id: 'WIDE-SEC-012',
    cwe: 'CWE-1321',
    category: 'Prototype Pollution',
    severity: 'HIGH',
    languages: ['js', 'ts'],
    pattern: /(?:__proto__|constructor\s*\[\s*['"]prototype['"]\]|Object\.assign\s*\(\s*\{\}\s*,\s*(?:req\.|body|params)|merge\s*\([^,]+,\s*(?:req\.|body))/i,
    message: 'Potential prototype pollution via unsafe recursive object merging.',
    remediation: 'Validate keys against \'__proto__\' and \'constructor\', or use Object.create(null) for unpolluted dictionaries.'
  },
  {
    id: 'WIDE-SEC-013',
    cwe: 'CWE-943',
    category: 'NoSQL Injection',
    severity: 'CRITICAL',
    languages: ['js', 'ts', 'py'],
    pattern: /(?:\.find|\.findOne|\.deleteMany|\.updateMany)\s*\(\s*(?:req\.(?:body|query|params)|\{[^}]*\$(?:where|ne|gt|regex))/i,
    message: 'NoSQL query structure accepts raw user object without type coercion.',
    remediation: 'Enforce strict schema validation and sanitize inputs so operator objects ($gt, $where) cannot be injected.'
  },
  {
    id: 'WIDE-SEC-014',
    cwe: 'CWE-601',
    category: 'Open Redirect',
    severity: 'MEDIUM',
    languages: ['js', 'ts', 'py', 'php'],
    pattern: /(?:res\.redirect|redirect|header\s*\(\s*['"]Location:)\s*\(\s*(?:req\.|params|query|request\.)/i,
    message: 'HTTP redirection destination is controlled by untrusted request parameter.',
    remediation: 'Use relative redirect paths or validate destinations against a strict allowlist of authorized hostnames.'
  },
  {
    id: 'WIDE-SEC-015',
    cwe: 'CWE-384',
    category: 'Session Fixation',
    severity: 'MEDIUM',
    languages: ['js', 'ts', 'py', 'php'],
    pattern: /(?:session\.regenerate|session_regenerate_id)\s*===?\s*false|req\.session\.regenerate\s*\(\s*function\s*\(\)\s*\{\s*\}\s*\)/i,
    message: 'Session identifier not refreshed upon privilege escalation or authentication.',
    remediation: 'Always regenerate session identifiers upon login using req.session.regenerate() or session_regenerate_id(true).'
  },
  {
    id: 'WIDE-SEC-016',
    cwe: 'CWE-639',
    category: 'Insecure Direct Object Reference (IDOR)',
    severity: 'HIGH',
    languages: ['js', 'ts', 'py', 'php', 'java'],
    pattern: /(?:findById|findByPk|findOne|SELECT.*?WHERE id =)\s*\(\s*req\.params\.id\s*\)(?!.*?(?:userId|ownerId|user\._?id|req\.user))/i,
    message: 'Database record queried strictly by client-supplied ID without verifying ownership.',
    remediation: 'Always scope database queries to the authenticated user ID (e.g. { id: req.params.id, userId: req.user.id }).'
  },
  {
    id: 'WIDE-SEC-017',
    cwe: 'CWE-942',
    category: 'CORS Misconfiguration',
    severity: 'MEDIUM',
    languages: ['js', 'ts', 'py', 'php'],
    pattern: /(?:Access-Control-Allow-Origin.*?['"]\*['"].*?Access-Control-Allow-Credentials.*?['"]true['"]|cors\s*\(\s*\{\s*origin:\s*true\s*,\s*credentials:\s*true)/i,
    message: 'Wildcard CORS origin allowed in conjunction with credential sharing.',
    remediation: 'Never combine Access-Control-Allow-Credentials: true with a wildcard or dynamically reflected origin.'
  },
  {
    id: 'WIDE-SEC-018',
    cwe: 'CWE-352',
    category: 'Cross-Site Request Forgery (CSRF)',
    severity: 'MEDIUM',
    languages: ['js', 'ts', 'py', 'php'],
    pattern: /(?:app\.(?:post|put|delete|patch)\s*\([^,]+,\s*(?!.*?csrf).*?\bfunction\b|csrfProtection.*?enabled:\s*false)/i,
    message: 'State-changing HTTP route registered without apparent CSRF token protection.',
    remediation: 'Enable SameSite=Lax/Strict cookie attributes and use CSRF tokens (csurf or double-submit cookie pattern).'
  },
  {
    id: 'WIDE-SEC-019',
    cwe: 'CWE-330',
    category: 'Weak Randomness',
    severity: 'LOW',
    languages: ['js', 'ts', 'py', 'php', 'java'],
    pattern: /(?:Math\.random|random\.random|rand\(|mt_rand)\s*\(\s*\).*?(?:token|secret|session|key|nonce|auth|otp)/i,
    message: 'Pseudorandom number generator used for security-sensitive token generation.',
    remediation: 'Use cryptographically secure random number generators (crypto.randomBytes() or secrets.token_hex()).'
  },
  {
    id: 'WIDE-SEC-020',
    cwe: 'CWE-209',
    category: 'Information Leakage',
    severity: 'LOW',
    languages: ['js', 'ts', 'py', 'php', 'java'],
    pattern: /(?:res\.(?:send|json)\s*\(\s*(?:err\.stack|err\.message|error\.stack)|printStackTrace\s*\(\)|ini_set\s*\(\s*['"]display_errors['"]\s*,\s*['"]1['"]\))/i,
    message: 'Detailed internal error stack trace or debug information exposed to client.',
    remediation: 'Log stack traces internally and return generic error responses with error correlation IDs to clients.'
  }
];

export const DEFAULT_AGENT_RULES: readonly SecurityRule[] = [
  {
    id: 'wide/ai-no-emojis',
    cwe: 'N/A',
    category: 'AI_SECURITY',
    severity: 'HIGH',
    languages: ['all'],
    pattern: /(?:[\uD800-\uDBFF][\uDC00-\uDFFF]|[\u2600-\u27BF])/,
    message: 'AI agents must not use emojis or emoticons under any circumstances.',
    remediation: 'Strip all emojis from text and outputs, preserving clean technical prose.',
    instruction: 'Do not use emojis anywhere in your responses or generated code. Never output emojis under any circumstances.'
  },
  {
    id: 'wide/cwe078-ai-unsafe-tool-exec',
    cwe: 'CWE-78',
    category: 'AI_SECURITY',
    severity: 'CRITICAL',
    languages: ['js', 'jsx', 'ts', 'tsx', 'py', 'mjs', 'cjs'],
    pattern: /\b(?:exec|execSync|spawn|subprocess\.run|os\.system)\s*\(\s*(?:toolCall|tool_call|args|arguments|response\.command|patch\.command)/i,
    message: 'Executing raw system command directly from AI tool call response without argument validation.',
    remediation: 'Whitelist allowed commands and run them in an isolated sandbox with fixed arguments.',
    instruction: 'Never execute raw system commands directly from AI tool call responses without argument validation.'
  },
  {
    id: 'wide/cwe079-ai-prompt-injection',
    cwe: 'CWE-79',
    category: 'AI_SECURITY',
    severity: 'HIGH',
    languages: ['js', 'jsx', 'ts', 'tsx', 'py', 'mjs', 'cjs'],
    pattern: /\b(?:prompt|instruction|query|input)\s*[:=]\s*(?:f?["'].*?\{|`.*?$\{).*(?:req\.|params\.|body\.|userInput|user_input|request\.)/i,
    message: 'Untrusted user input concatenated directly into LLM prompt template without sanitization.',
    remediation: 'Use structured multi-turn message roles or sanitize prompt inputs before sending to the model.',
    instruction: 'Always validate and sanitize untrusted user input before incorporating into prompt templates.'
  },
  {
    id: 'wide/cwe095-ai-unconstrained-eval',
    cwe: 'CWE-95',
    category: 'AI_SECURITY',
    severity: 'CRITICAL',
    languages: ['js', 'jsx', 'ts', 'tsx', 'py', 'mjs', 'cjs'],
    pattern: /\b(?:eval|Function|vm\.runInContext|compile)\s*\(\s*(?:toolOutput|tool_output|response\.text|aiResult|ai_output|completion)/i,
    message: 'Evaluating raw executable code returned by LLM without sandboxing or static verification.',
    remediation: 'Parse responses into structured abstract syntax trees or validate against a strict AST schema before execution.',
    instruction: 'Never evaluate raw executable code dynamically without AST schema validation or sandboxing.'
  },
  {
    id: 'wide/cwe306-ai-unauthenticated-mcp-registration',
    cwe: 'CWE-306',
    category: 'AI_SECURITY',
    severity: 'HIGH',
    languages: ['js', 'jsx', 'ts', 'tsx', 'py', 'mjs', 'cjs'],
    pattern: /\b(?:registerMcpServer|addMcpServer|mcpClient\.connect)\s*\(\s*(?:url|endpoint|serverConfig)\s*\)/i,
    message: 'Model Context Protocol server registered without identity verification or authorization signature.',
    remediation: 'Verify server host authorization and enforce cryptographic signature checks prior to registering external toolsets.',
    instruction: 'Never register external toolsets or MCP servers without authentication and user authorization.'
  },
  {
    id: 'wide/cwe400-ai-unbounded-agent-loop',
    cwe: 'CWE-400',
    category: 'AI_SECURITY',
    severity: 'MEDIUM',
    languages: ['js', 'jsx', 'ts', 'tsx', 'py', 'mjs', 'cjs'],
    pattern: /while\s*\(\s*(?:true|1|!done|!finished|!settled)\s*\)\s*\{(?![^}]*\b(?:maxRounds|maxSteps|maxIterations|round\s*>=|step\s*>=)\b)/i,
    message: 'Autonomous agent execution loop lacks explicit termination boundary or maximum step limit.',
    remediation: 'Enforce a strict step threshold or cancellation budget to prevent runaway agent execution loops.',
    instruction: 'Always respect maximum step thresholds and loop termination boundaries.'
  },
  {
    id: 'wide/cwe770-ai-unbounded-context-accumulation',
    cwe: 'CWE-770',
    category: 'AI_SECURITY',
    severity: 'MEDIUM',
    languages: ['js', 'jsx', 'ts', 'tsx', 'py', 'mjs', 'cjs'],
    pattern: /\b(?:history|messages|chatContext)\.push\s*\(.*?\)(?![^;]*(?:slice|shift|trim|truncate|maxTokens|maxHistory))/i,
    message: 'LLM conversation context accumulates without token limits or sliding window truncation.',
    remediation: 'Prune chat context using sliding window truncation or token counting before appending turns.',
    instruction: 'Maintain concise conversation context and avoid unbounded accumulation.'
  },
  {
    id: 'wide/cwe798-ai-prompt-secret-leak',
    cwe: 'CWE-798',
    category: 'AI_SECURITY',
    severity: 'HIGH',
    languages: ['js', 'jsx', 'ts', 'tsx', 'py', 'mjs', 'cjs'],
    pattern: /\b(?:systemPrompt|systemMessage|system_prompt)\s*[:=].*?(?:process\.env\.(?:[A-Z_]*(?:KEY|SECRET|TOKEN|PASSWORD|PASS|AUTH))|apiKey|api_key|secret)/i,
    message: 'Sensitive secrets or private API credentials embedded in prompt context.',
    remediation: 'Strip private credentials from prompt text and provide secrets through isolated backend proxy channels.',
    instruction: 'Never include secrets, API keys, private tokens, or credentials in prompt context or output.'
  },
  {
    id: 'wide/cwe829-ai-unvalidated-patch-apply',
    cwe: 'CWE-829',
    category: 'AI_SECURITY',
    severity: 'HIGH',
    languages: ['js', 'jsx', 'ts', 'tsx', 'py', 'mjs', 'cjs'],
    pattern: /\b(?:applyPatch|gitApply|applyDiff|writePatch)\s*\(\s*(?:aiPatch|llmResponse|output\.patch|modelDiff)/i,
    message: 'Applying LLM-generated patch directly to codebase without path traversal or integrity checks.',
    remediation: 'Validate destination file paths are strictly within workspace bounds and run static scans before applying patches.',
    instruction: 'Always inspect relevant files before modifying them, validate bounds, and verify patch integrity.'
  }
];
