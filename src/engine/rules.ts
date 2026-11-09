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
    remediation: 'Validate destination URLs against an explicit domain allowlist and block private IP ranges.'
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
    remediation: 'Never deserialize untrusted input with unsafe serializers. Use JSON.parse or safe_load in PyYAML.'
  },
  {
    id: 'WIDE-SEC-007',
    cwe: 'CWE-611',
    category: 'XML External Entity (XXE)',
    severity: 'HIGH',
    languages: ['js', 'ts', 'py', 'php', 'java'],
    pattern: /(?:xml2js|DOMParser|SimpleXMLElement|libxml_disable_entity_loader\s*\(\s*false|DocumentBuilderFactory.*?setFeature.*?external-general-entities.*?true)/i,
    message: 'XML parser configured without disabling external entity resolution.',
    remediation: 'Disable external DTDs and external entity expansion.'
  },
  {
    id: 'WIDE-SEC-008',
    cwe: 'CWE-798',
    category: 'Hardcoded Secret',
    severity: 'HIGH',
    languages: ['all'],
    pattern: /(?:(?:api_?key|secret|password|access_?token|jwt_?secret|private_?key)\s*[:=]\s*['"][a-zA-Z0-9_\-\.]{16,}['"]|AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36}|AIza[0-9A-Za-z\-_]{35})/i,
    message: 'High-entropy API token, private key, or credential hardcoded in source.',
    remediation: 'Extract secrets to environment variables or an external secret manager.'
  },
  {
    id: 'WIDE-SEC-009',
    cwe: 'CWE-327',
    category: 'Broken Cryptography',
    severity: 'MEDIUM',
    languages: ['js', 'ts', 'py', 'php', 'java', 'cs', 'go'],
    pattern: /(?:createHash\s*\(\s*['"](?:md5|sha1)['"]|hashlib\.(?:md5|sha1)|MD5\.Create|DES|RC4|crypto\.createCipheriv\s*\(\s*['"][^'"]*ecb)/i,
    message: 'Collision-prone or deprecated cryptographic algorithm (MD5/SHA1/DES/ECB mode).',
    remediation: 'Use SHA-256 or SHA-512 for integrity, bcrypt/argon2 for passwords, and AES-256-GCM for encryption.'
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
    remediation: 'Validate keys against __proto__ and constructor, or use Object.create(null).'
  },
  {
    id: 'WIDE-SEC-013',
    cwe: 'CWE-943',
    category: 'NoSQL Injection',
    severity: 'CRITICAL',
    languages: ['js', 'ts', 'py'],
    pattern: /(?:\.find|\.findOne|\.deleteMany|\.updateMany)\s*\(\s*(?:req\.(?:body|query|params)|\{[^}]*\$(?:where|ne|gt|regex))/i,
    message: 'NoSQL query structure accepts raw user object without type coercion.',
    remediation: 'Enforce strict schema validation and sanitize inputs so operator objects cannot be injected.'
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
    remediation: 'Enable SameSite cookies and use CSRF tokens (csurf or double-submit cookie pattern).'
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
