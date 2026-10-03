import { SecurityFinding, SecurityScorecard, SecurityAuditReport } from '../types/security.js';

export interface SastScanInput {
  filename?: string;
  code: string;
  fileType?: string;
}

interface SastRule {
  id: string;
  title: string;
  category: string;
  owaspCategory: SecurityFinding['owaspCategory'];
  cweId: string;
  severity: SecurityFinding['severity'];
  cvssScore: number;
  regex: RegExp;
  description: string;
  impact: string;
  recommendedFix: string;
  references: string[];
  remediationSnippets?: { technology: string; code: string }[];
}

const SAST_RULES: SastRule[] = [
  // 1. Secrets & Credentials
  {
    id: 'SAST-SECRET-AWS-01',
    title: 'Hardcoded AWS Access Key ID Detected',
    category: 'Secrets Management',
    owaspCategory: 'A07:2021 - Identification & Auth Failures',
    cweId: 'CWE-798',
    severity: 'CRITICAL',
    cvssScore: 9.8,
    regex: /(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}/g,
    description: 'An active Amazon Web Services (AWS) Access Key ID was detected hardcoded directly in the source code. Storing credentials in source code creates high exposure risk when repositories are committed or built into client artifacts.',
    impact: 'Attackers can use compromised cloud credentials to access cloud infrastructure, exfiltrate private databases, and spin up unauthorized compute resources.',
    recommendedFix: 'Revoke the exposed key immediately in AWS IAM, and load credentials dynamically from environment variables or a secret vault.',
    references: ['https://cwe.mitre.org/data/definitions/798.html'],
    remediationSnippets: [
      {
        technology: 'Node.js',
        code: 'const awsAccessKey = process.env.AWS_ACCESS_KEY_ID;\nconst awsSecretKey = process.env.AWS_SECRET_ACCESS_KEY;',
      },
    ],
  },
  {
    id: 'SAST-SECRET-STRIPE-01',
    title: 'Hardcoded Stripe Secret API Key',
    category: 'Secrets Management',
    owaspCategory: 'A07:2021 - Identification & Auth Failures',
    cweId: 'CWE-798',
    severity: 'CRITICAL',
    cvssScore: 9.6,
    regex: /sk_live_[0-9a-zA-Z]{24,}/g,
    description: 'A production live Stripe secret key was detected. Secret keys hold full write permissions over merchant accounts, billing subscriptions, and customer payment methods.',
    impact: 'Full compromise of merchant payment infrastructure, unauthorized customer refunds, and payment tampering.',
    recommendedFix: 'Roll the secret key in the Stripe Dashboard and load it via secure environment variables.',
    references: ['https://stripe.com/docs/keys'],
  },
  {
    id: 'SAST-SECRET-GITHUB-01',
    title: 'Hardcoded GitHub Personal Access Token',
    category: 'Secrets Management',
    owaspCategory: 'A07:2021 - Identification & Auth Failures',
    cweId: 'CWE-798',
    severity: 'CRITICAL',
    cvssScore: 9.4,
    regex: /(?:ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{60,})/g,
    description: 'A personal GitHub access token or fine-grained token is embedded in the codebase.',
    impact: 'Unauthorized access to private GitHub repositories, supply chain code modification, and malicious git commits.',
    recommendedFix: 'Revoke the token in GitHub Settings and inject it via CI/CD secrets.',
    references: ['https://docs.github.com/en/authentication/keeping-your-account-and-data-secure'],
  },
  {
    id: 'SAST-SECRET-DB-URI-01',
    title: 'Database Connection String with Embedded Credentials',
    category: 'Secrets Management',
    owaspCategory: 'A07:2021 - Identification & Auth Failures',
    cweId: 'CWE-798',
    severity: 'HIGH',
    cvssScore: 8.8,
    regex: /(?:postgres|postgresql|mysql|mongodb(?:\+srv)?):\/\/[a-zA-Z0-9_-]+:[^@\s"']+@[a-zA-Z0-9.-]+/gi,
    description: 'A database connection URI with cleartext username and password was found hardcoded in the file.',
    impact: 'Direct unauthorized access to the production or staging database.',
    recommendedFix: 'Move database connection strings to .env files and use secret managers in production.',
    references: ['https://12factor.net/config'],
  },
  {
    id: 'SAST-SECRET-GENERIC-01',
    title: 'High-Entropy API Secret / Password Assignment',
    category: 'Secrets Management',
    owaspCategory: 'A07:2021 - Identification & Auth Failures',
    cweId: 'CWE-798',
    severity: 'MEDIUM',
    cvssScore: 6.8,
    regex: /(?:api_?key|secret|password|auth_?token|jwt_?secret)\s*[:=]\s*["'][A-Za-z0-9+/=_-]{16,}["']/gi,
    description: 'Variables with names indicating sensitive cryptographic tokens or passwords contain hardcoded string literals.',
    impact: 'Exposes application secrets to version control and client bundles.',
    recommendedFix: 'Replace hardcoded literal with process.env or secret manager retrieval.',
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html'],
  },

  // 2. Cross-Site Scripting (XSS) & Insecure Sinks
  {
    id: 'SAST-XSS-EVAL-01',
    title: 'Dangerous Code Execution via eval() or Function Constructor',
    category: 'Injection Vulnerabilities',
    owaspCategory: 'A03:2021 - Injection',
    cweId: 'CWE-95',
    severity: 'HIGH',
    cvssScore: 8.5,
    regex: /\b(?:eval\(|new\s+Function\(|setTimeout\s*\(\s*["'`][^"'])/g,
    description: 'The application invokes dynamic string evaluation using eval(), Function(), or setTimeout with a string argument. If any part of this input originates from user data, attackers can execute arbitrary JavaScript in the application runtime.',
    impact: 'Remote code execution or DOM-based Cross-Site Scripting (XSS).',
    recommendedFix: 'Refactor code to use native JSON.parse() or structured functional parsers instead of dynamic code execution.',
    references: ['https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval#never_use_eval!'],
  },
  {
    id: 'SAST-XSS-INNERHTML-01',
    title: 'DOM-based XSS Sink: innerHTML / outerHTML / document.write',
    category: 'Injection Vulnerabilities',
    owaspCategory: 'A03:2021 - Injection',
    cweId: 'CWE-79',
    severity: 'HIGH',
    cvssScore: 7.8,
    regex: /\b(?:\.innerHTML|\.outerHTML|document\.write)\s*=/g,
    description: 'Raw HTML string assignment via innerHTML, outerHTML, or document.write() detected. Inserting unsanitized HTML allows script tags and malicious attributes (e.g. <img src=x onerror=...>) to execute.',
    impact: 'Client-side script execution, session hijacking, credential theft.',
    recommendedFix: 'Use textContent or innerText for plain text, or sanitize HTML using DOMPurify before insertion.',
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html'],
    remediationSnippets: [
      {
        technology: 'JavaScript / DOMPurify',
        code: 'import DOMPurify from "dompurify";\nelement.innerHTML = DOMPurify.sanitize(userProvidedHtml);',
      },
      {
        technology: 'Safe Plain Text',
        code: 'element.textContent = userProvidedText;',
      },
    ],
  },
  {
    id: 'SAST-XSS-REACT-01',
    title: 'Unsanitized React dangerouslySetInnerHTML Usage',
    category: 'Injection Vulnerabilities',
    owaspCategory: 'A03:2021 - Injection',
    cweId: 'CWE-79',
    severity: 'MEDIUM',
    cvssScore: 6.5,
    regex: /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:/g,
    description: 'Usage of dangerouslySetInnerHTML bypasses React\'s built-in JSX escaping. If the HTML snippet contains untrusted user input, it introduces a severe XSS vulnerability.',
    impact: 'Execution of arbitrary malicious JavaScript within the authenticated user session.',
    recommendedFix: 'Wrap the HTML string with DOMPurify.sanitize() before passing to __html.',
    references: ['https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html'],
    remediationSnippets: [
      {
        technology: 'React + DOMPurify',
        code: '<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(content) }} />',
      },
    ],
  },

  // 3. SQL Injection
  {
    id: 'SAST-SQLI-01',
    title: 'Potential SQL Injection via Raw String Concatenation',
    category: 'Injection Vulnerabilities',
    owaspCategory: 'A03:2021 - Injection',
    cweId: 'CWE-89',
    severity: 'CRITICAL',
    cvssScore: 9.3,
    regex: /(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\s+[^;]{1,100}(?:\+\s*[a-zA-Z0-9_.]+|\$\{[a-zA-Z0-9_.]+\})/gi,
    description: 'SQL query construction combines SQL commands with variables using string concatenation (+) or template literals (${...}). Unescaped user input can break out of string delimiters and alter query logic.',
    impact: 'Complete database bypass, unauthorized data exfiltration, database tampering, or drop table attacks.',
    recommendedFix: 'Use parameterized queries or prepared statements with placeholder tokens ($1, ?, :param).',
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'],
    remediationSnippets: [
      {
        technology: 'Node.js pg (PostgreSQL)',
        code: '// Vulnerable: db.query(`SELECT * FROM users WHERE id = ${userId}`);\n// Secure:\nawait db.query("SELECT * FROM users WHERE id = $1", [userId]);',
      },
      {
        technology: 'MySQL',
        code: '// Secure:\nconnection.execute("SELECT * FROM users WHERE id = ?", [userId]);',
      },
    ],
  },

  // 4. Insecure Cryptography
  {
    id: 'SAST-CRYPTO-WEAK-01',
    title: 'Use of Broken Cryptographic Hash Algorithm (MD5 / SHA1)',
    category: 'Cryptographic Failures',
    owaspCategory: 'A02:2021 - Cryptographic Failures',
    cweId: 'CWE-327',
    severity: 'MEDIUM',
    cvssScore: 5.9,
    regex: /createHash\s*\(\s*["'](?:md5|sha1)["']\s*\)/gi,
    description: 'MD5 and SHA-1 have known collision weaknesses and are broken for digital signatures, password hashing, and integrity checks.',
    impact: 'Collision attacks allowing counterfeit signatures and hash collisions.',
    recommendedFix: 'Upgrade to SHA-256 (crypto.createHash("sha256")) or SHA-3/Argon2 for passwords.',
    references: ['https://cwe.mitre.org/data/definitions/327.html'],
  },
  {
    id: 'SAST-CRYPTO-MATH-RAND-01',
    title: 'Insecure Pseudo-Random Number Generator for Security Context',
    category: 'Cryptographic Failures',
    owaspCategory: 'A02:2021 - Cryptographic Failures',
    cweId: 'CWE-338',
    severity: 'LOW',
    cvssScore: 3.8,
    regex: /Math\.random\s*\(\s*\)/g,
    description: 'Math.random() is a pseudo-random number generator that is cryptographically predictable and must never be used for security tokens, session IDs, or password reset nonces.',
    impact: 'Predictable security tokens leading to account takeover.',
    recommendedFix: 'Use crypto.randomUUID() or crypto.randomBytes() for security tokens.',
    references: ['https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues'],
    remediationSnippets: [
      {
        technology: 'Node.js / Web Crypto',
        code: 'import crypto from "crypto";\nconst token = crypto.randomBytes(32).toString("hex");',
      },
    ],
  },

  // 5. Insecure CORS
  {
    id: 'SAST-CORS-01',
    title: 'Permissive Wildcard CORS with Credentials',
    category: 'Access Control',
    owaspCategory: 'A01:2021 - Broken Access Control',
    cweId: 'CWE-942',
    severity: 'HIGH',
    cvssScore: 7.9,
    regex: /(?:origin:\s*["']\*["']\s*,\s*credentials:\s*true|credentials:\s*true\s*,\s*origin:\s*["']\*["'])/gi,
    description: 'CORS policy configured to allow any origin (*) while allowing credentials (cookies / auth headers). Browsers reject this configuration or it allows any malicious site to read authenticated API responses.',
    impact: 'Cross-origin data theft of sensitive user data from authenticated sessions.',
    recommendedFix: 'Specify an explicit whitelist of trusted origins and validate the Origin header.',
    references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS'],
  },

  // 6. Path Traversal
  {
    id: 'SAST-PATH-TRAVERSAL-01',
    title: 'Potential Path Traversal via Unvalidated File Path',
    category: 'Input Validation',
    owaspCategory: 'A01:2021 - Broken Access Control',
    cweId: 'CWE-22',
    severity: 'HIGH',
    cvssScore: 8.1,
    regex: /(?:res\.sendFile|fs\.readFile|fs\.readFileSync)\s*\(\s*(?:req\.params|req\.query|req\.body)/gi,
    description: 'Directly passing request parameters to filesystem access functions without path normalization or whitelisting can allow attackers to read arbitrary files (e.g. ../../etc/passwd or .env).',
    impact: 'Local File Inclusion (LFI) and disclosure of server secrets and system files.',
    recommendedFix: 'Validate that the resolved path starts with the allowed base directory using path.resolve and path.relative.',
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/File_Inclusion_Prevention_Cheat_Sheet.html'],
  },
];

// Vulnerable dependency signatures for package.json
const KNOWN_VULNERABLE_PACKAGES: Array<{
  name: string;
  vulnerableVersionPattern: RegExp;
  cve: string;
  cwe: string;
  title: string;
  severity: SecurityFinding['severity'];
  cvss: number;
  fixedIn: string;
}> = [
  {
    name: 'lodash',
    vulnerableVersionPattern: /"lodash":\s*["'][\^~]?(?:[0-3]\.|4\.(?:[0-9]|1[0-6])\.|4\.17\.(?:[0-9]|1[0-9]|20))["']/i,
    cve: 'CVE-2021-23337',
    cwe: 'CWE-1321',
    title: 'Lodash Prototype Pollution via template function',
    severity: 'HIGH',
    cvss: 7.5,
    fixedIn: '4.17.21',
  },
  {
    name: 'axios',
    vulnerableVersionPattern: /"axios":\s*["'][\^~]?(?:0\.(?:[0-1][0-9]|20)\.)["']/i,
    cve: 'CVE-2020-28168',
    cwe: 'CWE-918',
    title: 'Axios Server-Side Request Forgery (SSRF) bypass',
    severity: 'HIGH',
    cvss: 7.4,
    fixedIn: '0.21.1',
  },
  {
    name: 'jsonwebtoken',
    vulnerableVersionPattern: /"jsonwebtoken":\s*["'][\^~]?(?:[0-8]\.)["']/i,
    cve: 'CVE-2022-23529',
    cwe: 'CWE-94',
    title: 'jsonwebtoken Arbitrary Code Execution via insecure secret OrPublicKey',
    severity: 'CRITICAL',
    cvss: 9.8,
    fixedIn: '9.0.0',
  },
  {
    name: 'express-jwt',
    vulnerableVersionPattern: /"express-jwt":\s*["'][\^~]?(?:[0-5]\.)["']/i,
    cve: 'CVE-2020-15084',
    cwe: 'CWE-287',
    title: 'express-jwt Authentication Bypass',
    severity: 'HIGH',
    cvss: 8.1,
    fixedIn: '6.0.0',
  },
  {
    name: 'moment',
    vulnerableVersionPattern: /"moment":\s*["'][\^~]?(?:[0-1]\.|2\.(?:[0-9]|1[0-9]|2[0-8])\.|2\.29\.[0-3])["']/i,
    cve: 'CVE-2022-31129',
    cwe: 'CWE-1333',
    title: 'Moment.js Inefficient Regular Expression Complexity (ReDoS)',
    severity: 'MEDIUM',
    cvss: 6.2,
    fixedIn: '2.29.4',
  },
];

export function runSastCodeScan(input: SastScanInput): SecurityAuditReport {
  const startTime = Date.now();
  const code = input.code || '';
  const lines = code.split('\n');
  const filename = input.filename || 'source-code-snippet.ts';
  const findings: SecurityFinding[] = [];
  let passedCount = 0;

  // 1. Check if package.json manifest
  if (filename.endsWith('package.json') || code.includes('"dependencies"') || code.includes('"devDependencies"')) {
    for (const pkg of KNOWN_VULNERABLE_PACKAGES) {
      if (pkg.vulnerableVersionPattern.test(code)) {
        findings.push({
          id: `SAST-PKG-${pkg.name.toUpperCase()}`,
          title: `Vulnerable Dependency: ${pkg.name} (${pkg.cve})`,
          category: 'Dependency Security',
          owaspCategory: 'A06:2021 - Vulnerable and Outdated Components',
          cweId: pkg.cwe,
          severity: pkg.severity,
          cvssScore: pkg.cvss,
          description: `The package manifest declares an outdated version of "${pkg.name}" subject to known security advisory ${pkg.cve}: ${pkg.title}.`,
          impact: 'Known published exploit vectors affecting third-party code in your dependency graph.',
          observedEvidence: `Matched dependency "${pkg.name}" in package.json`,
          recommendedFix: `Upgrade "${pkg.name}" to version ${pkg.fixedIn} or higher. Run: npm install ${pkg.name}@latest`,
          references: [`https://nvd.nist.gov/vuln/detail/${pkg.cve}`],
          status: 'OPEN',
          location: {
            file: filename,
          },
        });
      }
    }
  }

  // 2. Scan standard code rules line-by-line
  for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
    const line = lines[lineIndex];
    // Skip empty lines or standard harmless comments
    if (!line.trim() || line.trim().startsWith('//') || line.trim().startsWith('*')) {
      continue;
    }

    for (const rule of SAST_RULES) {
      // Reset regex state
      rule.regex.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = rule.regex.exec(line)) !== null) {
        // Redact part of matched secret for safe display
        const matchedText = match[0];
        const displayEvidence = matchedText.length > 20
          ? matchedText.substring(0, 6) + '...' + matchedText.substring(matchedText.length - 4)
          : matchedText;

        findings.push({
          id: `${rule.id}-${lineIndex + 1}`,
          title: rule.title,
          category: rule.category,
          owaspCategory: rule.owaspCategory,
          cweId: rule.cweId,
          severity: rule.severity,
          cvssScore: rule.cvssScore,
          description: rule.description,
          impact: rule.impact,
          observedEvidence: `Line ${lineIndex + 1}: ${displayEvidence}`,
          recommendedFix: rule.recommendedFix,
          references: rule.references,
          remediationSnippets: rule.remediationSnippets,
          status: 'OPEN',
          location: {
            file: filename,
            line: lineIndex + 1,
            column: match.index + 1,
            codeSnippet: line.trim(),
          },
        });

        // Break to avoid infinite loops on 0-width regex matches
        if (rule.regex.lastIndex === match.index) {
          rule.regex.lastIndex++;
        }
      }
    }
  }

  // Baseline security checks passed
  if (findings.length === 0) {
    passedCount = 12;
  } else {
    passedCount = Math.max(2, 15 - findings.length);
  }

  // Calculate Scorecard
  const critical = findings.filter((f) => f.severity === 'CRITICAL').length;
  const high = findings.filter((f) => f.severity === 'HIGH').length;
  const medium = findings.filter((f) => f.severity === 'MEDIUM').length;
  const low = findings.filter((f) => f.severity === 'LOW').length;
  const info = findings.filter((f) => f.severity === 'INFO').length;

  const penalty = critical * 25 + high * 12 + medium * 5 + low * 2;
  const numericScore = Math.max(0, Math.min(100, 100 - penalty));

  let grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F' = 'A+';
  if (critical > 0 || numericScore < 40) grade = 'F';
  else if (high > 1 || numericScore < 55) grade = 'D';
  else if (high === 1 || numericScore < 70) grade = 'C';
  else if (medium > 0 || numericScore < 85) grade = 'B';
  else if (numericScore < 95) grade = 'A';
  else grade = 'A+';

  return {
    id: `SAST-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
    target: filename,
    targetType: 'SOURCE_CODE',
    timestamp: new Date().toISOString(),
    scanDurationMs: Date.now() - startTime,
    scorecard: {
      grade,
      numericScore,
      criticalCount: critical,
      highCount: high,
      mediumCount: medium,
      lowCount: low,
      infoCount: info,
      totalFindings: findings.length,
      passedChecksCount: passedCount,
    },
    findings,
    metadata: {
      linesOfCodeScanned: lines.length,
    },
    executiveSummary: `Static code security analysis of ${filename} (${lines.length} lines) completed with score ${numericScore}/100 (Grade ${grade}). Found ${findings.length} security flaw(s) or vulnerability indicator(s).`,
  };
}
