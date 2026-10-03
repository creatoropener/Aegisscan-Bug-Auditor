import { SecurityAuditReport, PreloadedDemoScenario } from '../types/security.js';

export const DEMO_SCENARIOS: PreloadedDemoScenario[] = [
  {
    id: 'demo-ecommerce-vulnerable',
    name: 'Vulnerable E-Commerce Portal',
    target: 'https://staging-shop.mockapp.internal',
    type: 'SITE_URL',
    description: 'Simulates a typical production web store with critical missing security headers, exposed admin endpoints in robots.txt, and unhardened cookies.',
    simulatedGrade: 'F',
    tag: 'Web DAST',
  },
  {
    id: 'demo-fintech-api',
    name: 'FinTech Backend & Payment Service',
    target: 'payment-processor.ts',
    type: 'SOURCE_CODE',
    description: 'Code sample containing hardcoded Stripe keys, raw SQL queries, MD5 password hashing, and unvalidated file reads.',
    simulatedGrade: 'F',
    tag: 'Code SAST',
  },
  {
    id: 'demo-hardened-enterprise',
    name: 'Hardened Production SaaS (A+ Benchmark)',
    target: 'https://cloud-vault.enterprise.io',
    type: 'SITE_URL',
    description: 'A fully hardened application implementing strict HSTS preload, nonce-based CSP, isolated COOP/COEP, and strict SameSite cookies.',
    simulatedGrade: 'A+',
    tag: 'Compliant Baseline',
  },
];

export const DEMO_CODE_SNIPPETS: Record<string, { filename: string; code: string }> = {
  vulnerable_api: {
    filename: 'src/api/userController.ts',
    code: `import express from 'express';
import { Pool } from 'pg';
import crypto from 'crypto';

const app = express();
const db = new Pool({ connectionString: 'postgres://admin:SuperSecret2026!@db.internal:5432/production' });

// AWS credentials for receipt bucket storage
const AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";
const STRIPE_SECRET = "sk_live_51M0abcdef1234567890abcdef";

app.get('/api/users/search', async (req, res) => {
  const searchTerm = req.query.q;
  // Vulnerability: Raw SQL injection
  const query = "SELECT id, username, email FROM users WHERE username = '" + searchTerm + "'";
  const result = await db.query(query);
  res.json(result.rows);
});

app.post('/api/user/render-bio', (req, res) => {
  const bioMarkdown = req.body.bio;
  // Vulnerability: Dangerous code execution
  const compiled = eval("transformMarkdown('" + bioMarkdown + "')");
  res.send({ rendered: compiled });
});

app.get('/api/download-receipt', (req, res) => {
  // Vulnerability: Path traversal
  const receiptPath = req.query.file as string;
  res.sendFile(receiptPath);
});

app.post('/api/generate-token', (req, res) => {
  // Vulnerability: Weak cryptographic random and broken MD5 hash
  const pseudoToken = Math.random().toString(36).substring(2);
  const hashed = crypto.createHash('md5').update(pseudoToken).digest('hex');
  res.json({ token: hashed });
});

export default app;`,
  },
  package_manifest: {
    filename: 'package.json',
    code: `{
  "name": "legacy-microservice",
  "version": "1.4.2",
  "dependencies": {
    "express": "^4.18.2",
    "lodash": "4.17.15",
    "axios": "0.19.2",
    "jsonwebtoken": "8.5.1",
    "moment": "2.24.0",
    "pg": "^8.11.3"
  }
}`,
  },
};

export const MOCK_REPORTS: Record<string, SecurityAuditReport> = {
  'demo-ecommerce-vulnerable': {
    id: 'DEMO-ECOM-001',
    target: 'https://staging-shop.mockapp.internal',
    targetType: 'SITE_URL',
    timestamp: new Date().toISOString(),
    scanDurationMs: 642,
    scorecard: {
      grade: 'F',
      numericScore: 32,
      criticalCount: 1,
      highCount: 3,
      mediumCount: 2,
      lowCount: 3,
      infoCount: 1,
      totalFindings: 10,
      passedChecksCount: 2,
    },
    metadata: {
      serverBanner: 'nginx/1.18.0 (Ubuntu)',
      statusCode: 200,
      redirectChain: ['http://staging-shop.mockapp.internal', 'https://staging-shop.mockapp.internal'],
      securityTxtFound: false,
      robotsTxtFound: true,
      headersCount: 14,
    },
    executiveSummary: 'Critical security posture alert for https://staging-shop.mockapp.internal. The target exhibits high risk of Cross-Site Scripting (missing CSP), Clickjacking vulnerability, session cookie leakage, and server technology disclosures.',
    findings: [
      {
        id: 'FIND-CSP-01',
        title: 'Missing Content-Security-Policy (CSP) Header',
        category: 'Browser Defense',
        owaspCategory: 'A03:2021 - Injection',
        cweId: 'CWE-1021',
        severity: 'HIGH',
        cvssScore: 8.2,
        description: 'No Content-Security-Policy was received in response headers. Modern browsers cannot prevent malicious inline scripts, unauthorized eval(), or external credential exfiltration scripts from running.',
        impact: 'Facilitates high-impact Cross-Site Scripting (XSS) and DOM data injection.',
        observedEvidence: 'Header "Content-Security-Policy" is absent.',
        recommendedFix: 'Configure a restrictive Content-Security-Policy with default-src \'self\' and nonce-based script loading.',
        references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP'],
        status: 'OPEN',
        headerName: 'Content-Security-Policy',
        remediationSnippets: [
          {
            technology: 'Nginx',
            code: 'add_header Content-Security-Policy "default-src \'self\'; script-src \'self\'; style-src \'self\' \'unsafe-inline\'; object-src \'none\';" always;',
          },
        ],
      },
      {
        id: 'FIND-COOKIE-HTTPONLY-session_id',
        title: 'Session Cookie "session_id" Missing "HttpOnly" Flag',
        category: 'Cookie Hardening',
        owaspCategory: 'A07:2021 - Identification & Auth Failures',
        cweId: 'CWE-1004',
        severity: 'HIGH',
        cvssScore: 7.5,
        description: 'The core user session cookie "session_id" lacks the HttpOnly attribute, rendering it readable via document.cookie by any injected script.',
        impact: 'Direct session token theft and account takeover via client-side script execution.',
        observedEvidence: 'Set-Cookie: session_id=e7b44fa90a12; Path=/; Domain=mockapp.internal',
        recommendedFix: 'Set HttpOnly attribute on session_id cookie creation.',
        references: ['https://owasp.org/www-community/HttpOnly'],
        status: 'OPEN',
      },
      {
        id: 'FIND-CLICKJACK-01',
        title: 'Missing Clickjacking Protection (X-Frame-Options)',
        category: 'Browser Defense',
        owaspCategory: 'A05:2021 - Security Misconfiguration',
        cweId: 'CWE-1021',
        severity: 'MEDIUM',
        cvssScore: 5.4,
        description: 'The website allows unrestricted framing by third-party origins. Attackers can embed checkout and profile alteration pages into invisible iframes to trick users.',
        impact: 'UI redressing and involuntary user transactions.',
        observedEvidence: 'X-Frame-Options header not present.',
        recommendedFix: 'Add "X-Frame-Options: DENY" or "X-Frame-Options: SAMEORIGIN".',
        references: ['https://cwe.mitre.org/data/definitions/1021.html'],
        status: 'OPEN',
        headerName: 'X-Frame-Options',
      },
      {
        id: 'FIND-HSTS-01',
        title: 'Missing HTTP Strict-Transport-Security (HSTS) Header',
        category: 'Transport Security',
        owaspCategory: 'A05:2021 - Security Misconfiguration',
        cweId: 'CWE-523',
        severity: 'HIGH',
        cvssScore: 7.5,
        description: 'HTTP Strict-Transport-Security header was not detected.',
        impact: 'Allows man-in-the-middle downgrade attacks to unencrypted HTTP.',
        observedEvidence: 'Header absent.',
        recommendedFix: 'Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
        references: ['https://hstspreload.org/'],
        status: 'OPEN',
        headerName: 'Strict-Transport-Security',
      },
      {
        id: 'FIND-ROBOTS-LEAK',
        title: 'Sensitive Admin Routes Disclosed in robots.txt',
        category: 'Information Leakage',
        owaspCategory: 'A01:2021 - Broken Access Control',
        cweId: 'CWE-200',
        severity: 'LOW',
        cvssScore: 3.5,
        description: 'robots.txt lists sensitive routes: /admin-console-v2, /backup-db, /staging-login.',
        impact: 'Unintentional reconnaissance disclosure of restricted portals.',
        observedEvidence: 'Disallow: /admin-console-v2, /backup-db',
        recommendedFix: 'Remove internal endpoint names from public robots.txt and enforce IP whitelisting or SSO authentication.',
        references: ['https://owasp.org/'],
        status: 'OPEN',
      },
      {
        id: 'FIND-INFO-01',
        title: 'Server & Tech-Stack Version Disclosure',
        category: 'Information Leakage',
        owaspCategory: 'A05:2021 - Security Misconfiguration',
        cweId: 'CWE-200',
        severity: 'LOW',
        cvssScore: 3.5,
        description: 'Server banner reveals "nginx/1.18.0 (Ubuntu)".',
        impact: 'Helps attackers target known Ubuntu/nginx package vulnerabilities.',
        observedEvidence: 'Server: nginx/1.18.0 (Ubuntu)',
        recommendedFix: 'Set server_tokens off in nginx.conf.',
        references: ['https://cwe.mitre.org/data/definitions/200.html'],
        status: 'OPEN',
      },
    ],
  },
  'demo-hardened-enterprise': {
    id: 'DEMO-HARDENED-001',
    target: 'https://cloud-vault.enterprise.io',
    targetType: 'SITE_URL',
    timestamp: new Date().toISOString(),
    scanDurationMs: 412,
    scorecard: {
      grade: 'A+',
      numericScore: 98,
      criticalCount: 0,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
      infoCount: 1,
      totalFindings: 1,
      passedChecksCount: 14,
    },
    metadata: {
      serverBanner: 'CloudFront',
      statusCode: 200,
      securityTxtFound: true,
      robotsTxtFound: true,
      headersCount: 22,
    },
    executiveSummary: 'Exemplary security posture benchmark for https://cloud-vault.enterprise.io. Implements zero-trust browser isolation, strict HSTS preload, strict nonce-based CSP, and verified RFC 9116 security disclosure policies.',
    findings: [
      {
        id: 'FIND-INFO-ROBOTS-OK',
        title: 'Security Posture Verified: All Essential Defensive Controls Active',
        category: 'Compliance Benchmark',
        owaspCategory: 'A05:2021 - Security Misconfiguration',
        cweId: 'CWE-16',
        severity: 'INFO',
        cvssScore: 0.0,
        description: 'Target achieves maximum grade. HSTS, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy are correctly implemented.',
        impact: 'Robust defense-in-depth across client browser surface.',
        observedEvidence: 'All 14 baseline defensive controls returned passing status.',
        recommendedFix: 'Maintain routine automated scanning in CI/CD pipeline.',
        references: ['https://owasp.org/'],
        status: 'FIXED',
      },
    ],
  },
};
