import http from 'http';
import https from 'https';
import { URL } from 'url';
import { SecurityFinding, SecurityScorecard, SecurityAuditReport } from '../types/security.js';

export interface ScanOptions {
  checkRobots?: boolean;
  checkSecurityTxt?: boolean;
  deepHtml?: boolean;
}

interface FetchResult {
  statusCode: number;
  headers: Record<string, string | string[] | undefined>;
  body: string;
  finalUrl: string;
  redirects: string[];
  protocol: string;
  durationMs: number;
}

function fetchWithRedirects(targetUrl: string, maxRedirects = 4): Promise<FetchResult> {
  const startTime = Date.now();
  const redirects: string[] = [];

  return new Promise((resolve, reject) => {
    function execute(currentUrl: string, redirectCount: number) {
      let parsedUrl: URL;
      try {
        parsedUrl = new URL(currentUrl);
      } catch (err) {
        return reject(new Error(`Invalid URL: ${currentUrl}`));
      }

      const isHttps = parsedUrl.protocol === 'https:';
      const lib = isHttps ? https : http;

      const req = lib.request(
        parsedUrl,
        {
          method: 'GET',
          timeout: 8000,
          rejectUnauthorized: false, // Allows inspecting sites with self-signed or invalid certs for reporting
          headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 AegisScan-Auditor/1.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Cache-Control': 'no-cache',
          },
        },
        (res) => {
          // Handle redirects
          if (
            (res.statusCode === 301 || res.statusCode === 302 || res.statusCode === 307 || res.statusCode === 308) &&
            res.headers.location &&
            redirectCount < maxRedirects
          ) {
            const nextUrl = new URL(res.headers.location, currentUrl).toString();
            redirects.push(nextUrl);
            res.resume(); // discard body
            return execute(nextUrl, redirectCount + 1);
          }

          let data = '';
          res.setEncoding('utf8');
          // Limit body read to first 512KB for performance and safety
          res.on('data', (chunk) => {
            if (data.length < 524288) {
              data += chunk;
            }
          });

          res.on('end', () => {
            resolve({
              statusCode: res.statusCode || 0,
              headers: res.headers,
              body: data,
              finalUrl: currentUrl,
              redirects,
              protocol: parsedUrl.protocol,
              durationMs: Date.now() - startTime,
            });
          });
        }
      );

      req.on('timeout', () => {
        req.destroy();
        reject(new Error('Connection timed out after 8000ms.'));
      });

      req.on('error', (err) => {
        reject(err);
      });

      req.end();
    }

    execute(targetUrl, 0);
  });
}

export async function runDastSiteScan(rawUrl: string, options: ScanOptions = {}): Promise<SecurityAuditReport> {
  let targetUrl = rawUrl.trim();
  if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
    targetUrl = 'https://' + targetUrl;
  }

  const parsedTarget = new URL(targetUrl);
  const domain = parsedTarget.hostname;

  const fetchResult = await fetchWithRedirects(targetUrl);
  const headers = fetchResult.headers;
  const findings: SecurityFinding[] = [];
  let passedCount = 0;

  const getHeader = (name: string): string | undefined => {
    const val = headers[name.toLowerCase()];
    if (Array.isArray(val)) return val.join('; ');
    return val;
  };

  // 1. HTTPS / Transport Security
  const isHttps = fetchResult.protocol === 'https:';
  if (!isHttps) {
    findings.push({
      id: 'FIND-TRANS-01',
      title: 'Insecure Cleartext HTTP Protocol in Use',
      category: 'Transport Security',
      owaspCategory: 'A02:2021 - Cryptographic Failures',
      cweId: 'CWE-319',
      severity: 'CRITICAL',
      cvssScore: 9.1,
      description: 'The target website communicates over unencrypted HTTP. Data transferred between client and server (including authentication cookies, passwords, and personal data) is transmitted in cleartext and vulnerable to interception or man-in-the-middle (MITM) tampering.',
      impact: 'Eavesdropping, credential theft, and session hijacking by attackers on the same network or ISP transit.',
      observedEvidence: `Accessed endpoint: ${fetchResult.finalUrl} (Protocol: http:)`,
      recommendedFix: 'Enforce HTTPS everywhere with 301 permanent redirects to the TLS version and enable Strict-Transport-Security (HSTS).',
      references: ['https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html'],
      status: 'OPEN',
      remediationSnippets: [
        {
          technology: 'Nginx',
          code: 'server {\n    listen 80 default_server;\n    server_name _;\n    return 301 https://$host$request_uri;\n}',
        },
        {
          technology: 'Express.js',
          code: 'app.use((req, res, next) => {\n  if (req.header("x-forwarded-proto") !== "https" && process.env.NODE_ENV === "production") {\n    return res.redirect(`https://${req.header("host")}${req.url}`);\n  }\n  next();\n});',
        },
      ],
    });
  } else {
    passedCount++;
  }

  // 2. Strict-Transport-Security (HSTS)
  const hsts = getHeader('strict-transport-security');
  if (!hsts) {
    findings.push({
      id: 'FIND-HSTS-01',
      title: 'Missing HTTP Strict-Transport-Security (HSTS) Header',
      category: 'Transport Security',
      owaspCategory: 'A05:2021 - Security Misconfiguration',
      cweId: 'CWE-523',
      severity: 'HIGH',
      cvssScore: 7.5,
      description: 'The HTTP Strict-Transport-Security (HSTS) header informs user agents that all future requests must be sent exclusively over HTTPS, protecting users from SSL-stripping and downgrade attacks.',
      impact: 'Attackers can strip TLS connections using tools like sslstrip when a user first connects to the domain.',
      observedEvidence: 'Header "Strict-Transport-Security" was not present in the HTTP response.',
      recommendedFix: 'Add the Strict-Transport-Security header with a minimum max-age of 1 year (31536000 seconds), includeSubDomains, and preload.',
      references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security'],
      status: 'OPEN',
      headerName: 'Strict-Transport-Security',
      remediationSnippets: [
        {
          technology: 'Nginx',
          code: 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;',
        },
        {
          technology: 'Express.js (Helmet)',
          code: 'import helmet from "helmet";\napp.use(helmet.hsts({\n  maxAge: 31536000,\n  includeSubDomains: true,\n  preload: true\n}));',
        },
        {
          technology: 'Next.js (next.config.js)',
          code: 'module.exports = {\n  async headers() {\n    return [\n      {\n        source: "/(.*)",\n        headers: [\n          { key: "Strict-Transport-Security", value: "max-age=31536000; includeSubDomains; preload" }\n        ]\n      }\n    ];\n  }\n};',
        },
      ],
    });
  } else {
    const maxAgeMatch = hsts.match(/max-age=(\d+)/i);
    const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0;
    if (maxAge < 15552000) {
      findings.push({
        id: 'FIND-HSTS-02',
        title: 'HSTS max-age Duration Insufficient',
        category: 'Transport Security',
        owaspCategory: 'A05:2021 - Security Misconfiguration',
        cweId: 'CWE-523',
        severity: 'LOW',
        cvssScore: 3.1,
        description: `The HSTS max-age is set to ${maxAge} seconds (${Math.round(maxAge / 86400)} days). Production best practice recommends at least 6 months (15,552,000s) or 1 year (31,536,000s) for HSTS preload eligibility.`,
        impact: 'Browser cache expires quickly, leaving windows where downgrade attacks can succeed.',
        observedEvidence: `Strict-Transport-Security: ${hsts}`,
        recommendedFix: 'Increase max-age to 31536000 (1 year).',
        references: ['https://hstspreload.org/'],
        status: 'OPEN',
        headerName: 'Strict-Transport-Security',
        rawHeaderValue: hsts,
      });
    } else {
      passedCount++;
    }
  }

  // 3. Content-Security-Policy (CSP)
  const csp = getHeader('content-security-policy');
  if (!csp) {
    findings.push({
      id: 'FIND-CSP-01',
      title: 'Missing Content-Security-Policy (CSP) Header',
      category: 'Browser Defense',
      owaspCategory: 'A03:2021 - Injection',
      cweId: 'CWE-1021',
      severity: 'HIGH',
      cvssScore: 8.2,
      description: 'Content-Security-Policy (CSP) is an essential browser mitigation layer that restricts the resources (scripts, images, stylesheets, objects) the browser is allowed to load for a given page, drastically reducing the impact of Cross-Site Scripting (XSS) and data injection attacks.',
      impact: 'Without CSP, injected XSS payloads can freely execute, steal cookies, exfiltrate localStorage tokens, or load unauthorized external malicious scripts.',
      observedEvidence: 'Header "Content-Security-Policy" is absent.',
      recommendedFix: 'Implement a strict CSP restricting script execution, using nonces or hashes for scripts, and disallowing dangerous wildcards.',
      references: ['https://csp.withgoogle.com/', 'https://owasp.org/www-community/attacks/xss/'],
      status: 'OPEN',
      headerName: 'Content-Security-Policy',
      remediationSnippets: [
        {
          technology: 'Nginx',
          code: `add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'nonce-$request_id'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; object-src 'none'; base-uri 'self'; frame-ancestors 'none';" always;`,
        },
        {
          technology: 'Express.js (Helmet)',
          code: `import helmet from "helmet";\napp.use(helmet.contentSecurityPolicy({\n  directives: {\n    defaultSrc: ["'self'"],\n    scriptSrc: ["'self'"],\n    objectSrc: ["'none'"],\n    upgradeInsecureRequests: [],\n  }\n}));`,
        },
      ],
    });
  } else {
    // Check weak CSP directives
    const hasUnsafeInline = csp.includes("'unsafe-inline'") && !csp.includes("'nonce-") && !csp.includes("'sha256-");
    const hasUnsafeEval = csp.includes("'unsafe-eval'");
    const hasWildcardScript = csp.includes("script-src *") || (csp.includes("default-src *") && !csp.includes("script-src"));

    if (hasUnsafeInline || hasUnsafeEval || hasWildcardScript) {
      findings.push({
        id: 'FIND-CSP-02',
        title: 'Weak or Permissive Content-Security-Policy Directives',
        category: 'Browser Defense',
        owaspCategory: 'A03:2021 - Injection',
        cweId: 'CWE-79',
        severity: 'MEDIUM',
        cvssScore: 6.1,
        description: `The CSP contains dangerous directives: ${[
          hasUnsafeInline ? "'unsafe-inline' (allows direct script tag execution)" : '',
          hasUnsafeEval ? "'unsafe-eval' (allows string evaluation to code)" : '',
          hasWildcardScript ? "wildcard '*' source" : '',
        ].filter(Boolean).join(', ')}.`,
        impact: 'Compromises XSS protections, allowing attackers to inject inline scripts or execute dynamic strings.',
        observedEvidence: `Content-Security-Policy: ${csp}`,
        recommendedFix: 'Replace unsafe-inline with cryptographically random nonces or cryptographic hashes (SHA-256), and remove unsafe-eval.',
        references: ['https://web.dev/strict-csp/'],
        status: 'OPEN',
        headerName: 'Content-Security-Policy',
        rawHeaderValue: csp,
      });
    } else {
      passedCount++;
    }
  }

  // 4. X-Frame-Options (Clickjacking)
  const xfo = getHeader('x-frame-options');
  const cspFrameAncestors = csp && csp.includes('frame-ancestors');
  if (!xfo && !cspFrameAncestors) {
    findings.push({
      id: 'FIND-CLICKJACK-01',
      title: 'Missing Clickjacking Protection (X-Frame-Options / frame-ancestors)',
      category: 'Browser Defense',
      owaspCategory: 'A05:2021 - Security Misconfiguration',
      cweId: 'CWE-1021',
      severity: 'MEDIUM',
      cvssScore: 5.4,
      description: 'The page can be embedded inside an <iframe> on external domains without restrictions. Attackers can overlay invisible transparent frames to trick users into clicking buttons or executing unwanted transactions (Clickjacking / UI Redress attack).',
      impact: 'Unauthorized actions triggered by tricked authenticated users (e.g. initiating fund transfers, modifying email settings).',
      observedEvidence: 'Neither X-Frame-Options header nor CSP frame-ancestors directive was detected.',
      recommendedFix: 'Set X-Frame-Options: DENY (or SAMEORIGIN), and add frame-ancestors \'none\' to your CSP.',
      references: ['https://owasp.org/www-community/attacks/Clickjacking'],
      status: 'OPEN',
      headerName: 'X-Frame-Options',
      remediationSnippets: [
        {
          technology: 'Nginx',
          code: 'add_header X-Frame-Options "DENY" always;',
        },
        {
          technology: 'Express.js',
          code: 'app.use((req, res, next) => {\n  res.setHeader("X-Frame-Options", "DENY");\n  next();\n});',
        },
      ],
    });
  } else {
    passedCount++;
  }

  // 5. X-Content-Type-Options (MIME Sniffing)
  const xcto = getHeader('x-content-type-options');
  if (!xcto || xcto.toLowerCase() !== 'nosniff') {
    findings.push({
      id: 'FIND-MIME-01',
      title: 'Missing X-Content-Type-Options: nosniff Header',
      category: 'Browser Defense',
      owaspCategory: 'A05:2021 - Security Misconfiguration',
      cweId: 'CWE-116',
      severity: 'LOW',
      cvssScore: 3.7,
      description: 'The X-Content-Type-Options: nosniff header prevents web browsers from interpreting files as something other than what is declared by the content-type (MIME-type sniffing).',
      impact: 'Browsers may execute non-executable MIME types (such as image/svg+xml or text/plain) as HTML/JavaScript if malicious code is embedded.',
      observedEvidence: xcto ? `Observed: ${xcto}` : 'Header absent from response.',
      recommendedFix: 'Set X-Content-Type-Options: nosniff on all responses.',
      references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options'],
      status: 'OPEN',
      headerName: 'X-Content-Type-Options',
      remediationSnippets: [
        {
          technology: 'Nginx',
          code: 'add_header X-Content-Type-Options "nosniff" always;',
        },
        {
          technology: 'Apache',
          code: 'Header always set X-Content-Type-Options "nosniff"',
        },
      ],
    });
  } else {
    passedCount++;
  }

  // 6. Referrer-Policy
  const refPolicy = getHeader('referrer-policy');
  if (!refPolicy || refPolicy.includes('unsafe-url')) {
    findings.push({
      id: 'FIND-REF-01',
      title: 'Permissive or Missing Referrer-Policy',
      category: 'Data Privacy & Exposure',
      owaspCategory: 'A05:2021 - Security Misconfiguration',
      cweId: 'CWE-200',
      severity: 'LOW',
      cvssScore: 3.3,
      description: 'A missing or overly permissive Referrer-Policy (such as unsafe-url) leaks the full target URL query string (which may contain user tokens, reset keys, or private IDs) to third-party endpoints in the HTTP Referer header.',
      impact: 'Leakage of sensitive session tokens or URL parameters to third-party CDNs and analytics providers.',
      observedEvidence: refPolicy ? `Referrer-Policy: ${refPolicy}` : 'Header absent.',
      recommendedFix: 'Configure Referrer-Policy: strict-origin-when-cross-origin or no-referrer.',
      references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy'],
      status: 'OPEN',
      headerName: 'Referrer-Policy',
      remediationSnippets: [
        {
          technology: 'Nginx',
          code: 'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
        },
      ],
    });
  } else {
    passedCount++;
  }

  // 7. Permissions-Policy
  const permPolicy = getHeader('permissions-policy') || getHeader('feature-policy');
  if (!permPolicy) {
    findings.push({
      id: 'FIND-PERM-01',
      title: 'Missing Permissions-Policy Header',
      category: 'Browser Defense',
      owaspCategory: 'A05:2021 - Security Misconfiguration',
      cweId: 'CWE-16',
      severity: 'LOW',
      cvssScore: 2.8,
      description: 'The Permissions-Policy header allows sites to disable browser APIs and device hardware access (e.g. camera, microphone, geolocation, payment, USB) for the page and embedded iframes.',
      impact: 'Third-party embedded widgets or compromised dependencies can access device hardware sensors without application restriction.',
      observedEvidence: 'Permissions-Policy header is absent.',
      recommendedFix: 'Set Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=() to lock down unneeded browser capabilities.',
      references: ['https://github.com/w3c/webappsec-permissions-policy'],
      status: 'OPEN',
      headerName: 'Permissions-Policy',
      remediationSnippets: [
        {
          technology: 'Nginx',
          code: 'add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;',
        },
      ],
    });
  } else {
    passedCount++;
  }

  // 8. Information Disclosure via Server / Tech Banner Headers
  const serverBanner = getHeader('server');
  const xPoweredBy = getHeader('x-powered-by');
  const xAspNetVersion = getHeader('x-aspnet-version');

  const leaks: string[] = [];
  if (serverBanner && /\d+\.\d+/.test(serverBanner)) leaks.push(`Server: ${serverBanner}`);
  if (xPoweredBy) leaks.push(`X-Powered-By: ${xPoweredBy}`);
  if (xAspNetVersion) leaks.push(`X-AspNet-Version: ${xAspNetVersion}`);

  if (leaks.length > 0) {
    findings.push({
      id: 'FIND-INFO-01',
      title: 'Server & Tech-Stack Version Disclosure',
      category: 'Information Leakage',
      owaspCategory: 'A05:2021 - Security Misconfiguration',
      cweId: 'CWE-200',
      severity: 'LOW',
      cvssScore: 3.5,
      description: `The application reveals specific server software and technology runtime versions in HTTP response headers: ${leaks.join(', ')}. This reconnaissance data aids automated scanner probes and targeted exploit delivery for known CVEs.`,
      impact: 'Facilitates vulnerability profiling by revealing exact framework and web server versions.',
      observedEvidence: leaks.join(' | '),
      recommendedFix: 'Suppress server disclosure headers. In Express, run app.disable("x-powered-by"). In Nginx, set server_tokens off.',
      references: ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server'],
      status: 'OPEN',
      remediationSnippets: [
        {
          technology: 'Express.js',
          code: 'app.disable("x-powered-by");',
        },
        {
          technology: 'Nginx',
          code: 'server_tokens off;\nproxy_hide_header X-Powered-By;',
        },
      ],
    });
  } else {
    passedCount++;
  }

  // 9. Cookie Security Flags
  const setCookie = headers['set-cookie'];
  if (setCookie) {
    const cookieArray = Array.isArray(setCookie) ? setCookie : [setCookie];
    for (const cookieStr of cookieArray) {
      const parts = cookieStr.split(';').map((s) => s.trim().toLowerCase());
      const cookieName = cookieStr.split('=')[0]?.trim() || 'Cookie';
      const isSessionCookie = /sess|auth|token|jwt|id|key/i.test(cookieName);

      const hasSecure = parts.includes('secure');
      const hasHttpOnly = parts.includes('httponly');
      const sameSite = parts.find((p) => p.startsWith('samesite='));

      if (!hasSecure) {
        findings.push({
          id: `FIND-COOKIE-SEC-${cookieName}`,
          title: `Cookie "${cookieName}" Missing "Secure" Flag`,
          category: 'Cookie Hardening',
          owaspCategory: 'A05:2021 - Security Misconfiguration',
          cweId: 'CWE-614',
          severity: isSessionCookie ? 'HIGH' : 'MEDIUM',
          cvssScore: isSessionCookie ? 7.4 : 5.3,
          description: `The cookie "${cookieName}" is set without the "Secure" attribute. The browser will transmit this cookie over unencrypted HTTP connections, exposing it to sniffing.`,
          impact: 'Session hijacking through network eavesdropping on insecure Wi-Fi or transit networks.',
          observedEvidence: `Set-Cookie: ${cookieStr}`,
          recommendedFix: 'Append "; Secure" to the Set-Cookie directive.',
          references: ['https://owasp.org/www-community/controls/SecureCookieAttribute'],
          status: 'OPEN',
        });
      }

      if (!hasHttpOnly && isSessionCookie) {
        findings.push({
          id: `FIND-COOKIE-HTTPONLY-${cookieName}`,
          title: `Session Cookie "${cookieName}" Missing "HttpOnly" Flag`,
          category: 'Cookie Hardening',
          owaspCategory: 'A07:2021 - Identification & Auth Failures',
          cweId: 'CWE-1004',
          severity: 'HIGH',
          cvssScore: 7.5,
          description: `The authentication/session cookie "${cookieName}" lacks the "HttpOnly" attribute, making it accessible to client-side scripts via document.cookie.`,
          impact: 'In the event of an XSS vulnerability, attackers can directly read and exfiltrate user session cookies.',
          observedEvidence: `Set-Cookie: ${cookieStr}`,
          recommendedFix: 'Append "; HttpOnly" to all session, authentication, and state management cookies.',
          references: ['https://owasp.org/www-community/HttpOnly'],
          status: 'OPEN',
        });
      }

      if (!sameSite) {
        findings.push({
          id: `FIND-COOKIE-SAMESITE-${cookieName}`,
          title: `Cookie "${cookieName}" Missing "SameSite" Attribute`,
          category: 'Cookie Hardening',
          owaspCategory: 'A01:2021 - Broken Access Control',
          cweId: 'CWE-1275',
          severity: 'LOW',
          cvssScore: 3.5,
          description: `The cookie "${cookieName}" does not specify a SameSite attribute (Lax or Strict), leaving the request handling dependent on default browser behavior against Cross-Site Request Forgery (CSRF).`,
          impact: 'Potential cross-site credential inclusion in third-party forged requests.',
          observedEvidence: `Set-Cookie: ${cookieStr}`,
          recommendedFix: 'Set SameSite=Lax (or SameSite=Strict for high-privilege operations).',
          references: ['https://web.dev/samesite-cookies-explained/'],
          status: 'OPEN',
        });
      }
    }
  }

  // 10. HTML DOM Passive Inspection (if HTML response returned)
  if (fetchResult.body && fetchResult.body.length > 50) {
    const html = fetchResult.body;

    // Check for target="_blank" without rel="noopener"
    const blankLinkRegex = /<a\s+[^>]*target=["']_blank["'][^>]*>/gi;
    let unsafeLinks = 0;
    let linkMatch;
    while ((linkMatch = blankLinkRegex.exec(html)) !== null && unsafeLinks < 5) {
      const tag = linkMatch[0];
      if (!/rel=["'][^"']*noopener[^"']*["']/i.test(tag)) {
        unsafeLinks++;
      }
    }

    if (unsafeLinks > 0) {
      findings.push({
        id: 'FIND-HTML-NOOPENER-01',
        title: 'Reverse Tabnabbing Risk: target="_blank" Missing rel="noopener"',
        category: 'Client-Side Hardening',
        owaspCategory: 'A05:2021 - Security Misconfiguration',
        cweId: 'CWE-1022',
        severity: 'LOW',
        cvssScore: 3.1,
        description: `Found ${unsafeLinks} external anchor tag(s) with target="_blank" missing rel="noopener" (or "noreferrer"). External target pages can access the opener tab via window.opener and redirect it to a phishing replica.`,
        impact: 'Phishing attack where an opened tab replaces the authentic tab with a spoofed login prompt.',
        observedEvidence: `Detected ${unsafeLinks} occurrences in HTML body.`,
        recommendedFix: 'Always include rel="noopener noreferrer" whenever using target="_blank".',
        references: ['https://owasp.org/www-community/attacks/Reverse_Tabnabbing'],
        status: 'OPEN',
      });
    }

    // Check for external scripts without Subresource Integrity (SRI)
    const scriptSrcRegex = /<script\s+[^>]*src=["'](https?:\/\/[^"']+)["'][^>]*>/gi;
    let scriptsWithoutSri = 0;
    let scriptMatch;
    while ((scriptMatch = scriptSrcRegex.exec(html)) !== null && scriptsWithoutSri < 5) {
      const scriptTag = scriptMatch[0];
      const src = scriptMatch[1];
      // If external domain and missing integrity
      if (!src.includes(domain) && !/integrity=["']sha(256|384|512)-/i.test(scriptTag)) {
        scriptsWithoutSri++;
      }
    }

    if (scriptsWithoutSri > 0) {
      findings.push({
        id: 'FIND-HTML-SRI-01',
        title: 'External Third-Party Scripts Missing Subresource Integrity (SRI)',
        category: 'Client-Side Hardening',
        owaspCategory: 'A08:2021 - Software & Data Integrity Failures',
        cweId: 'CWE-353',
        severity: 'MEDIUM',
        cvssScore: 5.0,
        description: `Detected ${scriptsWithoutSri} external CDN or third-party script(s) loaded without cryptographic Subresource Integrity (SRI) "integrity" hashes.`,
        impact: 'If a third-party CDN or hosted library is compromised or DNS hijacked, arbitrary malicious JavaScript executes in your application context.',
        observedEvidence: `Found ${scriptsWithoutSri} third-party scripts lacking integrity="..." attribute.`,
        recommendedFix: 'Generate SHA-384 integrity hashes and add crossorigin="anonymous" integrity="sha384-..." to all external script tags.',
        references: ['https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity'],
        status: 'OPEN',
      });
    }
  }

  // 11. Optional Well-Known Discovery (security.txt)
  let securityTxtFound = false;
  if (options.checkSecurityTxt !== false) {
    try {
      const secTxtUrl = new URL('/.well-known/security.txt', targetUrl).toString();
      const secRes = await fetchWithRedirects(secTxtUrl, 2);
      if (secRes.statusCode === 200 && secRes.body.includes('Contact:')) {
        securityTxtFound = true;
        passedCount++;
      } else {
        findings.push({
          id: 'FIND-DISC-SEC-TXT',
          title: 'Missing Vulnerability Disclosure Policy (security.txt)',
          category: 'Security Standards',
          owaspCategory: 'A05:2021 - Security Misconfiguration',
          cweId: 'CWE-16',
          severity: 'INFO',
          cvssScore: 0.0,
          description: 'The site does not publish a security.txt file (RFC 9116) at /.well-known/security.txt. This standard establishes a standardized channel for ethical security researchers to report vulnerabilities.',
          impact: 'Responsible security researchers may struggle to reach the right incident response team, delaying patch deployment.',
          observedEvidence: 'HTTP 404 or missing Contact directive at /.well-known/security.txt',
          recommendedFix: 'Publish a /.well-known/security.txt file containing Contact, Expires, and Encryption directives.',
          references: ['https://securitytxt.org/', 'https://www.rfc-editor.org/rfc/rfc9116'],
          status: 'OPEN',
        });
      }
    } catch {
      // ignore discovery failures
    }
  }

  // 12. Optional Robots.txt inspection for sensitive endpoint disclosures
  let robotsTxtFound = false;
  if (options.checkRobots !== false) {
    try {
      const robotsUrl = new URL('/robots.txt', targetUrl).toString();
      const robRes = await fetchWithRedirects(robotsUrl, 2);
      if (robRes.statusCode === 200 && robRes.body) {
        robotsTxtFound = true;
        const sensitiveDisallow = robRes.body.match(/disallow:\s*(\/(admin|api|backup|config|db|internal|private|staging|secret|portal)[^\s\n]*)/gi);
        if (sensitiveDisallow && sensitiveDisallow.length > 0) {
          findings.push({
            id: 'FIND-ROBOTS-LEAK',
            title: 'Sensitive Internal Endpoints Disclosed in robots.txt',
            category: 'Information Leakage',
            owaspCategory: 'A01:2021 - Broken Access Control',
            cweId: 'CWE-200',
            severity: 'LOW',
            cvssScore: 3.5,
            description: `The robots.txt file explicitly enumerates sensitive, administrative, or non-public URL paths: ${sensitiveDisallow.slice(0, 4).join(', ')}. Robots.txt is public and often indexed by attackers as high-value target lists.`,
            impact: 'Assists attackers in discovering non-public admin portals, staging areas, or internal API routes.',
            observedEvidence: `Disclosed paths: ${sensitiveDisallow.join('; ')}`,
            recommendedFix: 'Protect administrative routes with strict network controls, SSO, and VPN rather than relying on robots.txt obscurity. Avoid naming internal routes with sensitive keywords in robots.txt.',
            references: ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/03-Review_Webserver_Metafiles_for_Information_Leakage'],
            status: 'OPEN',
          });
        }
      }
    } catch {
      // ignore
    }
  }

  // Calculate Scorecard
  const critical = findings.filter((f) => f.severity === 'CRITICAL').length;
  const high = findings.filter((f) => f.severity === 'HIGH').length;
  const medium = findings.filter((f) => f.severity === 'MEDIUM').length;
  const low = findings.filter((f) => f.severity === 'LOW').length;
  const info = findings.filter((f) => f.severity === 'INFO').length;

  // Weighted scoring
  const penalty = critical * 25 + high * 12 + medium * 5 + low * 2;
  const numericScore = Math.max(0, Math.min(100, 100 - penalty));

  let grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F' = 'A+';
  if (critical > 0 || numericScore < 40) grade = 'F';
  else if (high > 1 || numericScore < 55) grade = 'D';
  else if (high === 1 || numericScore < 70) grade = 'C';
  else if (medium > 0 || numericScore < 85) grade = 'B';
  else if (numericScore < 95) grade = 'A';
  else grade = 'A+';

  const scorecard: SecurityScorecard = {
    grade,
    numericScore,
    criticalCount: critical,
    highCount: high,
    mediumCount: medium,
    lowCount: low,
    infoCount: info,
    totalFindings: findings.length,
    passedChecksCount: passedCount,
  };

  return {
    id: `SCAN-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
    target: targetUrl,
    targetType: 'SITE_URL',
    timestamp: new Date().toISOString(),
    scanDurationMs: fetchResult.durationMs,
    scorecard,
    findings,
    metadata: {
      serverBanner: serverBanner || 'Not disclosed',
      statusCode: fetchResult.statusCode,
      redirectChain: fetchResult.redirects,
      securityTxtFound,
      robotsTxtFound,
      headersCount: Object.keys(headers).length,
    },
    executiveSummary: `Automated security posture scan of ${targetUrl} completed with grade ${grade} (${numericScore}/100). Identified ${findings.length} security observation(s) across transport encryption, HTTP security headers, and browser defense policies.`,
  };
}
