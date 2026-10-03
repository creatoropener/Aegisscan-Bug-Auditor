import React from 'react';
import { SecurityAuditReport, OwaspCategory } from '../types/security';
import { ShieldCheck, ShieldAlert, AlertTriangle, ArrowRight, ExternalLink } from 'lucide-react';

interface OwaspMatrixViewProps {
  report: SecurityAuditReport;
  onFilterOwaspFindings: (category: OwaspCategory) => void;
}

interface OwaspCategoryDef {
  code: string;
  name: string;
  fullName: OwaspCategory;
  description: string;
  keyControls: string;
  owaspUrl: string;
}

const OWASP_CATEGORIES: OwaspCategoryDef[] = [
  {
    code: 'A01:2021',
    name: 'Broken Access Control',
    fullName: 'A01:2021 - Broken Access Control',
    description: 'Enforcing access limits so users cannot act outside their intended permissions. Flaws permit unauthorized data access, path traversal, or privilege escalation.',
    keyControls: 'Deny by default, CORS origin verification, path traversal checks, role-based authorization.',
    owaspUrl: 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/',
  },
  {
    code: 'A02:2021',
    name: 'Cryptographic Failures',
    fullName: 'A02:2021 - Cryptographic Failures',
    description: 'Failures related to cryptography (previously Sensitive Data Exposure) leading to compromised keys, cleartext transport (HTTP), or weak legacy ciphers (MD5/SHA1).',
    keyControls: 'Enforce HTTPS, strict HSTS preload, upgrade to SHA-256/Argon2, eliminate Math.random for tokens.',
    owaspUrl: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
  },
  {
    code: 'A03:2021',
    name: 'Injection',
    fullName: 'A03:2021 - Injection',
    description: 'Hostile data sent to an interpreter as part of a command or query. Includes SQL injection, Cross-Site Scripting (XSS), eval code injection, and template injection.',
    keyControls: 'Parameterized queries, strict CSP headers, DOMPurify for HTML sinks, elimination of eval().',
    owaspUrl: 'https://owasp.org/Top10/A03_2021-Injection/',
  },
  {
    code: 'A04:2021',
    name: 'Insecure Design',
    fullName: 'A04:2021 - Insecure Design',
    description: 'Focuses on risks related to design and architectural flaws before code implementation. Missing threat modeling or security baseline controls.',
    keyControls: 'Defense-in-depth, principle of least privilege, threat modeling, security architecture patterns.',
    owaspUrl: 'https://owasp.org/Top10/A04_2021-Insecure_Design/',
  },
  {
    code: 'A05:2021',
    name: 'Security Misconfiguration',
    fullName: 'A05:2021 - Security Misconfiguration',
    description: 'Missing security headers, default server credentials, verbose error stack traces, unpatched software, or exposed server banner versions.',
    keyControls: 'Automated hardening templates, disable X-Powered-By/server tokens, configure X-Frame-Options & nosniff.',
    owaspUrl: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
  },
  {
    code: 'A06:2021',
    name: 'Vulnerable & Outdated Components',
    fullName: 'A06:2021 - Vulnerable and Outdated Components',
    description: 'Running dependencies, client libraries, or server packages with known published CVEs (e.g. vulnerable lodash, axios, or Express middleware).',
    keyControls: 'Automated Software Bill of Materials (SBOM), continuous dependency auditing, rapid patch deployment.',
    owaspUrl: 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/',
  },
  {
    code: 'A07:2021',
    name: 'Identification & Auth Failures',
    fullName: 'A07:2021 - Identification & Auth Failures',
    description: 'Weak session handling, missing HttpOnly flags on session cookies, hardcoded credentials or API keys in source files.',
    keyControls: 'HttpOnly and SameSite cookie attributes, multi-factor auth, strict secret manager isolation.',
    owaspUrl: 'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/',
  },
  {
    code: 'A08:2021',
    name: 'Software & Data Integrity Failures',
    fullName: 'A08:2021 - Software & Data Integrity Failures',
    description: 'Code and infrastructure that does not protect against integrity violations, such as loading unverified third-party CDN scripts without Subresource Integrity (SRI).',
    keyControls: 'Cryptographic Subresource Integrity (SRI) hashes on all external scripts and CSS assets.',
    owaspUrl: 'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/',
  },
  {
    code: 'A09:2021',
    name: 'Security Logging & Monitoring',
    fullName: 'A09:2021 - Security Logging & Monitoring Failures',
    description: 'Insufficient logging and monitoring prevents early breach detection and automated incident alerting.',
    keyControls: 'Centralized append-only audit logging, real-time alerting on unauthorized access attempts.',
    owaspUrl: 'https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/',
  },
  {
    code: 'A10:2021',
    name: 'Server-Side Request Forgery (SSRF)',
    fullName: 'A10:2021 - Server-Side Request Forgery (SSRF)',
    description: 'Occurs when a web application fetches a remote resource without validating the user-supplied URL (e.g. internal cloud metadata access).',
    keyControls: 'Disable HTTP redirection on user URLs, restrict destination IP addresses (block 169.254.169.254).',
    owaspUrl: 'https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/',
  },
];

export const OwaspMatrixView: React.FC<OwaspMatrixViewProps> = ({
  report,
  onFilterOwaspFindings,
}) => {
  return (
    <div className="space-y-6">
      <div className="border-b border-slate-800 pb-5">
        <h1 className="text-xl font-bold tracking-tight text-white sm:text-2xl">
          OWASP Top 10 (2021) Compliance Matrix
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Automated evaluation of findings mapped to the industry-standard OWASP Top 10 web application security risks.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {OWASP_CATEGORIES.map((cat) => {
          const associatedFindings = report.findings.filter(
            (f) => f.owaspCategory === cat.fullName
          );
          const hasIssues = associatedFindings.length > 0;
          const hasCritical = associatedFindings.some((f) => f.severity === 'CRITICAL');
          const hasHigh = associatedFindings.some((f) => f.severity === 'HIGH');

          return (
            <div
              key={cat.code}
              className={`rounded-xl border p-5 flex flex-col justify-between transition-colors ${
                hasCritical
                  ? 'border-rose-800/60 bg-rose-950/20'
                  : hasHigh
                  ? 'border-amber-800/50 bg-amber-950/15'
                  : hasIssues
                  ? 'border-yellow-800/40 bg-yellow-950/10'
                  : 'border-slate-800 bg-slate-900/40'
              }`}
            >
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="font-mono text-xs font-semibold text-blue-400">
                    {cat.code}
                  </span>
                  <div className="flex items-center gap-1.5">
                    {hasIssues ? (
                      <span
                        className={`text-xs font-mono font-semibold px-2 py-0.5 rounded ${
                          hasCritical
                            ? 'bg-rose-950 text-rose-300 border border-rose-800/50'
                            : 'bg-amber-950 text-amber-300 border border-amber-800/50'
                        }`}
                      >
                        {associatedFindings.length} Finding{associatedFindings.length > 1 ? 's' : ''}
                      </span>
                    ) : (
                      <span className="flex items-center gap-1 text-xs text-emerald-400 font-medium">
                        <ShieldCheck className="h-3.5 w-3.5" />
                        <span>Pass</span>
                      </span>
                    )}
                  </div>
                </div>

                <h3 className="text-sm font-semibold text-white mb-1.5">{cat.name}</h3>
                <p className="text-xs text-slate-300 leading-relaxed mb-3">{cat.description}</p>
              </div>

              <div className="border-t border-slate-800/60 pt-3 space-y-2 text-xs">
                <div>
                  <span className="text-[11px] font-medium text-slate-400">Defensive Controls: </span>
                  <span className="text-slate-300">{cat.keyControls}</span>
                </div>

                <div className="flex items-center justify-between pt-1">
                  <a
                    href={cat.owaspUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 text-[11px] text-slate-400 hover:text-white transition-colors"
                  >
                    <span>OWASP Standard Guide</span>
                    <ExternalLink className="h-3 w-3" />
                  </a>

                  {hasIssues && (
                    <button
                      onClick={() => onFilterOwaspFindings(cat.fullName)}
                      className="inline-flex items-center gap-1 text-xs font-medium text-blue-400 hover:text-blue-300 transition-colors"
                    >
                      <span>Filter ({associatedFindings.length})</span>
                      <ArrowRight className="h-3 w-3" />
                    </button>
                  )}
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
