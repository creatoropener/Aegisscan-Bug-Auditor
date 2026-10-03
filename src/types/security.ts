/**
 * Security Vulnerability & Audit Types
 */

export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type FindingStatus = 'OPEN' | 'IN_REVIEW' | 'FIXED' | 'ACCEPTED_RISK' | 'FALSE_POSITIVE';

export type ScanType = 'SITE_URL' | 'SOURCE_CODE' | 'CONFIG_MANIFEST' | 'BENCHMARK_DEMO';

export type OwaspCategory =
  | 'A01:2021 - Broken Access Control'
  | 'A02:2021 - Cryptographic Failures'
  | 'A03:2021 - Injection'
  | 'A04:2021 - Insecure Design'
  | 'A05:2021 - Security Misconfiguration'
  | 'A06:2021 - Vulnerable and Outdated Components'
  | 'A07:2021 - Identification & Auth Failures'
  | 'A08:2021 - Software & Data Integrity Failures'
  | 'A09:2021 - Security Logging & Monitoring Failures'
  | 'A10:2021 - Server-Side Request Forgery (SSRF)';

export interface SecurityFinding {
  id: string;
  title: string;
  category: string;
  owaspCategory: OwaspCategory;
  cweId: string; // e.g. "CWE-693"
  severity: SeverityLevel;
  cvssScore: number; // 0.0 - 10.0
  description: string;
  impact: string;
  observedEvidence: string;
  recommendedFix: string;
  remediationSnippets?: {
    technology: string;
    code: string;
  }[];
  references: string[];
  status: FindingStatus;
  location?: {
    file?: string;
    line?: number;
    column?: number;
    codeSnippet?: string;
  };
  headerName?: string;
  rawHeaderValue?: string;
}

export interface SecurityScorecard {
  grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
  numericScore: number; // 0 - 100
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
  totalFindings: number;
  passedChecksCount: number;
}

export interface SecurityAuditReport {
  id: string;
  target: string;
  targetType: ScanType;
  timestamp: string;
  scanDurationMs: number;
  scorecard: SecurityScorecard;
  findings: SecurityFinding[];
  metadata: {
    ipAddress?: string;
    serverBanner?: string;
    httpVersion?: string;
    statusCode?: number;
    redirectChain?: string[];
    securityTxtFound?: boolean;
    robotsTxtFound?: boolean;
    headersCount?: number;
    linesOfCodeScanned?: number;
  };
  executiveSummary?: string;
  owaspComplianceSummary?: Record<string, { pass: boolean; count: number }>;
}

export interface PreloadedDemoScenario {
  id: string;
  name: string;
  target: string;
  type: ScanType;
  description: string;
  simulatedGrade: 'A+' | 'B' | 'F';
  tag: string;
}
