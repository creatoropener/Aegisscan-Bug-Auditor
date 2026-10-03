import { SecurityAuditReport, PreloadedDemoScenario, SecurityFinding } from '../types/security';

export async function fetchHealth(): Promise<{ status: string; hasGeminiKey: boolean }> {
  const res = await fetch('/api/health');
  if (!res.ok) throw new Error('Health check failed');
  return res.json();
}

export async function fetchScenarios(): Promise<{
  scenarios: PreloadedDemoScenario[];
  codeSnippets: Record<string, { filename: string; code: string }>;
}> {
  const res = await fetch('/api/scenarios');
  if (!res.ok) throw new Error('Failed to fetch scenarios');
  return res.json();
}

export async function fetchScenarioReport(scenarioId: string): Promise<SecurityAuditReport> {
  const res = await fetch(`/api/scenarios/${encodeURIComponent(scenarioId)}`);
  if (!res.ok) throw new Error(`Failed to load report for ${scenarioId}`);
  return res.json();
}

export async function scanSiteUrl(
  url: string,
  options?: { checkRobots?: boolean; checkSecurityTxt?: boolean; deepHtml?: boolean }
): Promise<SecurityAuditReport> {
  const res = await fetch('/api/scan/site', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url, options }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to scan target URL');
  }
  return res.json();
}

export async function scanSourceCode(
  filename: string,
  code: string,
  fileType?: string
): Promise<SecurityAuditReport> {
  const res = await fetch('/api/scan/code', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ filename, code, fileType }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to scan source code');
  }
  return res.json();
}

export async function generateAiReport(report: SecurityAuditReport): Promise<string> {
  const res = await fetch('/api/scan/ai-report', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ report }),
  });
  if (!res.ok) {
    throw new Error('Failed to generate AI executive report');
  }
  const data = await res.json();
  return data.analysis || '';
}

export async function askAiCopilot(
  message: string,
  contextFinding?: SecurityFinding,
  currentReport?: SecurityAuditReport
): Promise<string> {
  const res = await fetch('/api/scan/ai-copilot', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message, contextFinding, currentReport }),
  });
  if (!res.ok) {
    throw new Error('Failed to ask Security Co-Pilot');
  }
  const data = await res.json();
  return data.reply || '';
}
