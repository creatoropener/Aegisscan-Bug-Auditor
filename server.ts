import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import { GoogleGenAI } from '@google/genai';
import { runDastSiteScan } from './src/server/dastEngine.js';
import { runSastCodeScan } from './src/server/sastEngine.js';
import { DEMO_SCENARIOS, DEMO_CODE_SNIPPETS, MOCK_REPORTS } from './src/server/demoScenarios.js';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const port = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Initialize Google Gemini AI Client on the server side
let aiClient: GoogleGenAI | null = null;
if (process.env.GEMINI_API_KEY) {
  try {
    aiClient = new GoogleGenAI({
      apiKey: process.env.GEMINI_API_KEY,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        },
      },
    });
  } catch (err) {
    console.warn('Failed to initialize GoogleGenAI client:', err);
  }
}

// 1. Health & Status
app.get('/api/health', (_req, res) => {
  res.json({
    status: 'ok',
    version: '1.0.0',
    hasGeminiKey: Boolean(process.env.GEMINI_API_KEY),
    timestamp: new Date().toISOString(),
  });
});

// 2. Demo Presets & Benchmark Scenarios
app.get('/api/scenarios', (_req, res) => {
  res.json({
    scenarios: DEMO_SCENARIOS,
    codeSnippets: DEMO_CODE_SNIPPETS,
  });
});

app.get('/api/scenarios/:id', (req, res) => {
  const scenarioId = req.params.id;
  if (scenarioId === 'demo-fintech-api') {
    const snippet = DEMO_CODE_SNIPPETS.vulnerable_api;
    const report = runSastCodeScan({
      filename: snippet.filename,
      code: snippet.code,
    });
    return res.json(report);
  }

  const mock = MOCK_REPORTS[scenarioId];
  if (mock) {
    return res.json(mock);
  }

  res.status(404).json({ error: `Scenario ${scenarioId} not found` });
});

// 3. Automated Passive DAST Web Scanner Endpoint
app.post('/api/scan/site', async (req, res) => {
  try {
    const { url, options } = req.body;
    if (!url || typeof url !== 'string') {
      return res.status(400).json({ error: 'Valid URL is required.' });
    }

    const report = await runDastSiteScan(url, options || {});
    res.json(report);
  } catch (error: any) {
    console.error('Scan error:', error);
    res.status(500).json({
      error: error.message || 'Failed to scan target endpoint.',
      code: 'SCAN_FAILED',
    });
  }
});

// 4. Automated SAST Static Code Scanner Endpoint
app.post('/api/scan/code', (req, res) => {
  try {
    const { filename, code, fileType } = req.body;
    if (!code || typeof code !== 'string') {
      return res.status(400).json({ error: 'Source code content is required.' });
    }

    const report = runSastCodeScan({ filename, code, fileType });
    res.json(report);
  } catch (error: any) {
    console.error('SAST scan error:', error);
    res.status(500).json({
      error: error.message || 'Failed to analyze source code.',
      code: 'SAST_FAILED',
    });
  }
});

// 5. AI Security Executive Summary & Threat Assessment
app.post('/api/scan/ai-report', async (req, res) => {
  try {
    const { report } = req.body;
    if (!report || !report.findings) {
      return res.status(400).json({ error: 'Valid report object required.' });
    }

    if (!aiClient) {
      // Deterministic fallback if API key not injected
      return res.json({
        analysis: generateDeterministicAiReport(report),
      });
    }

    const findingsSummary = (report.findings as any[])
      .slice(0, 8)
      .map(
        (f, i) =>
          `${i + 1}. [${f.severity}] ${f.title} (${f.owaspCategory || 'General'}, ${f.cweId || 'CWE'}): ${f.description.slice(0, 150)}`
      )
      .join('\n');

    const prompt = `You are a Principal Cyber Security Auditor and Defensive AppSec Architect.
Analyze the following automated vulnerability scan results for target: "${report.target}" (Type: ${report.targetType}).
Scorecard: Grade ${report.scorecard.grade} (${report.scorecard.numericScore}/100), Critical: ${report.scorecard.criticalCount}, High: ${report.scorecard.highCount}, Medium: ${report.scorecard.mediumCount}, Low: ${report.scorecard.lowCount}.

Key Findings Identified:
${findingsSummary}

Provide a concise, professional executive security assessment structured with these exact sections:
1. Executive Risk Posture (2-3 sentences on overall exposure)
2. Highest Severity Threat Scenario (explain realistic exploit chain or attacker leverage)
3. OWASP Top 10 Impact Analysis (which critical categories are failing and why)
4. Recommended Immediate Remediation Plan (3-4 prioritized actions for developers and DevOps)

Keep the tone authoritative, defensive, objective, and actionable. Do not generate exploit payloads or attack scripts; focus strictly on defensive hardening and remediation.`;

    const aiRes = await aiClient.models.generateContent({
      model: 'gemini-3.8-flash',
      contents: prompt,
    });

    res.json({
      analysis: aiRes.text || generateDeterministicAiReport(report),
    });
  } catch (err: any) {
    console.error('Gemini AI report error:', err);
    res.json({
      analysis: generateDeterministicAiReport(req.body.report),
    });
  }
});

// 6. Interactive AI Security Assistant (Co-Pilot)
app.post('/api/scan/ai-copilot', async (req, res) => {
  try {
    const { message, contextFinding, currentReport } = req.body;
    if (!message) {
      return res.status(400).json({ error: 'User message is required.' });
    }

    if (!aiClient) {
      return res.json({
        reply: `Here is defensive hardening advice for "${contextFinding?.title || 'Security Hardening'}":
1. Review the OWASP guidelines for ${contextFinding?.owaspCategory || 'Security Misconfiguration'}.
2. Ensure default-deny configurations for all public endpoints.
3. Validate that cryptographic tokens and secrets are stored in secure environment vaults rather than source files.
4. Apply the recommended code patches provided in the vulnerability details.`,
      });
    }

    const findingContext = contextFinding
      ? `\nActive Finding Context:\n- Title: ${contextFinding.title}\n- Severity: ${contextFinding.severity} (CVSS ${contextFinding.cvssScore})\n- OWASP: ${contextFinding.owaspCategory}\n- CWE: ${contextFinding.cweId}\n- Evidence: ${contextFinding.observedEvidence}\n- Recommended Fix: ${contextFinding.recommendedFix}`
      : currentReport
        ? `\nCurrent Report Target: ${currentReport.target} (Grade: ${currentReport.scorecard.grade}, Total Findings: ${currentReport.scorecard.totalFindings})`
        : '';

    const prompt = `You are AegisScan Defensive Security Co-Pilot, an expert in Application Security (AppSec), OWASP ASVS, secure coding, and cloud infrastructure hardening.
Assist the developer with the following question while focusing exclusively on defensive guidance, code refactoring, secure configuration (Nginx/Apache/Express/Next.js/CSP), and vulnerability remediation.
Never provide functional exploitation scripts or attack payloads.

${findingContext}

Developer's Question: "${message}"

Provide a clear, practical, expert defensive answer with concrete code snippets or configuration examples where appropriate.`;

    const aiRes = await aiClient.models.generateContent({
      model: 'gemini-3.8-flash',
      contents: prompt,
    });

    res.json({
      reply: aiRes.text || 'Unable to generate security guidance at this time.',
    });
  } catch (err: any) {
    console.error('Co-Pilot error:', err);
    res.json({
      reply: 'An error occurred while contacting the security advisor. Please check your network and try again.',
    });
  }
});

function generateDeterministicAiReport(report: any): string {
  if (!report) return 'Security assessment completed.';
  const score = report.scorecard;
  return `### Executive Risk Posture
The target "${report.target}" scored **${score.numericScore}/100** with an overall grade of **${score.grade}**. ${
    score.criticalCount > 0
      ? `Immediate intervention is required due to ${score.criticalCount} critical vulnerability finding(s) that permit remote compromise or credential exposure.`
      : score.highCount > 0
        ? `Elevated risk detected with ${score.highCount} high-severity issue(s) primarily impacting browser isolation and session security.`
        : 'The baseline security posture is stable with mostly low-severity defensive hardening opportunities.'
  }

### Highest Severity Threat Scenario
Absence or misconfiguration of Content-Security-Policy (CSP) and cookie security flags creates an exposure vector where malicious scripts or cross-origin framing can compromise authenticated user sessions. Attackers can execute UI redressing or exfiltrate tokens transmitted without cryptographic protections.

### OWASP Top 10 Impact Analysis
- **A05:2021 Security Misconfiguration**: Core HTTP transport and response headers are missing or improperly parameterized.
- **A07:2021 Identification & Auth Failures**: Session tokens and authentication cookies require mandatory \`HttpOnly\`, \`Secure\`, and \`SameSite\` flags.
- **A03:2021 Injection / Browser Defense**: Lack of strict origin and script execution boundaries leaves endpoints vulnerable to DOM manipulation.

### Recommended Immediate Remediation Plan
1. **Deploy Modern Defense Headers**: Apply strict CSP directives (\`default-src 'self'\`), enable HSTS with a 1-year duration, and enforce \`X-Frame-Options: DENY\`.
2. **Harden Cookie Architecture**: Ensure every stateful authentication cookie includes \`SameSite=Lax\` and \`Secure\`.
3. **Automate CI/CD Gate**: Integrate regular static code and dependency auditing into commit pipelines to catch leaked keys and vulnerable libraries prior to production deployment.`;
}

// Vite middleware in dev or static files in production
async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.resolve(distPath, 'index.html'));
    });
  }

  app.listen(port, '0.0.0.0', () => {
    console.log(`AegisScan security server running on http://0.0.0.0:${port}`);
  });
}

startServer();
