import React from 'react';
import { SecurityAuditReport, PreloadedDemoScenario } from '../types/security';
import { ShieldAlert, ShieldCheck, AlertTriangle, Info, Globe, Code2, ArrowUpRight, CheckCircle2, Sparkles, RefreshCw } from 'lucide-react';

interface DashboardOverviewProps {
  report: SecurityAuditReport;
  scenarios: PreloadedDemoScenario[];
  onSelectScenario: (id: string) => void;
  onViewFindings: () => void;
  onOpenReportModal: () => void;
  onOpenNewScan: () => void;
  onSelectFinding: (id: string) => void;
}

export const DashboardOverview: React.FC<DashboardOverviewProps> = ({
  report,
  scenarios,
  onSelectScenario,
  onViewFindings,
  onOpenReportModal,
  onOpenNewScan,
  onSelectFinding,
}) => {
  const scorecard = report.scorecard;

  const gradeColors: Record<string, { text: string; bg: string; border: string }> = {
    'A+': { text: 'text-emerald-400', bg: 'bg-emerald-950/40', border: 'border-emerald-500/40' },
    A: { text: 'text-emerald-400', bg: 'bg-emerald-950/40', border: 'border-emerald-500/40' },
    B: { text: 'text-blue-400', bg: 'bg-blue-950/40', border: 'border-blue-500/40' },
    C: { text: 'text-amber-400', bg: 'bg-amber-950/40', border: 'border-amber-500/40' },
    D: { text: 'text-orange-400', bg: 'bg-orange-950/40', border: 'border-orange-500/40' },
    F: { text: 'text-rose-400', bg: 'bg-rose-950/40', border: 'border-rose-500/40' },
  };

  const currentGradeStyle = gradeColors[scorecard.grade] || gradeColors['C'];

  // Top high-priority findings
  const highPriorityFindings = report.findings
    .filter((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH')
    .slice(0, 4);

  return (
    <div className="space-y-8">
      {/* Target & Benchmark Bar */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between border-b border-slate-800/80 pb-6">
        <div>
          <div className="flex items-center gap-2 text-xs text-slate-400">
            <span className="flex items-center gap-1.5 text-slate-300 font-medium">
              {report.targetType === 'SITE_URL' ? (
                <Globe className="h-3.5 w-3.5 text-blue-400" />
              ) : (
                <Code2 className="h-3.5 w-3.5 text-emerald-400" />
              )}
              {report.targetType === 'SITE_URL' ? 'Live Web Target' : 'Source Code Asset'}
            </span>
            <span aria-hidden="true">·</span>
            <span className="font-mono tabular-nums">{new Date(report.timestamp).toLocaleString()}</span>
            <span aria-hidden="true">·</span>
            <span className="font-mono tabular-nums">{report.scanDurationMs}ms execution</span>
          </div>
          <h1 className="mt-1 text-2xl font-bold tracking-tight text-white sm:text-3xl font-mono truncate max-w-3xl">
            {report.target}
          </h1>
        </div>

        {/* Demo Switcher Quick Buttons */}
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs text-slate-500 mr-1">Benchmark Lab:</span>
          {scenarios.map((sc) => (
            <button
              key={sc.id}
              onClick={() => onSelectScenario(sc.id)}
              className="rounded-lg border border-slate-800 bg-slate-900/80 px-3 py-1.5 text-xs text-slate-300 hover:border-slate-700 hover:bg-slate-800 transition-colors"
            >
              {sc.name}
            </button>
          ))}
          <button
            onClick={onOpenNewScan}
            className="rounded-lg border border-blue-500/30 bg-blue-950/30 px-3 py-1.5 text-xs text-blue-300 hover:bg-blue-900/40 transition-colors flex items-center gap-1.5"
          >
            <RefreshCw className="h-3 w-3" />
            Audit Custom Target
          </button>
        </div>
      </div>

      {/* Primary Posture Cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-5">
        {/* Posture Grade Card */}
        <div
          className={`flex flex-col justify-between rounded-xl border ${currentGradeStyle.border} ${currentGradeStyle.bg} p-5`}
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Security Grade</span>
            <span className="text-xs font-mono text-slate-400 tabular-nums">
              Score: {scorecard.numericScore}/100
            </span>
          </div>
          <div className="my-2 flex items-baseline gap-3">
            <span className={`text-5xl font-black font-mono tracking-tight ${currentGradeStyle.text}`}>
              {scorecard.grade}
            </span>
            <span className="text-xs text-slate-300 leading-snug">
              {scorecard.grade === 'A+' || scorecard.grade === 'A'
                ? 'Strong defense-in-depth posture'
                : scorecard.grade === 'B'
                ? 'Moderate posture with mild hardening gaps'
                : scorecard.grade === 'C'
                ? 'High risk vulnerabilities detected'
                : 'Critical exposure requiring immediate mitigation'}
            </span>
          </div>
          <div className="w-full bg-slate-950/60 rounded-full h-1.5 overflow-hidden">
            <div
              className={`h-full rounded-full transition-all duration-500 ${
                scorecard.numericScore > 80
                  ? 'bg-emerald-500'
                  : scorecard.numericScore > 50
                  ? 'bg-amber-500'
                  : 'bg-rose-500'
              }`}
              style={{ width: `${scorecard.numericScore}%` }}
            />
          </div>
        </div>

        {/* Critical Card */}
        <div className="flex flex-col justify-between rounded-xl border border-slate-800 bg-slate-900/60 p-5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Critical Severity</span>
            <ShieldAlert className="h-4 w-4 text-rose-500" />
          </div>
          <div className="my-2">
            <span className="text-3xl font-bold font-mono text-white tabular-nums">
              {scorecard.criticalCount}
            </span>
            <span className="ml-2 text-xs text-slate-500 font-mono">CVSS 9.0–10.0</span>
          </div>
          <p className="text-xs text-slate-400">Direct compromise or key leak risk</p>
        </div>

        {/* High & Medium Card */}
        <div className="flex flex-col justify-between rounded-xl border border-slate-800 bg-slate-900/60 p-5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">High & Medium</span>
            <AlertTriangle className="h-4 w-4 text-amber-500" />
          </div>
          <div className="my-2">
            <span className="text-3xl font-bold font-mono text-white tabular-nums">
              {scorecard.highCount + scorecard.mediumCount}
            </span>
            <span className="ml-2 text-xs text-slate-500 font-mono">
              {scorecard.highCount} high · {scorecard.mediumCount} med
            </span>
          </div>
          <p className="text-xs text-slate-400">Browser policy & session weaknesses</p>
        </div>

        {/* Low & Info Card */}
        <div className="flex flex-col justify-between rounded-xl border border-slate-800 bg-slate-900/60 p-5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Low / Informational</span>
            <Info className="h-4 w-4 text-blue-400" />
          </div>
          <div className="my-2">
            <span className="text-3xl font-bold font-mono text-white tabular-nums">
              {scorecard.lowCount + scorecard.infoCount}
            </span>
            <span className="ml-2 text-xs text-slate-500 font-mono">
              {scorecard.lowCount} low · {scorecard.infoCount} info
            </span>
          </div>
          <p className="text-xs text-slate-400">Hardening & metadata disclosures</p>
        </div>

        {/* Passing Checks Card */}
        <div className="flex flex-col justify-between rounded-xl border border-slate-800 bg-slate-900/60 p-5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Controls Passed</span>
            <CheckCircle2 className="h-4 w-4 text-emerald-400" />
          </div>
          <div className="my-2">
            <span className="text-3xl font-bold font-mono text-emerald-400 tabular-nums">
              {scorecard.passedChecksCount}
            </span>
            <span className="ml-2 text-xs text-slate-500">verifications</span>
          </div>
          <p className="text-xs text-slate-400">Active defensive boundaries</p>
        </div>
      </div>

      {/* Two Column Layout: Urgent Findings & Executive Threat Synthesis */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Urgent Findings (2 cols) */}
        <div className="lg:col-span-2 rounded-xl border border-slate-800 bg-slate-900/40 p-6">
          <div className="flex items-center justify-between mb-5">
            <div>
              <h2 className="text-base font-semibold text-white">Priority Vulnerability Findings</h2>
              <p className="text-xs text-slate-400">
                Issues requiring immediate architectural or configuration remediation
              </p>
            </div>
            <button
              onClick={onViewFindings}
              className="text-xs font-medium text-blue-400 hover:text-blue-300 flex items-center gap-1 transition-colors"
            >
              <span>View All ({report.findings.length})</span>
              <ArrowUpRight className="h-3.5 w-3.5" />
            </button>
          </div>

          {highPriorityFindings.length === 0 ? (
            <div className="rounded-lg border border-dashed border-slate-800 p-8 text-center">
              <CheckCircle2 className="mx-auto h-8 w-8 text-emerald-400 mb-2" />
              <p className="text-sm font-medium text-white">No Critical or High Vulnerabilities</p>
              <p className="text-xs text-slate-400 mt-1">
                All high-impact browser security policies and transport encryption benchmarks passed.
              </p>
            </div>
          ) : (
            <div className="space-y-3">
              {highPriorityFindings.map((finding) => (
                <div
                  key={finding.id}
                  onClick={() => onSelectFinding(finding.id)}
                  className="group flex flex-col sm:flex-row sm:items-center justify-between gap-3 rounded-lg border border-slate-800/80 bg-slate-900/80 p-4 hover:border-slate-700 hover:bg-slate-800/60 cursor-pointer transition-colors"
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span
                        className={`text-xs font-mono font-semibold px-2 py-0.5 rounded ${
                          finding.severity === 'CRITICAL'
                            ? 'bg-rose-950/80 text-rose-300 border border-rose-800/40'
                            : 'bg-amber-950/80 text-amber-300 border border-amber-800/40'
                        }`}
                      >
                        {finding.severity}
                      </span>
                      <span className="text-xs font-mono text-slate-400 tabular-nums">
                        CVSS {finding.cvssScore.toFixed(1)}
                      </span>
                      <span className="text-xs text-slate-500">·</span>
                      <span className="text-xs text-slate-400">{finding.cweId}</span>
                    </div>
                    <h3 className="text-sm font-medium text-white group-hover:text-blue-400 transition-colors">
                      {finding.title}
                    </h3>
                    <p className="text-xs text-slate-400 line-clamp-1">{finding.description}</p>
                  </div>

                  <div className="shrink-0 flex items-center gap-2">
                    <span className="text-xs font-medium text-slate-400 group-hover:text-slate-200">
                      Remediate →
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Target Profile & Discovery Metadata (1 col) */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-6 space-y-5">
          <div className="flex items-center justify-between">
            <h2 className="text-base font-semibold text-white">Target Telemetry</h2>
            <button
              onClick={onOpenReportModal}
              className="text-xs font-medium text-blue-400 hover:text-blue-300 flex items-center gap-1 transition-colors"
            >
              <Sparkles className="h-3.5 w-3.5 text-blue-400" />
              <span>Full AI Report</span>
            </button>
          </div>

          <div className="divide-y divide-slate-800/60 text-xs">
            <div className="py-2.5 flex justify-between">
              <span className="text-slate-400">Target Type</span>
              <span className="font-mono text-slate-200">{report.targetType}</span>
            </div>
            {report.metadata.statusCode && (
              <div className="py-2.5 flex justify-between">
                <span className="text-slate-400">HTTP Status</span>
                <span className="font-mono text-slate-200">{report.metadata.statusCode} OK</span>
              </div>
            )}
            <div className="py-2.5 flex justify-between">
              <span className="text-slate-400">Server Banner</span>
              <span className="font-mono text-slate-200 truncate max-w-[180px]">
                {report.metadata.serverBanner || 'Not disclosed'}
              </span>
            </div>
            {report.metadata.securityTxtFound !== undefined && (
              <div className="py-2.5 flex justify-between">
                <span className="text-slate-400">RFC 9116 security.txt</span>
                <span
                  className={`font-medium ${
                    report.metadata.securityTxtFound ? 'text-emerald-400' : 'text-slate-500'
                  }`}
                >
                  {report.metadata.securityTxtFound ? 'Present' : 'Not configured'}
                </span>
              </div>
            )}
            {report.metadata.robotsTxtFound !== undefined && (
              <div className="py-2.5 flex justify-between">
                <span className="text-slate-400">robots.txt</span>
                <span className="font-medium text-slate-200">
                  {report.metadata.robotsTxtFound ? 'Discovered' : 'Absent'}
                </span>
              </div>
            )}
            {report.metadata.linesOfCodeScanned !== undefined && (
              <div className="py-2.5 flex justify-between">
                <span className="text-slate-400">Lines Scanned</span>
                <span className="font-mono text-slate-200 tabular-nums">
                  {report.metadata.linesOfCodeScanned} lines
                </span>
              </div>
            )}
          </div>

          <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-4">
            <span className="text-xs font-semibold text-slate-300 block mb-1">Audit Summary</span>
            <p className="text-xs text-slate-400 leading-relaxed">
              {report.executiveSummary || 'Automated security scan completed successfully.'}
            </p>
          </div>

          <button
            onClick={onOpenReportModal}
            className="w-full rounded-lg bg-slate-800 px-4 py-2 text-xs font-semibold text-white hover:bg-slate-700 transition-colors flex items-center justify-center gap-2"
          >
            <span>View Executive Audit PDF/Print</span>
            <ArrowUpRight className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>
    </div>
  );
};
