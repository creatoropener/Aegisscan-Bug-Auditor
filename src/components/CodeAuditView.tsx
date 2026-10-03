import React, { useState } from 'react';
import { Play, Upload, Sparkles, Copy, Check, FileCode, ShieldAlert, CheckCircle2 } from 'lucide-react';
import { scanSourceCode } from '../services/api';
import { SecurityAuditReport, SecurityFinding } from '../types/security';

interface CodeAuditViewProps {
  onScanComplete: (report: SecurityAuditReport) => void;
  codeSnippets: Record<string, { filename: string; code: string }>;
  onSelectFinding: (id: string) => void;
  onAskCopilotForCode: (code: string) => void;
}

export const CodeAuditView: React.FC<CodeAuditViewProps> = ({
  onScanComplete,
  codeSnippets,
  onSelectFinding,
  onAskCopilotForCode,
}) => {
  const [filename, setFilename] = useState('src/auth/sessionHandler.ts');
  const [code, setCode] = useState(codeSnippets.vulnerable_api?.code || '');
  const [isScanning, setIsScanning] = useState(false);
  const [lastAuditReport, setLastAuditReport] = useState<SecurityAuditReport | null>(null);
  const [copied, setCopied] = useState(false);

  const handleRunScan = async () => {
    if (!code.trim()) return;
    setIsScanning(true);
    try {
      const report = await scanSourceCode(filename, code);
      setLastAuditReport(report);
      onScanComplete(report);
    } catch (err: any) {
      console.error('Scan error:', err);
    } finally {
      setIsScanning(false);
    }
  };

  const handleLoadSnippet = (key: string) => {
    const snip = codeSnippets[key];
    if (snip) {
      setFilename(snip.filename);
      setCode(snip.code);
    }
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      setFilename(file.name);
      const reader = new FileReader();
      reader.onload = (event) => {
        setCode((event.target?.result as string) || '');
      };
      reader.readAsText(file);
    }
  };

  const handleCopyCode = () => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const lines = code.split('\n');

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between border-b border-slate-800 pb-5">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white sm:text-2xl">
            Static Application Security Testing (SAST)
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Detect hardcoded credentials, XSS sinks, SQL injections, and vulnerable dependencies directly in code.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => onAskCopilotForCode(code)}
            className="flex items-center gap-1.5 rounded-lg border border-blue-500/30 bg-blue-950/40 px-3 py-1.5 text-xs font-medium text-blue-300 hover:bg-blue-900/40 transition-colors"
          >
            <Sparkles className="h-3.5 w-3.5 text-blue-400" />
            <span>AI Code Hardening</span>
          </button>

          <button
            onClick={handleRunScan}
            disabled={isScanning || !code.trim()}
            className="flex items-center gap-1.5 rounded-lg bg-blue-600 px-4 py-1.5 text-xs font-semibold text-white hover:bg-blue-500 transition-colors disabled:opacity-50"
          >
            <Play className="h-3.5 w-3.5" />
            <span>{isScanning ? 'Auditing Code...' : 'Audit Code Now'}</span>
          </button>
        </div>
      </div>

      {/* Editor & Controls */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Code Editor Panel (2 cols) */}
        <div className="lg:col-span-2 rounded-xl border border-slate-800 bg-slate-900/60 overflow-hidden flex flex-col">
          {/* File Tab Bar */}
          <div className="flex flex-wrap items-center justify-between border-b border-slate-800 px-4 py-2.5 bg-slate-950/80">
            <div className="flex items-center gap-2">
              <FileCode className="h-4 w-4 text-blue-400" />
              <input
                type="text"
                value={filename}
                onChange={(e) => setFilename(e.target.value)}
                className="bg-transparent font-mono text-xs text-white focus:outline-none border-b border-transparent focus:border-blue-500 px-1"
              />
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={handleCopyCode}
                className="text-xs text-slate-400 hover:text-white transition-colors flex items-center gap-1"
                title="Copy code"
              >
                {copied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
              </button>

              <label className="text-xs text-slate-400 hover:text-white transition-colors flex items-center gap-1 cursor-pointer">
                <Upload className="h-3.5 w-3.5" />
                <span className="hidden sm:inline">Upload</span>
                <input
                  type="file"
                  onChange={handleFileUpload}
                  className="hidden"
                  accept=".js,.ts,.tsx,.jsx,.json,.py,.go,.php,.env"
                />
              </label>
            </div>
          </div>

          {/* Quick Preset Selector */}
          <div className="flex items-center gap-2 px-4 py-2 border-b border-slate-800/80 bg-slate-950/40 text-[11px] text-slate-400">
            <span>Benchmark samples:</span>
            <button
              onClick={() => handleLoadSnippet('vulnerable_api')}
              className="hover:text-blue-400 transition-colors"
            >
              Express API (SQLi & Keys)
            </button>
            <span>·</span>
            <button
              onClick={() => handleLoadSnippet('package_manifest')}
              className="hover:text-blue-400 transition-colors"
            >
              Package.json (CVEs)
            </button>
          </div>

          {/* Code Textarea with line numbers */}
          <div className="flex-1 flex bg-slate-950 min-h-[420px] font-mono text-xs overflow-hidden">
            {/* Line numbers gutter */}
            <div className="w-12 py-3 text-right pr-3 select-none text-slate-600 bg-slate-950/90 border-r border-slate-900 font-mono text-[11px]">
              {lines.map((_, i) => (
                <div key={i} className="leading-6">
                  {i + 1}
                </div>
              ))}
            </div>

            {/* Code Input */}
            <textarea
              value={code}
              onChange={(e) => setCode(e.target.value)}
              className="flex-1 w-full bg-transparent p-3 text-emerald-300 font-mono text-xs leading-6 resize-none focus:outline-none"
              spellCheck={false}
            />
          </div>
        </div>

        {/* Live Findings Sidebar (1 col) */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 space-y-4 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-3">
              <h2 className="text-sm font-semibold text-white">SAST Findings</h2>
              {lastAuditReport && (
                <span className="font-mono text-xs text-slate-400">
                  Grade {lastAuditReport.scorecard.grade} ({lastAuditReport.scorecard.numericScore}/100)
                </span>
              )}
            </div>

            {!lastAuditReport ? (
              <div className="py-12 text-center text-slate-500 space-y-2">
                <FileCode className="mx-auto h-8 w-8 text-slate-600" />
                <p className="text-xs">Click "Audit Code Now" to scan the editor contents for vulnerabilities.</p>
              </div>
            ) : lastAuditReport.findings.length === 0 ? (
              <div className="py-12 text-center space-y-2">
                <CheckCircle2 className="mx-auto h-8 w-8 text-emerald-400" />
                <p className="text-xs font-semibold text-white">No Vulnerabilities Detected</p>
                <p className="text-[11px] text-slate-400">Code passed all SAST rules and secret leak checks.</p>
              </div>
            ) : (
              <div className="space-y-2 max-h-[380px] overflow-y-auto pr-1">
                {lastAuditReport.findings.map((f) => (
                  <div
                    key={f.id}
                    onClick={() => onSelectFinding(f.id)}
                    className="group rounded-lg border border-slate-800/80 bg-slate-950/70 p-3 hover:border-slate-700 hover:bg-slate-900 cursor-pointer transition-colors"
                  >
                    <div className="flex items-center justify-between mb-1">
                      <span
                        className={`text-[10px] font-mono font-semibold px-1.5 py-0.5 rounded ${
                          f.severity === 'CRITICAL'
                            ? 'bg-rose-950 text-rose-300'
                            : f.severity === 'HIGH'
                            ? 'bg-amber-950 text-amber-300'
                            : 'bg-yellow-950 text-yellow-300'
                        }`}
                      >
                        {f.severity}
                      </span>
                      {f.location?.line && (
                        <span className="font-mono text-[10px] text-slate-500">
                          Line {f.location.line}
                        </span>
                      )}
                    </div>
                    <h3 className="text-xs font-medium text-white group-hover:text-blue-400 transition-colors">
                      {f.title}
                    </h3>
                    <p className="text-[11px] text-slate-400 mt-1 line-clamp-1">{f.observedEvidence}</p>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="pt-3 border-t border-slate-800 text-xs text-slate-400">
            <span>Rules active: </span>
            <span className="text-slate-300">AWS/Stripe/JWT secrets, eval/innerHTML XSS sinks, SQLi concat, path traversal, CVE package database.</span>
          </div>
        </div>
      </div>
    </div>
  );
};
