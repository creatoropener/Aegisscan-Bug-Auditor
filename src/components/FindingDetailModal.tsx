import React, { useState } from 'react';
import { SecurityFinding, FindingStatus } from '../types/security';
import { X, Copy, Check, ExternalLink, Bot, Shield, Terminal, ArrowRight } from 'lucide-react';

interface FindingDetailModalProps {
  finding: SecurityFinding | null;
  onClose: () => void;
  onUpdateStatus: (id: string, status: FindingStatus) => void;
  onAskCopilot: (finding: SecurityFinding) => void;
}

export const FindingDetailModal: React.FC<FindingDetailModalProps> = ({
  finding,
  onClose,
  onUpdateStatus,
  onAskCopilot,
}) => {
  const [copiedSnippetIndex, setCopiedSnippetIndex] = useState<number | null>(null);
  const [activeSnippetTab, setActiveSnippetTab] = useState(0);

  if (!finding) return null;

  const handleCopyCode = (code: string, index: number) => {
    navigator.clipboard.writeText(code);
    setCopiedSnippetIndex(index);
    setTimeout(() => setCopiedSnippetIndex(null), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm overflow-y-auto">
      <div className="relative w-full max-w-3xl rounded-xl border border-slate-800 bg-slate-900 shadow-2xl overflow-hidden my-8">
        {/* Top Header */}
        <div className="flex items-start justify-between border-b border-slate-800 p-6 bg-slate-900/90">
          <div className="space-y-1.5 pr-8">
            <div className="flex flex-wrap items-center gap-2">
              <span
                className={`font-mono text-xs font-semibold px-2 py-0.5 rounded ${
                  finding.severity === 'CRITICAL'
                    ? 'bg-rose-950 text-rose-300 border border-rose-800/60'
                    : finding.severity === 'HIGH'
                    ? 'bg-amber-950 text-amber-300 border border-amber-800/60'
                    : finding.severity === 'MEDIUM'
                    ? 'bg-yellow-950 text-yellow-300 border border-yellow-800/40'
                    : 'bg-blue-950 text-blue-300 border border-blue-800/40'
                }`}
              >
                {finding.severity}
              </span>
              <span className="font-mono text-xs text-slate-300 tabular-nums">
                CVSS {finding.cvssScore.toFixed(1)}
              </span>
              <span className="text-xs text-slate-500">·</span>
              <span className="text-xs text-slate-400 font-mono">{finding.cweId}</span>
              <span className="text-xs text-slate-500">·</span>
              <span className="text-xs text-slate-400">{finding.category}</span>
            </div>
            <h2 className="text-xl font-bold text-white tracking-tight">{finding.title}</h2>
          </div>

          <button
            onClick={onClose}
            className="rounded-lg p-1.5 text-slate-400 hover:bg-slate-800 hover:text-white transition-colors"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 space-y-6 max-h-[75vh] overflow-y-auto">
          {/* Status & Quick Action Bar */}
          <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-slate-800 bg-slate-950/60 p-3">
            <div className="flex items-center gap-2">
              <span className="text-xs text-slate-400">Finding Status:</span>
              <select
                value={finding.status}
                onChange={(e) => onUpdateStatus(finding.id, e.target.value as FindingStatus)}
                className="rounded border border-slate-700 bg-slate-900 px-3 py-1 text-xs text-white focus:outline-none"
              >
                <option value="OPEN">Open (Unresolved)</option>
                <option value="IN_REVIEW">In Review / In Progress</option>
                <option value="FIXED">Mark as Remediated (Fixed)</option>
                <option value="ACCEPTED_RISK">Accepted Business Risk</option>
                <option value="FALSE_POSITIVE">False Positive</option>
              </select>
            </div>

            <button
              onClick={() => {
                onClose();
                onAskCopilot(finding);
              }}
              className="flex items-center gap-1.5 rounded-lg border border-blue-500/30 bg-blue-950/40 px-3 py-1 text-xs font-medium text-blue-300 hover:bg-blue-900/40 transition-colors"
            >
              <Bot className="h-3.5 w-3.5 text-blue-400" />
              <span>Ask AI Co-Pilot to Fix</span>
            </button>
          </div>

          {/* Description & Impact */}
          <div className="space-y-4">
            <div>
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                Technical Vulnerability Overview
              </h3>
              <p className="text-xs leading-relaxed text-slate-300">{finding.description}</p>
            </div>

            <div className="rounded-lg border border-rose-950/60 bg-rose-950/20 p-4">
              <h3 className="text-xs font-semibold text-rose-300 mb-1">
                Threat Scenario & Business Impact
              </h3>
              <p className="text-xs text-rose-200/90 leading-relaxed">{finding.impact}</p>
            </div>
          </div>

          {/* Observed Evidence */}
          <div>
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
              Observed Scanner Evidence
            </h3>
            <div className="rounded-lg border border-slate-800 bg-slate-950 p-3 font-mono text-xs text-slate-300 overflow-x-auto">
              {finding.location?.codeSnippet ? (
                <div className="space-y-1">
                  <div className="text-[11px] text-slate-500">
                    File: {finding.location.file} (Line {finding.location.line})
                  </div>
                  <div className="text-rose-400 bg-rose-950/30 px-2 py-1 rounded">
                    {finding.location.codeSnippet}
                  </div>
                </div>
              ) : (
                <code>{finding.observedEvidence}</code>
              )}
            </div>
          </div>

          {/* Remediation Guidance */}
          <div className="space-y-3">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              Prescribed Remediation
            </h3>
            <p className="text-xs text-slate-300 leading-relaxed">{finding.recommendedFix}</p>

            {/* Code Snippets if available */}
            {finding.remediationSnippets && finding.remediationSnippets.length > 0 && (
              <div className="rounded-lg border border-slate-800 bg-slate-950 overflow-hidden">
                <div className="flex items-center justify-between border-b border-slate-800 px-3 py-2 bg-slate-900/60">
                  <div className="flex items-center gap-2">
                    <Terminal className="h-3.5 w-3.5 text-slate-400" />
                    <span className="text-xs font-medium text-slate-300">
                      Remediation Code Patch
                    </span>
                    <div className="flex items-center gap-1 ml-3">
                      {finding.remediationSnippets.map((snip, idx) => (
                        <button
                          key={snip.technology}
                          onClick={() => setActiveSnippetTab(idx)}
                          className={`rounded px-2 py-0.5 text-[11px] transition-colors ${
                            activeSnippetTab === idx
                              ? 'bg-slate-800 text-white font-medium'
                              : 'text-slate-400 hover:text-slate-200'
                          }`}
                        >
                          {snip.technology}
                        </button>
                      ))}
                    </div>
                  </div>

                  <button
                    onClick={() =>
                      handleCopyCode(
                        finding.remediationSnippets![activeSnippetTab].code,
                        activeSnippetTab
                      )
                    }
                    className="flex items-center gap-1 text-[11px] text-slate-400 hover:text-white transition-colors"
                  >
                    {copiedSnippetIndex === activeSnippetTab ? (
                      <>
                        <Check className="h-3 w-3 text-emerald-400" />
                        <span className="text-emerald-400">Copied</span>
                      </>
                    ) : (
                      <>
                        <Copy className="h-3 w-3" />
                        <span>Copy</span>
                      </>
                    )}
                  </button>
                </div>

                <div className="p-4 overflow-x-auto">
                  <pre className="font-mono text-xs text-emerald-400 leading-relaxed">
                    {finding.remediationSnippets[activeSnippetTab].code}
                  </pre>
                </div>
              </div>
            )}
          </div>

          {/* Standards & External References */}
          {finding.references && finding.references.length > 0 && (
            <div className="border-t border-slate-800 pt-4">
              <span className="text-[11px] text-slate-400 font-semibold block mb-2">
                Standards & Advisory References:
              </span>
              <ul className="space-y-1">
                {finding.references.map((ref, idx) => (
                  <li key={idx}>
                    <a
                      href={ref}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 text-xs text-blue-400 hover:underline"
                    >
                      <span>{ref}</span>
                      <ExternalLink className="h-3 w-3" />
                    </a>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="flex items-center justify-between border-t border-slate-800 bg-slate-900/90 px-6 py-4">
          <div className="text-[11px] text-slate-500 font-mono">
            {finding.owaspCategory}
          </div>
          <button
            onClick={onClose}
            className="rounded-lg bg-slate-800 px-4 py-2 text-xs font-semibold text-white hover:bg-slate-700 transition-colors"
          >
            Close Inspector
          </button>
        </div>
      </div>
    </div>
  );
};
