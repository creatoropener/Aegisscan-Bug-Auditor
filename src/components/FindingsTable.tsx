import React, { useState, useMemo } from 'react';
import { SecurityFinding, SeverityLevel, FindingStatus } from '../types/security';
import { Search, ShieldAlert, AlertTriangle, Info, ChevronRight, CheckCircle2, SlidersHorizontal } from 'lucide-react';

interface FindingsTableProps {
  findings: SecurityFinding[];
  onSelectFinding: (id: string) => void;
  onUpdateFindingStatus: (id: string, status: FindingStatus) => void;
}

export const FindingsTable: React.FC<FindingsTableProps> = ({
  findings,
  onSelectFinding,
  onUpdateFindingStatus,
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState<SeverityLevel | 'ALL'>('ALL');
  const [selectedStatus, setSelectedStatus] = useState<FindingStatus | 'ALL'>('ALL');

  const filteredFindings = useMemo(() => {
    return findings.filter((f) => {
      const matchesSearch =
        searchQuery === '' ||
        f.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
        f.cweId.toLowerCase().includes(searchQuery.toLowerCase()) ||
        f.owaspCategory.toLowerCase().includes(searchQuery.toLowerCase()) ||
        f.description.toLowerCase().includes(searchQuery.toLowerCase());

      const matchesSeverity = selectedSeverity === 'ALL' || f.severity === selectedSeverity;
      const matchesStatus = selectedStatus === 'ALL' || f.status === selectedStatus;

      return matchesSearch && matchesSeverity && matchesStatus;
    });
  }, [findings, searchQuery, selectedSeverity, selectedStatus]);

  const severityCounts = useMemo(() => {
    return {
      ALL: findings.length,
      CRITICAL: findings.filter((f) => f.severity === 'CRITICAL').length,
      HIGH: findings.filter((f) => f.severity === 'HIGH').length,
      MEDIUM: findings.filter((f) => f.severity === 'MEDIUM').length,
      LOW: findings.filter((f) => f.severity === 'LOW').length,
      INFO: findings.filter((f) => f.severity === 'INFO').length,
    };
  }, [findings]);

  return (
    <div className="space-y-6">
      {/* Title & Filter Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between border-b border-slate-800 pb-5">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white sm:text-2xl">
            Vulnerability Findings & Defect Register
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Browse, triage, and track remediation across all identified security defects.
          </p>
        </div>

        {/* Search Input */}
        <div className="relative w-full sm:w-72">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-400" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search CVE, CWE, title..."
            className="w-full rounded-lg border border-slate-800 bg-slate-900/90 pl-9 pr-3 py-1.5 text-xs text-white placeholder-slate-500 focus:border-blue-500 focus:outline-none"
          />
        </div>
      </div>

      {/* Segmented Filter Controls */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        {/* Severity Tabs */}
        <div className="flex flex-wrap items-center gap-1 rounded-lg border border-slate-800 bg-slate-900/60 p-1">
          {(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const).map((sev) => {
            const count = severityCounts[sev];
            const isActive = selectedSeverity === sev;
            return (
              <button
                key={sev}
                onClick={() => setSelectedSeverity(sev)}
                className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap ${
                  isActive
                    ? 'bg-slate-800 text-white shadow-sm'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <span>{sev === 'ALL' ? 'All Findings' : sev}</span>
                <span className="font-mono text-[10px] text-slate-500">({count})</span>
              </button>
            );
          })}
        </div>

        {/* Status Dropdown Filter */}
        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-500 flex items-center gap-1">
            <SlidersHorizontal className="h-3 w-3" />
            Status:
          </span>
          <select
            value={selectedStatus}
            onChange={(e) => setSelectedStatus(e.target.value as any)}
            className="rounded-lg border border-slate-800 bg-slate-900 px-3 py-1 text-xs text-slate-300 focus:border-blue-500 focus:outline-none"
          >
            <option value="ALL">All Statuses</option>
            <option value="OPEN">Open</option>
            <option value="IN_REVIEW">In Review</option>
            <option value="FIXED">Fixed</option>
            <option value="ACCEPTED_RISK">Accepted Risk</option>
          </select>
        </div>
      </div>

      {/* Findings Table */}
      <div className="overflow-hidden rounded-xl border border-slate-800 bg-slate-900/40">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-slate-800 bg-slate-900/90 text-[11px] font-semibold text-slate-400">
              <tr>
                <th scope="col" className="py-3.5 pl-4 pr-3 sm:pl-6">
                  Severity / CVSS
                </th>
                <th scope="col" className="px-3 py-3.5">
                  Vulnerability Details
                </th>
                <th scope="col" className="px-3 py-3.5 hidden md:table-cell">
                  OWASP Category & CWE
                </th>
                <th scope="col" className="px-3 py-3.5">
                  Workflow Status
                </th>
                <th scope="col" className="py-3.5 pl-3 pr-4 sm:pr-6 text-right">
                  Action
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {filteredFindings.length === 0 ? (
                <tr>
                  <td colSpan={5} className="py-12 text-center text-slate-500">
                    No security findings matching current search and filter criteria.
                  </td>
                </tr>
              ) : (
                filteredFindings.map((finding) => (
                  <tr
                    key={finding.id}
                    className="hover:bg-slate-800/40 transition-colors group cursor-pointer"
                    onClick={() => onSelectFinding(finding.id)}
                  >
                    {/* Severity & Score */}
                    <td className="whitespace-nowrap py-4 pl-4 pr-3 sm:pl-6">
                      <div className="flex items-center gap-2">
                        <span
                          className={`font-mono text-xs font-semibold px-2 py-0.5 rounded ${
                            finding.severity === 'CRITICAL'
                              ? 'bg-rose-950/90 text-rose-300 border border-rose-800/40'
                              : finding.severity === 'HIGH'
                              ? 'bg-amber-950/90 text-amber-300 border border-amber-800/40'
                              : finding.severity === 'MEDIUM'
                              ? 'bg-yellow-950/70 text-yellow-300 border border-yellow-800/30'
                              : finding.severity === 'LOW'
                              ? 'bg-blue-950/60 text-blue-300 border border-blue-800/30'
                              : 'bg-slate-800 text-slate-300'
                          }`}
                        >
                          {finding.severity}
                        </span>
                        <span className="font-mono text-slate-400 tabular-nums">
                          {finding.cvssScore.toFixed(1)}
                        </span>
                      </div>
                    </td>

                    {/* Title & Evidence Description */}
                    <td className="px-3 py-4 max-w-md">
                      <div className="space-y-0.5">
                        <span className="font-medium text-white group-hover:text-blue-400 transition-colors block">
                          {finding.title}
                        </span>
                        <p className="text-[11px] text-slate-400 line-clamp-1">
                          {finding.description}
                        </p>
                      </div>
                    </td>

                    {/* OWASP & CWE */}
                    <td className="px-3 py-4 hidden md:table-cell">
                      <div className="space-y-0.5">
                        <span className="text-[11px] text-slate-300 block truncate max-w-xs">
                          {finding.owaspCategory}
                        </span>
                        <span className="font-mono text-[10px] text-slate-500">
                          {finding.cweId}
                        </span>
                      </div>
                    </td>

                    {/* Status Dropdown */}
                    <td
                      className="px-3 py-4 whitespace-nowrap"
                      onClick={(e) => e.stopPropagation()}
                    >
                      <select
                        value={finding.status}
                        onChange={(e) =>
                          onUpdateFindingStatus(finding.id, e.target.value as FindingStatus)
                        }
                        className={`rounded border px-2 py-1 text-[11px] font-medium focus:outline-none ${
                          finding.status === 'FIXED'
                            ? 'border-emerald-600/40 bg-emerald-950/60 text-emerald-300'
                            : finding.status === 'IN_REVIEW'
                            ? 'border-blue-600/40 bg-blue-950/60 text-blue-300'
                            : finding.status === 'ACCEPTED_RISK'
                            ? 'border-slate-700 bg-slate-800 text-slate-400'
                            : 'border-slate-800 bg-slate-900 text-slate-300'
                        }`}
                      >
                        <option value="OPEN">Open</option>
                        <option value="IN_REVIEW">In Review</option>
                        <option value="FIXED">Fixed</option>
                        <option value="ACCEPTED_RISK">Accepted Risk</option>
                        <option value="FALSE_POSITIVE">False Positive</option>
                      </select>
                    </td>

                    {/* Action */}
                    <td className="py-4 pl-3 pr-4 sm:pr-6 text-right whitespace-nowrap">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectFinding(finding.id);
                        }}
                        className="inline-flex items-center gap-1 text-slate-400 hover:text-white transition-colors"
                      >
                        <span>Inspect</span>
                        <ChevronRight className="h-3.5 w-3.5" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
