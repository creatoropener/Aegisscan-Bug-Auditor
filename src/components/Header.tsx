import React from 'react';
import { ShieldCheck, Plus, Bot, FileText } from 'lucide-react';

export type NavTab = 'overview' | 'findings' | 'code-audit' | 'owasp' | 'export';

interface HeaderProps {
  activeTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
  onOpenNewScan: () => void;
  onToggleCopilot: () => void;
  copilotOpen: boolean;
  findingsCount: number;
}

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  onSelectTab,
  onOpenNewScan,
  onToggleCopilot,
  copilotOpen,
  findingsCount,
}) => {
  return (
    <header className="sticky top-0 z-40 w-full border-b border-slate-800 bg-slate-950/90 backdrop-blur-md">
      <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-4 sm:px-6 lg:px-8">
        {/* Zone 1: Single text wordmark */}
        <button
          onClick={() => onSelectTab('overview')}
          className="text-left font-semibold text-lg tracking-tight text-white hover:text-blue-400 transition-colors"
        >
          AegisScan
        </button>

        {/* Zone 2: 4-5 clean text navigation links */}
        <nav className="hidden md:flex items-center gap-7 text-sm font-medium text-slate-400">
          <button
            onClick={() => onSelectTab('overview')}
            className={`whitespace-nowrap transition-colors hover:text-white ${
              activeTab === 'overview' ? 'text-blue-400 font-semibold' : ''
            }`}
          >
            Dashboard
          </button>
          <button
            onClick={() => onSelectTab('findings')}
            className={`whitespace-nowrap transition-colors hover:text-white flex items-center gap-1.5 ${
              activeTab === 'findings' ? 'text-blue-400 font-semibold' : ''
            }`}
          >
            Findings
            {findingsCount > 0 && (
              <span className="font-mono text-xs text-slate-300">({findingsCount})</span>
            )}
          </button>
          <button
            onClick={() => onSelectTab('code-audit')}
            className={`whitespace-nowrap transition-colors hover:text-white ${
              activeTab === 'code-audit' ? 'text-blue-400 font-semibold' : ''
            }`}
          >
            Code Audit
          </button>
          <button
            onClick={() => onSelectTab('owasp')}
            className={`whitespace-nowrap transition-colors hover:text-white ${
              activeTab === 'owasp' ? 'text-blue-400 font-semibold' : ''
            }`}
          >
            OWASP Matrix
          </button>
          <button
            onClick={() => onSelectTab('export')}
            className={`whitespace-nowrap transition-colors hover:text-white flex items-center gap-1.5 ${
              activeTab === 'export' ? 'text-blue-400 font-semibold' : ''
            }`}
          >
            Audit Report
          </button>
        </nav>

        {/* Zone 3: 1-2 primary actions */}
        <div className="flex items-center gap-3">
          <button
            onClick={onToggleCopilot}
            className={`flex items-center gap-2 rounded-lg border px-3 py-1.5 text-xs font-medium transition-colors ${
              copilotOpen
                ? 'border-blue-500 bg-blue-500/10 text-blue-300'
                : 'border-slate-800 bg-slate-900 text-slate-300 hover:border-slate-700 hover:bg-slate-800'
            }`}
            title="Ask Security Co-Pilot"
          >
            <Bot className="h-4 w-4 text-blue-400" />
            <span className="hidden sm:inline">Security Co-Pilot</span>
          </button>

          <button
            onClick={onOpenNewScan}
            className="flex items-center gap-2 rounded-lg bg-blue-600 px-4 py-2 text-xs font-semibold text-white shadow-sm hover:bg-blue-500 transition-colors whitespace-nowrap"
          >
            <Plus className="h-4 w-4" />
            <span>New Scan</span>
          </button>
        </div>
      </div>
    </header>
  );
};
