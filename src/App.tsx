/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from 'react';
import { Header, NavTab } from './components/Header';
import { DashboardOverview } from './components/DashboardOverview';
import { FindingsTable } from './components/FindingsTable';
import { FindingDetailModal } from './components/FindingDetailModal';
import { ScanModal } from './components/ScanModal';
import { CodeAuditView } from './components/CodeAuditView';
import { OwaspMatrixView } from './components/OwaspMatrixView';
import { ExecutiveReportModal } from './components/ExecutiveReportModal';
import { AiCopilotDrawer } from './components/AiCopilotDrawer';
import {
  SecurityAuditReport,
  SecurityFinding,
  FindingStatus,
  PreloadedDemoScenario,
  OwaspCategory,
} from './types/security';
import { fetchScenarios, fetchScenarioReport } from './services/api';
import { Loader2 } from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState<NavTab>('overview');
  const [currentReport, setCurrentReport] = useState<SecurityAuditReport | null>(null);
  const [scenarios, setScenarios] = useState<PreloadedDemoScenario[]>([]);
  const [codeSnippets, setCodeSnippets] = useState<Record<string, { filename: string; code: string }>>({});
  const [isLoadingInitial, setIsLoadingInitial] = useState(true);

  // Modals & Panels
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  const [isScanModalOpen, setIsScanModalOpen] = useState(false);
  const [isReportModalOpen, setIsReportModalOpen] = useState(false);
  const [isCopilotOpen, setIsCopilotOpen] = useState(false);
  const [copilotFinding, setCopilotFinding] = useState<SecurityFinding | null>(null);

  // Load scenarios on mount
  useEffect(() => {
    async function initData() {
      try {
        const data = await fetchScenarios();
        setScenarios(data.scenarios);
        setCodeSnippets(data.codeSnippets);

        // Preload default scenario: 'demo-ecommerce-vulnerable'
        if (data.scenarios.length > 0) {
          const defaultReport = await fetchScenarioReport(data.scenarios[0].id);
          setCurrentReport(defaultReport);
        }
      } catch (err) {
        console.error('Initialization error:', err);
      } finally {
        setIsLoadingInitial(false);
      }
    }
    initData();
  }, []);

  const handleSelectScenario = async (id: string) => {
    try {
      const rep = await fetchScenarioReport(id);
      setCurrentReport(rep);
    } catch (err) {
      console.error('Error loading scenario:', err);
    }
  };

  const handleUpdateFindingStatus = (id: string, newStatus: FindingStatus) => {
    if (!currentReport) return;
    const updatedFindings = currentReport.findings.map((f) =>
      f.id === id ? { ...f, status: newStatus } : f
    );
    setCurrentReport({
      ...currentReport,
      findings: updatedFindings,
    });
  };

  const handleScanComplete = (newReport: SecurityAuditReport) => {
    setCurrentReport(newReport);
    setActiveTab('overview');
  };

  const handleOpenCopilotWithFinding = (finding: SecurityFinding) => {
    setCopilotFinding(finding);
    setIsCopilotOpen(true);
  };

  const handleAskCopilotForCode = (code: string) => {
    setCopilotFinding(null);
    setIsCopilotOpen(true);
  };

  const handleFilterOwaspFindings = (category: OwaspCategory) => {
    setActiveTab('findings');
  };

  const selectedFinding = currentReport?.findings.find((f) => f.id === selectedFindingId) || null;

  if (isLoadingInitial && !currentReport) {
    return (
      <div className="min-h-screen bg-slate-950 flex flex-col items-center justify-center text-slate-400 gap-3">
        <Loader2 className="h-8 w-8 animate-spin text-blue-500" />
        <span className="text-xs font-mono">Initializing AegisScan Security Engine...</span>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans">
      {/* 3-Zone Clean Header */}
      <Header
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        onOpenNewScan={() => setIsScanModalOpen(true)}
        onToggleCopilot={() => setIsCopilotOpen(!isCopilotOpen)}
        copilotOpen={isCopilotOpen}
        findingsCount={currentReport?.findings.length || 0}
      />

      {/* Main Content Area */}
      <main className="flex-1 mx-auto w-full max-w-7xl px-4 sm:px-6 lg:px-8 py-8">
        {currentReport && activeTab === 'overview' && (
          <DashboardOverview
            report={currentReport}
            scenarios={scenarios}
            onSelectScenario={handleSelectScenario}
            onViewFindings={() => setActiveTab('findings')}
            onOpenReportModal={() => setIsReportModalOpen(true)}
            onOpenNewScan={() => setIsScanModalOpen(true)}
            onSelectFinding={(id) => setSelectedFindingId(id)}
          />
        )}

        {currentReport && activeTab === 'findings' && (
          <FindingsTable
            findings={currentReport.findings}
            onSelectFinding={(id) => setSelectedFindingId(id)}
            onUpdateFindingStatus={handleUpdateFindingStatus}
          />
        )}

        {activeTab === 'code-audit' && (
          <CodeAuditView
            onScanComplete={handleScanComplete}
            codeSnippets={codeSnippets}
            onSelectFinding={(id) => setSelectedFindingId(id)}
            onAskCopilotForCode={handleAskCopilotForCode}
          />
        )}

        {currentReport && activeTab === 'owasp' && (
          <OwaspMatrixView
            report={currentReport}
            onFilterOwaspFindings={handleFilterOwaspFindings}
          />
        )}

        {currentReport && activeTab === 'export' && (
          <div className="space-y-6">
            <div className="flex items-center justify-between border-b border-slate-800 pb-5">
              <div>
                <h1 className="text-xl font-bold tracking-tight text-white sm:text-2xl">
                  Security Assessment & Audit Reports
                </h1>
                <p className="text-xs text-slate-400 mt-1">
                  Generate formal executive summaries, compliance documentation, and exportable reports.
                </p>
              </div>
              <button
                onClick={() => setIsReportModalOpen(true)}
                className="rounded-lg bg-blue-600 px-4 py-2 text-xs font-semibold text-white hover:bg-blue-500 transition-colors"
              >
                Open Full Document Exporter
              </button>
            </div>

            <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-8 text-center space-y-4">
              <div className="max-w-md mx-auto space-y-2">
                <span className="font-mono text-xs text-blue-400">
                  Target: {currentReport.target}
                </span>
                <h2 className="text-lg font-bold text-white">Ready for Export & Distribution</h2>
                <p className="text-xs text-slate-400">
                  Generate print-ready executive PDFs, SARIF/JSON files for CI/CD gates, or GitHub-flavored Markdown summaries.
                </p>
              </div>
              <button
                onClick={() => setIsReportModalOpen(true)}
                className="rounded-lg bg-slate-800 px-5 py-2.5 text-xs font-semibold text-white hover:bg-slate-700 transition-colors"
              >
                Preview & Export Document
              </button>
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 py-6 text-center text-xs text-slate-500">
        <div className="mx-auto max-w-7xl px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
          <span>AegisScan Vulnerability & Posture Auditor</span>
          <span className="font-mono text-[11px]">OWASP Top 10 · CWE / CVE · CVSS v3.1</span>
        </div>
      </footer>

      {/* Finding Detail Modal */}
      {selectedFinding && (
        <FindingDetailModal
          finding={selectedFinding}
          onClose={() => setSelectedFindingId(null)}
          onUpdateStatus={handleUpdateFindingStatus}
          onAskCopilot={handleOpenCopilotWithFinding}
        />
      )}

      {/* Launch New Scan Modal */}
      <ScanModal
        isOpen={isScanModalOpen}
        onClose={() => setIsScanModalOpen(false)}
        onScanComplete={handleScanComplete}
        codeSnippets={codeSnippets}
      />

      {/* Executive Report Exporter Modal */}
      {isReportModalOpen && currentReport && (
        <ExecutiveReportModal
          report={currentReport}
          onClose={() => setIsReportModalOpen(false)}
        />
      )}

      {/* Interactive AI Co-Pilot Drawer */}
      <AiCopilotDrawer
        isOpen={isCopilotOpen}
        onClose={() => setIsCopilotOpen(false)}
        activeFinding={copilotFinding}
        currentReport={currentReport || undefined}
      />
    </div>
  );
}
