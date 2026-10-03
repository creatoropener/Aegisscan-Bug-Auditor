import React, { useState } from 'react';
import { X, Globe, Code2, Play, Upload, Shield, Loader2, Sparkles, CheckCircle2 } from 'lucide-react';
import { scanSiteUrl, scanSourceCode } from '../services/api';
import { SecurityAuditReport } from '../types/security';

interface ScanModalProps {
  isOpen: boolean;
  onClose: () => void;
  onScanComplete: (report: SecurityAuditReport) => void;
  codeSnippets: Record<string, { filename: string; code: string }>;
}

export const ScanModal: React.FC<ScanModalProps> = ({
  isOpen,
  onClose,
  onScanComplete,
  codeSnippets,
}) => {
  const [scanType, setScanType] = useState<'SITE_URL' | 'SOURCE_CODE'>('SITE_URL');
  const [urlInput, setUrlInput] = useState('');
  const [checkRobots, setCheckRobots] = useState(true);
  const [checkSecurityTxt, setCheckSecurityTxt] = useState(true);

  // SAST state
  const [codeFilename, setCodeFilename] = useState('userController.ts');
  const [codeContent, setCodeContent] = useState('');

  // Scanning state
  const [isLoading, setIsLoading] = useState(false);
  const [scanStep, setScanStep] = useState('');
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleStartUrlScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!urlInput.trim()) {
      setErrorMessage('Please enter a target URL to scan.');
      return;
    }

    setErrorMessage(null);
    setIsLoading(true);
    setScanStep('Connecting to endpoint and negotiating TLS handshake...');

    try {
      setTimeout(() => setScanStep('Analyzing HTTP security headers (HSTS, CSP, X-Frame-Options)...'), 500);
      setTimeout(() => setScanStep('Inspecting cookie security flags & information disclosure...'), 1200);
      setTimeout(() => setScanStep('Evaluating OWASP Top 10 risk vectors & CVSS scores...'), 1800);

      const report = await scanSiteUrl(urlInput.trim(), {
        checkRobots,
        checkSecurityTxt,
        deepHtml: true,
      });

      setIsLoading(false);
      onScanComplete(report);
      onClose();
    } catch (err: any) {
      setIsLoading(false);
      setErrorMessage(err.message || 'Failed to complete security scan.');
    }
  };

  const handleStartCodeScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!codeContent.trim()) {
      setErrorMessage('Please provide source code or package manifest to scan.');
      return;
    }

    setErrorMessage(null);
    setIsLoading(true);
    setScanStep('Parsing syntax tokens & regex rule matrices...');

    try {
      setTimeout(() => setScanStep('Auditing code sinks for XSS, SQLi, and secret leaks...'), 300);
      setTimeout(() => setScanStep('Cross-referencing CVE database and computing CVSS scores...'), 700);

      const report = await scanSourceCode(codeFilename, codeContent);
      setIsLoading(false);
      onScanComplete(report);
      onClose();
    } catch (err: any) {
      setIsLoading(false);
      setErrorMessage(err.message || 'Failed to complete code security scan.');
    }
  };

  const handleLoadSnippet = (key: string) => {
    const snip = codeSnippets[key];
    if (snip) {
      setCodeFilename(snip.filename);
      setCodeContent(snip.code);
    }
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      setCodeFilename(file.name);
      const reader = new FileReader();
      reader.onload = (event) => {
        setCodeContent((event.target?.result as string) || '');
      };
      reader.readAsText(file);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/85 backdrop-blur-sm overflow-y-auto">
      <div className="relative w-full max-w-2xl rounded-xl border border-slate-800 bg-slate-900 shadow-2xl overflow-hidden my-6">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-800 px-6 py-4 bg-slate-900/90">
          <div>
            <h2 className="text-lg font-bold text-white tracking-tight">Initiate Security Audit</h2>
            <p className="text-xs text-slate-400">
              Run automated defensive vulnerability assessment on web sites or source code
            </p>
          </div>
          <button
            onClick={onClose}
            disabled={isLoading}
            className="rounded-lg p-1.5 text-slate-400 hover:bg-slate-800 hover:text-white transition-colors"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Modal Content */}
        <div className="p-6 space-y-6">
          {/* Mode Switcher */}
          <div className="grid grid-cols-2 gap-2 rounded-lg border border-slate-800 bg-slate-950 p-1">
            <button
              type="button"
              onClick={() => {
                setScanType('SITE_URL');
                setErrorMessage(null);
              }}
              className={`flex items-center justify-center gap-2 rounded-md py-2 text-xs font-semibold transition-colors ${
                scanType === 'SITE_URL'
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <Globe className="h-4 w-4" />
              <span>Live Website Scanner (DAST)</span>
            </button>

            <button
              type="button"
              onClick={() => {
                setScanType('SOURCE_CODE');
                setErrorMessage(null);
              }}
              className={`flex items-center justify-center gap-2 rounded-md py-2 text-xs font-semibold transition-colors ${
                scanType === 'SOURCE_CODE'
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <Code2 className="h-4 w-4" />
              <span>Source Code & Manifest (SAST)</span>
            </button>
          </div>

          {errorMessage && (
            <div className="rounded-lg border border-rose-900/50 bg-rose-950/40 p-3 text-xs text-rose-300">
              {errorMessage}
            </div>
          )}

          {isLoading ? (
            <div className="py-12 flex flex-col items-center justify-center text-center space-y-4">
              <Loader2 className="h-8 w-8 animate-spin text-blue-500" />
              <div className="space-y-1">
                <span className="text-sm font-semibold text-white">Running Automated Scan</span>
                <p className="text-xs text-slate-400 font-mono">{scanStep}</p>
              </div>
            </div>
          ) : scanType === 'SITE_URL' ? (
            /* DAST Form */
            <form onSubmit={handleStartUrlScan} className="space-y-5">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1.5">
                  Target Domain or URL
                </label>
                <div className="relative">
                  <Globe className="absolute left-3 top-2.5 h-4 w-4 text-slate-400" />
                  <input
                    type="text"
                    value={urlInput}
                    onChange={(e) => setUrlInput(e.target.value)}
                    placeholder="https://example.com or staging.myapp.io"
                    className="w-full rounded-lg border border-slate-700 bg-slate-950 pl-9 pr-3 py-2 text-xs text-white placeholder-slate-500 focus:border-blue-500 focus:outline-none"
                    autoFocus
                  />
                </div>
                <p className="text-[11px] text-slate-500 mt-1">
                  Passive non-intrusive scan: audits transport encryption, HTTP headers, cookies, and public metadata.
                </p>
              </div>

              {/* Discovery Options */}
              <div className="space-y-2 border-t border-slate-800 pt-4">
                <span className="text-xs font-medium text-slate-300">Discovery Checks:</span>
                <div className="flex flex-col gap-2">
                  <label className="flex items-center gap-2 cursor-pointer text-xs text-slate-300">
                    <input
                      type="checkbox"
                      checked={checkSecurityTxt}
                      onChange={(e) => setCheckSecurityTxt(e.target.checked)}
                      className="rounded border-slate-700 bg-slate-950 text-blue-600 focus:ring-0"
                    />
                    <span>Verify RFC 9116 security.txt policy (/.well-known/security.txt)</span>
                  </label>
                  <label className="flex items-center gap-2 cursor-pointer text-xs text-slate-300">
                    <input
                      type="checkbox"
                      checked={checkRobots}
                      onChange={(e) => setCheckRobots(e.target.checked)}
                      className="rounded border-slate-700 bg-slate-950 text-blue-600 focus:ring-0"
                    />
                    <span>Inspect robots.txt for sensitive path disclosures</span>
                  </label>
                </div>
              </div>

              {/* Quick Preset Buttons */}
              <div className="border-t border-slate-800 pt-4">
                <span className="text-[11px] text-slate-400 block mb-2">Test with common domains:</span>
                <div className="flex flex-wrap gap-2">
                  {['https://github.com', 'https://google.com', 'https://owasp.org'].map((preset) => (
                    <button
                      key={preset}
                      type="button"
                      onClick={() => setUrlInput(preset)}
                      className="rounded border border-slate-800 bg-slate-950 px-2.5 py-1 text-xs text-slate-300 hover:border-slate-700 hover:text-white transition-colors"
                    >
                      {preset.replace('https://', '')}
                    </button>
                  ))}
                </div>
              </div>

              <div className="flex justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={onClose}
                  className="rounded-lg border border-slate-800 px-4 py-2 text-xs font-medium text-slate-300 hover:bg-slate-800 transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="flex items-center gap-2 rounded-lg bg-blue-600 px-5 py-2 text-xs font-semibold text-white shadow-sm hover:bg-blue-500 transition-colors"
                >
                  <Play className="h-3.5 w-3.5" />
                  <span>Start Live Scan</span>
                </button>
              </div>
            </form>
          ) : (
            /* SAST Form */
            <form onSubmit={handleStartCodeScan} className="space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div className="w-full sm:w-1/2">
                  <label className="block text-xs font-medium text-slate-300 mb-1">
                    Filename / Identifier
                  </label>
                  <input
                    type="text"
                    value={codeFilename}
                    onChange={(e) => setCodeFilename(e.target.value)}
                    className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 text-xs text-white focus:border-blue-500 focus:outline-none"
                  />
                </div>

                <div className="flex items-center gap-2 pt-4 sm:pt-0">
                  <label className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 text-xs text-slate-300 hover:border-slate-600 cursor-pointer transition-colors">
                    <Upload className="h-3.5 w-3.5" />
                    <span>Upload File</span>
                    <input
                      type="file"
                      onChange={handleFileUpload}
                      className="hidden"
                      accept=".js,.ts,.tsx,.jsx,.json,.py,.go,.php,.env"
                    />
                  </label>
                </div>
              </div>

              {/* Sample Preset Loaders */}
              <div className="flex items-center gap-2">
                <span className="text-[11px] text-slate-400">Load vulnerable template:</span>
                <button
                  type="button"
                  onClick={() => handleLoadSnippet('vulnerable_api')}
                  className="rounded border border-slate-800 bg-slate-950 px-2 py-0.5 text-[11px] text-blue-400 hover:bg-slate-800 transition-colors"
                >
                  Node.js API (SQLi & Keys)
                </button>
                <button
                  type="button"
                  onClick={() => handleLoadSnippet('package_manifest')}
                  className="rounded border border-slate-800 bg-slate-950 px-2 py-0.5 text-[11px] text-blue-400 hover:bg-slate-800 transition-colors"
                >
                  Package.json (Known CVEs)
                </button>
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Code Snippet to Analyze
                </label>
                <textarea
                  value={codeContent}
                  onChange={(e) => setCodeContent(e.target.value)}
                  rows={8}
                  placeholder="// Paste JavaScript, TypeScript, Python, or package.json code here..."
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 p-3 font-mono text-xs text-emerald-400 focus:border-blue-500 focus:outline-none leading-relaxed"
                />
              </div>

              <div className="flex justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={onClose}
                  className="rounded-lg border border-slate-800 px-4 py-2 text-xs font-medium text-slate-300 hover:bg-slate-800 transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="flex items-center gap-2 rounded-lg bg-blue-600 px-5 py-2 text-xs font-semibold text-white shadow-sm hover:bg-blue-500 transition-colors"
                >
                  <Play className="h-3.5 w-3.5" />
                  <span>Analyze Code</span>
                </button>
              </div>
            </form>
          )}
        </div>
      </div>
    </div>
  );
};
