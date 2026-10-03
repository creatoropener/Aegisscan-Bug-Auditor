import React, { useState, useRef, useEffect } from 'react';
import { Bot, Send, X, Sparkles, Terminal, Shield, Loader2, ArrowRight } from 'lucide-react';
import { askAiCopilot } from '../services/api';
import { SecurityFinding, SecurityAuditReport } from '../types/security';

interface AiCopilotDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  activeFinding?: SecurityFinding | null;
  currentReport?: SecurityAuditReport;
}

interface ChatMessage {
  id: string;
  sender: 'user' | 'copilot';
  text: string;
  timestamp: string;
}

export const AiCopilotDrawer: React.FC<AiCopilotDrawerProps> = ({
  isOpen,
  onClose,
  activeFinding,
  currentReport,
}) => {
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: 'init-1',
      sender: 'copilot',
      text: 'Hello, I am AegisScan Security Co-Pilot. I can help you analyze vulnerabilities, generate strict security headers (CSP, HSTS), sanitize code sinks, or map findings to OWASP ASVS benchmarks. What can I help you harden today?',
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    },
  ]);
  const [inputText, setInputText] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (activeFinding) {
      setMessages((prev) => [
        ...prev,
        {
          id: `finding-${Date.now()}`,
          sender: 'copilot',
          text: `I've loaded context for finding: **${activeFinding.title}** (${activeFinding.severity}, CVSS ${activeFinding.cvssScore}). Ask me how to fix this for your framework, generate configuration directives, or assess the exploit scenario.`,
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        },
      ]);
    }
  }, [activeFinding?.id]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  if (!isOpen) return null;

  const handleSendMessage = async (customMessage?: string) => {
    const textToSend = customMessage || inputText;
    if (!textToSend.trim() || isSubmitting) return;

    const userMsg: ChatMessage = {
      id: `user-${Date.now()}`,
      sender: 'user',
      text: textToSend.trim(),
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    };

    setMessages((prev) => [...prev, userMsg]);
    setInputText('');
    setIsSubmitting(true);

    try {
      const reply = await askAiCopilot(
        textToSend.trim(),
        activeFinding || undefined,
        currentReport
      );

      const copilotMsg: ChatMessage = {
        id: `copilot-${Date.now()}`,
        sender: 'copilot',
        text: reply,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      };
      setMessages((prev) => [...prev, copilotMsg]);
    } catch (err: any) {
      setMessages((prev) => [
        ...prev,
        {
          id: `err-${Date.now()}`,
          sender: 'copilot',
          text: 'Encountered a problem generating guidance. Please verify your connection and try again.',
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        },
      ]);
    } finally {
      setIsSubmitting(false);
    }
  };

  const samplePrompts = [
    'How do I configure a strict Content-Security-Policy with nonces?',
    'What is the remediation for SQL injection in Node.js pg?',
    'Explain how to safely deploy HSTS preload to avoid locking out subdomains.',
    'How do I prevent DOM-based XSS when rendering user bios?',
  ];

  return (
    <div className="fixed inset-y-0 right-0 z-50 flex w-full max-w-md flex-col border-l border-slate-800 bg-slate-950 shadow-2xl">
      {/* Drawer Header */}
      <div className="flex items-center justify-between border-b border-slate-800 px-5 py-4 bg-slate-900/90">
        <div className="flex items-center gap-2">
          <Bot className="h-5 w-5 text-blue-400" />
          <div>
            <h2 className="text-sm font-bold text-white tracking-tight">Security Co-Pilot</h2>
            <p className="text-[11px] text-slate-400">Powered by Gemini AppSec Defense</p>
          </div>
        </div>

        <button
          onClick={onClose}
          className="rounded-lg p-1.5 text-slate-400 hover:bg-slate-800 hover:text-white transition-colors"
        >
          <X className="h-4 w-4" />
        </button>
      </div>

      {/* Active Context Banner */}
      {activeFinding && (
        <div className="border-b border-blue-900/40 bg-blue-950/20 px-4 py-2 text-xs flex items-center justify-between">
          <div className="flex items-center gap-1.5 truncate pr-2">
            <span className="text-blue-400 font-medium">Context:</span>
            <span className="text-slate-300 truncate">{activeFinding.title}</span>
          </div>
          <span className="font-mono text-[10px] text-blue-300 shrink-0">
            {activeFinding.cweId}
          </span>
        </div>
      )}

      {/* Chat Messages */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {messages.map((msg) => (
          <div
            key={msg.id}
            className={`flex flex-col ${
              msg.sender === 'user' ? 'items-end' : 'items-start'
            }`}
          >
            <div
              className={`rounded-xl px-4 py-3 text-xs leading-relaxed max-w-[90%] ${
                msg.sender === 'user'
                  ? 'bg-blue-600 text-white'
                  : 'border border-slate-800 bg-slate-900 text-slate-200'
              }`}
            >
              <div className="whitespace-pre-wrap font-sans">{msg.text}</div>
            </div>
            <span className="text-[10px] text-slate-500 mt-1 px-1">{msg.timestamp}</span>
          </div>
        ))}

        {isSubmitting && (
          <div className="flex items-center gap-2 text-xs text-slate-400 p-2">
            <Loader2 className="h-4 w-4 animate-spin text-blue-400" />
            <span>Consulting AppSec defense models...</span>
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Quick Prompts */}
      <div className="border-t border-slate-800/80 p-3 bg-slate-900/40 space-y-2">
        <span className="text-[10px] uppercase font-semibold tracking-wider text-slate-500 block">
          Suggested Topics:
        </span>
        <div className="flex flex-wrap gap-1.5 max-h-24 overflow-y-auto">
          {samplePrompts.map((prompt, i) => (
            <button
              key={i}
              onClick={() => handleSendMessage(prompt)}
              disabled={isSubmitting}
              className="rounded border border-slate-800 bg-slate-950 px-2 py-1 text-[11px] text-slate-300 hover:border-slate-700 hover:text-white transition-colors text-left truncate max-w-full"
            >
              {prompt}
            </button>
          ))}
        </div>
      </div>

      {/* Input Form */}
      <form
        onSubmit={(e) => {
          e.preventDefault();
          handleSendMessage();
        }}
        className="border-t border-slate-800 p-4 bg-slate-950 flex items-center gap-2"
      >
        <input
          type="text"
          value={inputText}
          onChange={(e) => setInputText(e.target.value)}
          placeholder="Ask how to remediate, generate headers..."
          disabled={isSubmitting}
          className="flex-1 rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-xs text-white placeholder-slate-500 focus:border-blue-500 focus:outline-none"
        />
        <button
          type="submit"
          disabled={!inputText.trim() || isSubmitting}
          className="rounded-lg bg-blue-600 p-2 text-white hover:bg-blue-500 transition-colors disabled:opacity-50"
        >
          <Send className="h-4 w-4" />
        </button>
      </form>
    </div>
  );
};
