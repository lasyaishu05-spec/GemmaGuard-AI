"use client";

import React from "react";
import { Shield, Cpu, Layers, CheckCircle2 } from "lucide-react";

interface ScanProgressModalProps {
  step: number;
  repoUrl: string;
}

export const ScanProgressModal: React.FC<ScanProgressModalProps> = ({ step, repoUrl }) => {
  const steps = [
    { title: "Cloning Repository & AST Traversal", desc: "Inspecting repository file tree & call hierarchies", icon: Layers },
    { title: "Local Ollama (gemma3:1b) Ingestion", desc: "Tokenizing code files & generating AST dependency graphs", icon: Cpu },
    { title: "Local Ollama (gemma3:1b) Deep Audit", desc: "Evaluating multi-file vulnerabilities & CVSS scores", icon: Shield },
    { title: "Synthesizing Auto-Healed Patches", desc: "Generating secure replacements with 100% on-device inference", icon: CheckCircle2 },
  ];

  return (
    <div className="fixed inset-0 z-50 bg-slate-900/40 backdrop-blur-sm flex items-center justify-center p-4 select-none">
      <div className="w-full max-w-lg rounded-2xl bg-white border border-slate-200 p-6 flex flex-col gap-5 shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-100 pb-3">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-emerald-50 border border-emerald-200 flex items-center justify-center text-emerald-600">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-900">Auditing Repository</h3>
              <p className="text-xs text-slate-500 truncate max-w-xs font-mono">{repoUrl}</p>
            </div>
          </div>
          <span className="text-xs text-emerald-700 font-bold bg-emerald-50 px-2.5 py-1 rounded-full border border-emerald-200">
            {Math.min(step * 25, 100)}%
          </span>
        </div>

        {/* Progress Bar */}
        <div className="w-full h-2 bg-slate-100 rounded-full overflow-hidden">
          <div
            className="h-full bg-emerald-600 transition-all duration-300 rounded-full"
            style={{ width: `${Math.min(step * 25, 100)}%` }}
          />
        </div>

        {/* Steps List */}
        <div className="flex flex-col gap-2.5">
          {steps.map((st, i) => {
            const isDone = step > i + 1;
            const isCurrent = step === i + 1;
            const Icon = st.icon;

            return (
              <div
                key={i}
                className={`p-3 rounded-xl border flex items-center justify-between transition-all ${
                  isCurrent
                    ? "bg-emerald-50/60 border-emerald-300"
                    : isDone
                    ? "bg-slate-50 border-slate-200 text-slate-800"
                    : "bg-white border-slate-100 text-slate-400"
                }`}
              >
                <div className="flex items-center gap-3">
                  <div
                    className={`w-7 h-7 rounded-lg flex items-center justify-center text-xs ${
                      isCurrent
                        ? "bg-emerald-100 text-emerald-700"
                        : isDone
                        ? "bg-emerald-100 text-emerald-700"
                        : "bg-slate-100 text-slate-400"
                    }`}
                  >
                    <Icon className="w-4 h-4" />
                  </div>
                  <div className="flex flex-col">
                    <span className={`text-xs font-semibold ${isCurrent ? "text-emerald-950 font-bold" : isDone ? "text-slate-800" : "text-slate-400"}`}>
                      {st.title}
                    </span>
                    <span className="text-[11px] text-slate-400">{st.desc}</span>
                  </div>
                </div>

                {isDone && <CheckCircle2 className="w-4 h-4 text-emerald-600" />}
                {isCurrent && <div className="w-4 h-4 border-2 border-emerald-600 border-t-transparent rounded-full animate-spin" />}
              </div>
            );
          })}
        </div>

        {/* Footer */}
        <div className="text-xs text-slate-500 text-center pt-1 border-t border-slate-100 flex items-center justify-center gap-1.5">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
          <span>Sovereign Local Inference • 100% On-Device Ollama (gemma3:1b)</span>
        </div>
      </div>
    </div>
  );
};
