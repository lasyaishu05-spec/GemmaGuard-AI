"use client";

import React from "react";
import { Shield, Sparkles, Volume2, VolumeX, Lock, Radio } from "lucide-react";
import { sound } from "@/lib/sound";

interface HeaderProps {
  soundEnabled: boolean;
  onToggleSound: () => void;
  onRunAudit: () => void;
  isScanning: boolean;
}

export const Header: React.FC<HeaderProps> = ({
  soundEnabled,
  onToggleSound,
}) => {
  return (
    <header className="h-14 border-b border-slate-200 bg-white/95 backdrop-blur px-6 flex items-center justify-between select-none z-30">
      {/* Brand Identity */}
      <div className="flex items-center gap-3">
        <div className="w-8 h-8 rounded-lg bg-emerald-50 border border-emerald-200 flex items-center justify-center text-emerald-600 shadow-sm">
          <Shield className="w-4 h-4 fill-emerald-100" />
        </div>

        <div className="flex items-center gap-2.5">
          <h1 className="text-sm font-bold tracking-tight text-slate-900 flex items-center gap-1">
            <span>GemmaGuard</span>
            <span className="text-emerald-600">AI</span>
          </h1>

          <span className="text-slate-300">/</span>

          <span className="text-xs text-slate-500 font-medium hidden sm:inline">
            Graph-RAG Code Reviewer &amp; Auto-Healer
          </span>

          <span className="bg-emerald-50 text-emerald-700 text-[10px] font-semibold px-2 py-0.5 rounded-full border border-emerald-200 ml-1">
            MLH Hackathon
          </span>
        </div>
      </div>

      {/* Right Controls */}
      <div className="flex items-center gap-2.5">
        {/* Model Architecture Badge */}
        <div className="hidden md:flex items-center gap-2 bg-slate-50 border border-slate-200 px-3 py-1 rounded-lg text-xs">
          <span className="text-slate-500">Tiered Compute:</span>
          <span className="font-semibold text-slate-700">Gemma 2 9B (Router)</span>
          <span className="text-slate-300">➔</span>
          <span className="font-semibold text-emerald-700">Gemma 2 27B (Auto-Healer)</span>
        </div>

        {/* Sovereign Air-Gapped Pill */}
        <div className="flex items-center gap-1.5 bg-slate-50 border border-slate-200 px-2.5 py-1 rounded-lg text-xs text-slate-600">
          <Lock className="w-3.5 h-3.5 text-emerald-600" />
          <span className="font-medium">100% Private Open-Weights</span>
        </div>

        {/* Audio Toggle */}
        <button
          onClick={() => {
            onToggleSound();
            sound.playClick();
          }}
          title={soundEnabled ? "Mute Sound Effects" : "Enable Sound Effects"}
          className="p-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-slate-500 hover:text-slate-800 transition"
        >
          {soundEnabled ? (
            <Volume2 className="w-4 h-4 text-emerald-600" />
          ) : (
            <VolumeX className="w-4 h-4 text-slate-400" />
          )}
        </button>
      </div>
    </header>
  );
};
