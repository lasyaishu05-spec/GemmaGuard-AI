"use client";

import React from "react";
import {
  FileCode,
  ShieldAlert,
  Sparkles,
  Lock,
  Flame,
} from "lucide-react";
import { AuditApiResponse } from "@/types";

interface RepoOverviewStatsProps {
  data: AuditApiResponse | null;
  resolvedCount: number;
  isLoading: boolean;
}

export const RepoOverviewStats: React.FC<RepoOverviewStatsProps> = ({
  data,
  resolvedCount,
  isLoading,
}) => {
  const metadata = data?.trace?.metadata;
  const fileCount = metadata?.file_count ?? 0;
  const locCount = metadata?.loc_count ?? 0;
  const totalFound = metadata?.severities?.total_found ?? 0;
  const criticalCount = metadata?.severities?.critical ?? 0;
  const highCount = metadata?.severities?.high ?? 0;
  const mediumCount = metadata?.severities?.medium ?? 0;
  const autoHealTotal = metadata?.auto_heal_available ?? totalFound;

  if (isLoading) {
    return (
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3 p-4 bg-slate-50/80 border-b border-slate-200">
        {[1, 2, 3, 4, 5].map((idx) => (
          <div
            key={idx}
            className="p-3.5 rounded-xl bg-white border border-slate-200 card-shadow flex items-center gap-3 animate-pulse"
          >
            <div className="w-10 h-10 rounded-lg bg-slate-200" />
            <div className="flex-1 space-y-1.5">
              <div className="h-3 w-16 bg-slate-200 rounded" />
              <div className="h-5 w-24 bg-slate-300 rounded" />
            </div>
          </div>
        ))}
      </div>
    );
  }

  return (
    <div className="grid grid-cols-2 md:grid-cols-5 gap-3 p-4 bg-slate-50/80 border-b border-slate-200">
      {/* 1. Scanned Files Chip */}
      <div className="p-3.5 rounded-xl bg-white border border-slate-200 card-shadow flex items-center gap-3">
        <div className="w-10 h-10 rounded-lg bg-slate-100 border border-slate-200 flex items-center justify-center text-slate-700">
          <FileCode className="w-5 h-5" />
        </div>
        <div>
          <div className="text-xs text-slate-500 font-medium">Scanned Files</div>
          <div className="text-lg font-bold text-slate-900 flex items-baseline gap-1 mt-0.5">
            <span>{fileCount}</span>
            <span className="text-xs text-slate-400 font-normal">
              ({locCount.toLocaleString()} LOC)
            </span>
          </div>
        </div>
      </div>

      {/* 2. Vulnerabilities Count */}
      <div className="p-3.5 rounded-xl bg-white border border-rose-200 card-shadow flex items-center gap-3">
        <div className="w-10 h-10 rounded-lg bg-rose-50 border border-rose-200 flex items-center justify-center text-rose-600">
          <Flame className="w-5 h-5" />
        </div>
        <div>
          <div className="text-xs text-slate-500 font-medium">Vulnerabilities</div>
          <div className="text-lg font-bold text-rose-600 flex items-baseline gap-1 mt-0.5">
            <span>{totalFound}</span>
            <span className="text-xs text-slate-500 font-normal">Found</span>
          </div>
        </div>
      </div>

      {/* 3. Severity Triage Splitter */}
      <div className="p-3.5 rounded-xl bg-white border border-slate-200 card-shadow flex flex-col justify-center gap-1.5">
        <div className="text-xs text-slate-500 font-medium">Severity Triage</div>
        <div className="flex items-center gap-1.5 text-xs font-semibold">
          <span className="text-rose-700 bg-rose-50 px-2 py-0.5 rounded border border-rose-200 text-xs">
            {criticalCount} Critical
          </span>
          <span className="text-amber-700 bg-amber-50 px-2 py-0.5 rounded border border-amber-200 text-xs">
            {highCount} High
          </span>
          <span className="text-slate-700 bg-slate-100 px-2 py-0.5 rounded border border-slate-200 text-xs">
            {mediumCount} Med
          </span>
        </div>
      </div>

      {/* 4. Gemma 2 27B Healed Patches */}
      <div className="p-3.5 rounded-xl bg-white border border-emerald-200 card-shadow flex items-center gap-3">
        <div className="w-10 h-10 rounded-lg bg-emerald-50 border border-emerald-200 flex items-center justify-center text-emerald-600">
          <Sparkles className="w-5 h-5" />
        </div>
        <div>
          <div className="text-xs text-slate-500 font-medium">Auto-Healed Patches</div>
          <div className="text-lg font-bold text-emerald-700 flex items-baseline gap-1 mt-0.5">
            <span>{resolvedCount} / {autoHealTotal}</span>
            <span className="text-xs text-slate-500 font-normal">Patched</span>
          </div>
        </div>
      </div>

      {/* 5. Sovereign Air-Gapped Seal */}
      <div className="col-span-2 md:col-span-1 p-3.5 rounded-xl bg-white border border-slate-200 card-shadow flex items-center gap-3">
        <div className="w-10 h-10 rounded-lg bg-emerald-50 border border-emerald-200 flex items-center justify-center text-emerald-600">
          <Lock className="w-5 h-5" />
        </div>
        <div>
          <div className="text-xs text-slate-500 font-medium">Privacy Status</div>
          <div className="text-xs font-bold text-slate-800 mt-0.5">Zero Data Egress</div>
          <div className="text-[10px] text-slate-400">100% Sovereign Node</div>
        </div>
      </div>
    </div>
  );
};
