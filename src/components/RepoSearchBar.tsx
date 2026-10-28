"use client";

import React from "react";
import {
  GitBranch,
  Play,
  Sparkles,
  FolderGit2,
  Search,
} from "lucide-react";
import { SAMPLE_REPOS } from "@/lib/mockData";
import { sound } from "@/lib/sound";

interface RepoSearchBarProps {
  repoUrl: string;
  setRepoUrl: (url: string) => void;
  branch: string;
  setBranch: (branch: string) => void;
  onAudit: () => void;
  isScanning: boolean;
}

export const RepoSearchBar: React.FC<RepoSearchBarProps> = ({
  repoUrl,
  setRepoUrl,
  branch,
  setBranch,
  onAudit,
  isScanning,
}) => {
  return (
    <div className="bg-white border-b border-slate-200 px-6 py-4 flex flex-col gap-3">
      {/* Search Input Row */}
      <div className="flex flex-col md:flex-row items-stretch md:items-center gap-3">
        {/* Repo URL Input */}
        <div className="flex-1 relative flex items-center rounded-xl bg-slate-50 border border-slate-200 focus-within:border-emerald-500 focus-within:bg-white focus-within:ring-2 focus-within:ring-emerald-500/15 card-shadow transition-all">
          <div className="pl-3.5 pr-2.5 text-slate-400 flex items-center gap-2 select-none">
            <svg className="w-4 h-4 text-slate-700 fill-current" viewBox="0 0 24 24">
              <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z" />
            </svg>
            <span className="text-xs text-slate-500 font-semibold hidden sm:inline">
              Repository:
            </span>
          </div>
          <input
            type="text"
            value={repoUrl}
            onChange={(e) => setRepoUrl(e.target.value)}
            placeholder="Paste GitHub repository URL (e.g. https://github.com/org/repo)..."
            className="w-full bg-transparent py-2.5 pr-3 text-sm text-slate-800 placeholder-slate-400 outline-none font-mono text-xs md:text-sm"
            disabled={isScanning}
          />
        </div>

        {/* Branch Selector */}
        <div className="flex items-center gap-2 bg-slate-50 border border-slate-200 rounded-xl px-3 py-2 text-xs text-slate-700">
          <GitBranch className="w-4 h-4 text-slate-400" />
          <select
            value={branch}
            onChange={(e) => setBranch(e.target.value)}
            disabled={isScanning}
            className="bg-transparent text-slate-700 font-medium outline-none cursor-pointer"
          >
            <option value="main">main</option>
            <option value="dev">dev</option>
            <option value="release-v2">release-v2</option>
          </select>
        </div>

        {/* Audit Button */}
        <button
          onClick={() => {
            sound.playExecute();
            onAudit();
          }}
          disabled={isScanning || !repoUrl.trim()}
          className={`px-5 py-2.5 rounded-xl text-xs font-bold tracking-wide flex items-center justify-center gap-2 transition-all duration-200 shadow-sm ${
            isScanning
              ? "bg-slate-100 text-slate-400 border border-slate-200 cursor-wait"
              : "bg-emerald-600 hover:bg-emerald-700 text-white shadow-emerald-600/20 active:scale-[0.98]"
          }`}
        >
          {isScanning ? (
            <>
              <div className="w-4 h-4 border-2 border-slate-400 border-t-transparent rounded-full animate-spin" />
              <span>Scanning Repository...</span>
            </>
          ) : (
            <>
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>Audit Repository</span>
            </>
          )}
        </button>
      </div>

      {/* Preset Demo Chips */}
      <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-slate-500 text-xs flex items-center gap-1.5 font-medium">
            <FolderGit2 className="w-3.5 h-3.5 text-slate-400" />
            Quick Demo Repos:
          </span>

          {SAMPLE_REPOS.map((sample) => {
            const active = repoUrl === sample.url;
            return (
              <button
                key={sample.name}
                onClick={() => {
                  sound.playClick();
                  setRepoUrl(sample.url);
                  setBranch(sample.branch);
                }}
                disabled={isScanning}
                className={`text-xs px-2.5 py-1 rounded-lg border transition-all flex items-center gap-1.5 ${
                  active
                    ? "bg-emerald-50 border-emerald-300 text-emerald-800 font-semibold"
                    : "bg-slate-50 border-slate-200 text-slate-600 hover:bg-white hover:border-slate-300"
                }`}
              >
                <span>{sample.name}</span>
                <span className="text-[10px] text-slate-400 font-mono">({sample.branch})</span>
              </button>
            );
          })}
        </div>

        <div className="text-xs text-slate-500 flex items-center gap-1.5">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
          <span>Graph-RAG Vector Index: <strong className="text-slate-700 font-semibold">Ready</strong></span>
        </div>
      </div>
    </div>
  );
};
