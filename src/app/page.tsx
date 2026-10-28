"use client";

import React, { useState } from "react";
import { Header } from "@/components/Header";
import { RepoSearchBar } from "@/components/RepoSearchBar";
import { RepoOverviewStats } from "@/components/RepoOverviewStats";
import { VulnerabilityList } from "@/components/VulnerabilityList";
import { VulnerabilityDetail } from "@/components/VulnerabilityDetail";
import { ScanProgressModal } from "@/components/ScanProgressModal";
import { DEFAULT_SCAN_RESULT } from "@/lib/mockData";
import { RepoVulnerability } from "@/types";
import { sound } from "@/lib/sound";

export default function Home() {
  const [repoUrl, setRepoUrl] = useState<string>(DEFAULT_SCAN_RESULT.repoUrl);
  const [branch, setBranch] = useState<string>(DEFAULT_SCAN_RESULT.branch);
  const [scanResult, setScanResult] = useState(DEFAULT_SCAN_RESULT);
  const [vulnerabilities, setVulnerabilities] = useState<RepoVulnerability[]>(DEFAULT_SCAN_RESULT.vulnerabilities);
  const [selectedVuln, setSelectedVuln] = useState<RepoVulnerability>(DEFAULT_SCAN_RESULT.vulnerabilities[0]);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [scanStep, setScanStep] = useState<number>(0);
  const [soundEnabled, setSoundEnabled] = useState<boolean>(true);

  const handleToggleSound = () => {
    sound.enabled = !soundEnabled;
    setSoundEnabled(!soundEnabled);
  };

  const handleAudit = () => {
    setIsScanning(true);
    setScanStep(1);

    setTimeout(() => {
      setScanStep(2);
      sound.playBeep(580, "sine", 0.04, 0.03);
    }, 450);

    setTimeout(() => {
      setScanStep(3);
      sound.playBeep(720, "sine", 0.04, 0.03);
    }, 950);

    setTimeout(() => {
      setScanStep(4);
      sound.playBeep(880, "sine", 0.05, 0.04);
    }, 1500);

    setTimeout(() => {
      setIsScanning(false);
      setScanStep(0);
      sound.playSuccess();
    }, 1900);
  };

  const handleApplyPatch = (vulnId: string) => {
    setVulnerabilities((prev) =>
      prev.map((v) => {
        if (v.id === vulnId) {
          const nextStatus = v.status === "applied" ? "unresolved" : "applied";
          const updated = { ...v, status: nextStatus as "applied" | "unresolved" };
          if (selectedVuln.id === vulnId) {
            setSelectedVuln(updated);
          }
          return updated;
        }
        return v;
      })
    );
  };

  const resolvedCount = vulnerabilities.filter((v) => v.status === "applied").length;

  return (
    <main className="h-screen w-screen overflow-hidden flex flex-col bg-[#f8fafc] text-slate-800 font-sans">
      {/* 1. Global Navigation Bar */}
      <Header
        soundEnabled={soundEnabled}
        onToggleSound={handleToggleSound}
        onRunAudit={handleAudit}
        isScanning={isScanning}
      />

      {/* 2. Repository Search & Configuration Bar */}
      <RepoSearchBar
        repoUrl={repoUrl}
        setRepoUrl={setRepoUrl}
        branch={branch}
        setBranch={setBranch}
        onAudit={handleAudit}
        isScanning={isScanning}
      />

      {/* 3. At-a-Glance Overview KPI Bar */}
      <RepoOverviewStats
        stats={scanResult.stats}
        resolvedCount={resolvedCount}
      />

      {/* 4. Main 2-Column Scannable Workspace */}
      <div className="flex-1 flex overflow-hidden min-h-0 bg-white">
        {/* Left Column: Triage List with Filters */}
        <VulnerabilityList
          vulnerabilities={vulnerabilities}
          selectedId={selectedVuln.id}
          onSelect={(vuln) => setSelectedVuln(vuln)}
        />

        {/* Right Column: Deep Resolution Workspace */}
        <VulnerabilityDetail
          vulnerability={selectedVuln}
          onApplyPatch={handleApplyPatch}
          scanResult={scanResult}
        />
      </div>

      {/* 5. Live Scan Modal during execution */}
      {isScanning && (
        <ScanProgressModal
          step={scanStep}
          repoUrl={repoUrl}
        />
      )}

      {/* Subtle Clean Footer Bar */}
      <footer className="h-7 border-t border-slate-200 bg-white px-6 flex items-center justify-between text-xs text-slate-500 select-none z-20">
        <div className="flex items-center gap-3">
          <span className="flex items-center gap-1.5 text-emerald-700 font-medium">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
            <span>GemmaGuard Core: Online</span>
          </span>
          <span>•</span>
          <span>Open-Weights: Gemma 2 9B Router + Gemma 2 27B Reasoner</span>
          <span>•</span>
          <span className="text-slate-400 font-mono text-[11px]">{repoUrl.replace("https://github.com/", "")}</span>
        </div>

        <div className="flex items-center gap-3">
          <span className="text-slate-600 font-medium">Graph-RAG AST: 28 Files</span>
          <span>•</span>
          <span className="text-emerald-700 font-medium">Zero Cloud Egress • 100% Private</span>
        </div>
      </footer>
    </main>
  );
}
