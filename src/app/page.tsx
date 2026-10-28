"use client";

import React, { useState, useEffect, useCallback } from "react";
import { Header } from "@/components/Header";
import { RepoSearchBar } from "@/components/RepoSearchBar";
import { RepoOverviewStats } from "@/components/RepoOverviewStats";
import { VulnerabilityList } from "@/components/VulnerabilityList";
import { VulnerabilityDetail } from "@/components/VulnerabilityDetail";
import { ScanProgressModal } from "@/components/ScanProgressModal";
import { AuditApiResponse, VulnerabilityItem } from "@/types";
import { sound } from "@/lib/sound";

export default function Home() {
  const [repoUrl, setRepoUrl] = useState<string>("https://github.com/lasyaishu05-spec/studyMate-AI");
  const [branch, setBranch] = useState<string>("main");
  const [data, setData] = useState<AuditApiResponse | null>(null);
  const [vulnerabilitiesList, setVulnerabilitiesList] = useState<VulnerabilityItem[]>([]);
  const [selectedVuln, setSelectedVuln] = useState<VulnerabilityItem | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [scanStep, setScanStep] = useState<number>(0);
  const [soundEnabled, setSoundEnabled] = useState<boolean>(true);

  const handleToggleSound = () => {
    sound.enabled = !soundEnabled;
    setSoundEnabled(!soundEnabled);
  };

  // Perform dynamic audit against backend API /api/audit
  const performAudit = useCallback(async (targetUrl: string, targetBranch: string) => {
    setIsLoading(true);
    setScanStep(1);

    // Audio cues and simulated progression steps
    setTimeout(() => {
      setScanStep(2);
      sound.playBeep(580, "sine", 0.04, 0.03);
    }, 400);

    setTimeout(() => {
      setScanStep(3);
      sound.playBeep(720, "sine", 0.04, 0.03);
    }, 850);

    setTimeout(() => {
      setScanStep(4);
      sound.playBeep(880, "sine", 0.05, 0.04);
    }, 1250);

    try {
      const response = await fetch("/api/audit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repoUrl: targetUrl, branch: targetBranch }),
      });

      if (!response.ok) {
        throw new Error("Audit request failed");
      }

      const payload: AuditApiResponse = await response.json();

      // Enforce 1.5 second clean loading skeleton window
      setTimeout(() => {
        setData(payload);
        setVulnerabilitiesList(payload.vulnerabilities_list || []);
        setSelectedVuln(payload.vulnerabilities_list?.[0] || null);
        setIsLoading(false);
        setScanStep(0);
        sound.playSuccess();
      }, 1500);
    } catch (err) {
      console.error("Error executing audit:", err);
      setIsLoading(false);
      setScanStep(0);
    }
  }, []);

  // Initial load
  useEffect(() => {
    performAudit(repoUrl, branch);
  }, []);

  // Trigger audit on button click or URL change
  const handleRunAudit = () => {
    performAudit(repoUrl, branch);
  };

  // Toggle patch applied state
  const handleApplyPatch = (vulnId: string) => {
    setVulnerabilitiesList((prev) =>
      prev.map((v) => {
        if (v.id === vulnId) {
          const nextStatus = v.status === "applied" ? "unresolved" : "applied";
          const updated = { ...v, status: nextStatus as "applied" | "unresolved" };
          if (selectedVuln?.id === vulnId) {
            setSelectedVuln(updated);
          }
          return updated;
        }
        return v;
      })
    );
  };

  const resolvedCount = vulnerabilitiesList.filter((v) => v.status === "applied").length;

  return (
    <main className="h-screen w-screen overflow-hidden flex flex-col bg-[#f8fafc] text-slate-800 font-sans">
      {/* 1. Global Navigation Bar */}
      <Header
        soundEnabled={soundEnabled}
        onToggleSound={handleToggleSound}
        onRunAudit={handleRunAudit}
        isScanning={isLoading}
      />

      {/* 2. Repository Search & Configuration Bar */}
      <RepoSearchBar
        repoUrl={repoUrl}
        setRepoUrl={setRepoUrl}
        branch={branch}
        setBranch={setBranch}
        onAudit={handleRunAudit}
        isScanning={isLoading}
      />

      {/* 3. Dynamic Top Stats Banner wired to data?.trace?.metadata */}
      <RepoOverviewStats
        data={data}
        resolvedCount={resolvedCount}
        isLoading={isLoading}
      />

      {/* 4. Main 2-Column Scannable Workspace */}
      <div className="flex-1 flex overflow-hidden min-h-0 bg-white">
        {/* Left Column: Vulnerabilities List dynamically bound to data?.vulnerabilities_list */}
        <VulnerabilityList
          vulnerabilitiesList={vulnerabilitiesList}
          selectedId={selectedVuln?.id || ""}
          onSelect={(vuln) => setSelectedVuln(vuln)}
          isLoading={isLoading}
        />

        {/* Right Column: Patch solution & Graph-RAG topology */}
        <VulnerabilityDetail
          vulnerability={selectedVuln}
          data={data}
          onApplyPatch={handleApplyPatch}
          isLoading={isLoading}
        />
      </div>

      {/* 5. Live Scan Modal during execution */}
      {isLoading && (
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
          <span>
            Router: {data?.trace?.routing_engine || "Gemma 2 9B"} ➔ Reasoner: {data?.trace?.reasoning_engine || "Gemma 2 27B"}
          </span>
          <span>•</span>
          <span className="text-slate-400 font-mono text-[11px]">{repoUrl.replace("https://github.com/", "")}</span>
        </div>

        <div className="flex items-center gap-3">
          <span className="text-slate-600 font-medium">
            Scanned Files: {data?.trace?.metadata?.file_count ?? 0}
          </span>
          <span>•</span>
          <span className="text-emerald-700 font-medium">Zero Cloud Egress • 100% Private</span>
        </div>
      </footer>
    </main>
  );
}
