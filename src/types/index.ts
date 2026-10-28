export type Severity = "Critical" | "High" | "Medium" | "Low";

export interface GraphNode {
  id: string;
  label: string;
  file: string;
  type: "entrypoint" | "vulnerable_target" | "upstream_consumer" | "dependency" | "healed_patch" | "vulnerable" | "healed" | "upstream";
  x: number;
  y: number;
  metadata?: Record<string, string | number | boolean>;
}

export interface DependencyLink {
  source: string;
  target: string;
  relation?: string;
  label?: string;
  risk: "high" | "medium" | "low" | "safe";
}

export interface RepoVulnerability {
  id: string;
  title: string;
  severity: Severity;
  cvssScore: number;
  cwe: string;
  file: string;
  lineRange: string;
  category: "RCE" | "SQLi" | "Path Traversal" | "Secrets" | "Auth";
  impactSummary: string;
  upstreamBlastRadius: string[];
  vulnerableCode: string;
  healedPatch: string;
  patchExplanation: string[];
  gemmaReasoningLogs: string[];
  diffStats: { additions: number; deletions: number };
  status: "unresolved" | "applied" | "ignored";
}

export interface RepositoryScanResult {
  repoUrl: string;
  branch: string;
  commitHash: string;
  scanTimestamp: string;
  durationMs: number;
  stats: {
    totalFiles: number;
    linesOfCode: number;
    vulnerabilitiesCount: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    autoHealAvailable: number;
    sovereignComputeTime: string;
  };
  vulnerabilities: RepoVulnerability[];
  graphNodes: {
    id: string;
    label: string;
    file: string;
    type: "entrypoint" | "vulnerable" | "healed" | "upstream";
    x: number;
    y: number;
    risk: Severity;
  }[];
  graphEdges: {
    source: string;
    target: string;
    label: string;
    risk: "high" | "medium" | "safe";
  }[];
  modelLineage: {
    routingModel: string;
    routerHardware: string;
    routerTokens: number;
    routerLatencyMs: number;
    reasoningModel: string;
    reasoningHardware: string;
    astDepthChecked: number;
    openWeightsLoopVerified: boolean;
    zeroEgressSignature: string;
  };
}

export interface VulnerabilityAudit {
  vulnerabilityName: string;
  severity: "Critical" | "High" | "Medium";
  cvssScore: number;
  cwe: string;
  impactAnalysis: string;
  upstreamImpact: string;
  originalCode: string;
  refactoredPatch: string;
  patchExplanation: string[];
  diffAdditions: number;
  diffDeletions: number;
}

export interface LineagePayload {
  routingEngine: string;
  reasoningEngine: string;
  sourceSnippetsReviewed: number;
  filesScanned: string[];
  dependenciesTraversed: string[];
  cardA: any;
  cardB: any;
  cardC: any;
  graphNodes: GraphNode[];
  graphLinks: DependencyLink[];
  terminalLogs: { timestamp: string; level: "INFO" | "WARN" | "SUCCESS" | "TRACE"; message: string }[];
}
