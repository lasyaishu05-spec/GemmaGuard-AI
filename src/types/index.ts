export type Severity = "Critical" | "High" | "Medium" | "Low";

export interface GraphNode {
  id: string;
  label: string;
  file: string;
  type: "entrypoint" | "vulnerable_target" | "upstream_consumer" | "dependency" | "healed_patch" | "vulnerable" | "healed" | "upstream";
  x: number;
  y: number;
  risk?: Severity;
  metadata?: Record<string, string | number | boolean>;
}

export interface DependencyLink {
  source: string;
  target: string;
  relation?: string;
  label?: string;
  risk: "high" | "medium" | "low" | "safe";
}

export interface VulnerabilityItem {
  id: string;
  title: string;
  severity: Severity;
  severity_color?: string;
  cvss_score?: number;
  cvssScore?: number;
  cwe: string;
  file_name?: string;
  file?: string;
  line_numbers?: string;
  lineRange?: string;
  category: "RCE" | "SQLi" | "Path Traversal" | "Secrets" | "Auth" | "Prompt Injection" | "IDOR";
  impact?: string;
  impactSummary?: string;
  upstream_blast_radius?: string[];
  upstreamBlastRadius?: string[];
  vulnerable_code?: string;
  vulnerableCode?: string;
  healed_patch?: string;
  healedPatch?: string;
  patch_explanation?: string[];
  patchExplanation?: string[];
  gemma_reasoning_logs?: string[];
  gemmaReasoningLogs?: string[];
  diff_stats?: { additions: number; deletions: number };
  diffStats?: { additions: number; deletions: number };
  status: "unresolved" | "applied" | "ignored";
}

export interface PatchSolution {
  title: string;
  file_name: string;
  summary: string;
  architectural_risk: string;
  markdown_report: string;
  vulnerable_snippet: string;
  refactored_code: string;
  validation_badges: string[];
  diff_additions: number;
  diff_deletions: number;
}

export interface AuditApiResponse {
  repo_url: string;
  branch: string;
  commit_hash: string;
  timestamp: string;
  trace: {
    metadata: {
      file_count: number;
      loc_count: number;
      severities: {
        total_found: number;
        critical: number;
        high: number;
        medium: number;
      };
      auto_heal_available: number;
      compute_cluster: string;
    };
    dependencies_traversed: string[];
    routing_engine: string;
    reasoning_engine: string;
  };
  vulnerabilities_list: VulnerabilityItem[];
  patch_solution: PatchSolution;
}

// Backward-compat aliases
export type RepoVulnerability = VulnerabilityItem;
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
  vulnerabilities: any[];
  graphNodes: GraphNode[];
  graphEdges: DependencyLink[];
  modelLineage: any;
}
