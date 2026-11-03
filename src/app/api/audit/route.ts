import { NextResponse } from "next/server";
import {
  AuditApiResponse,
  PatchSolution,
  Severity,
  VulnerabilityItem,
} from "@/types";
import {
  buildAuditPrompt,
  isFindingSupportedBySource,
  parseGitHubRepositoryUrl,
  RepositorySource,
} from "@/lib/auditCore";

const OLLAMA_URL = process.env.OLLAMA_URL || "http://127.0.0.1:11434";
const OLLAMA_MODEL = process.env.OLLAMA_MODEL || "gemma3:1b";
const MAX_SOURCE_FILES = 4;
const MAX_SOURCE_BYTES = 16_000;

interface GitHubTreeItem {
  path: string;
  type: string;
  size?: number;
}

interface GitHubSourceFile {
  encoding: string;
  content: string;
}

interface RepositorySnapshot {
  commitHash: string;
  files: RepositorySource[];
}

const CODE_FILE_EXTENSION =
  /\.(?:js|jsx|ts|tsx|py|go|rs|java|php|rb|sql|sh)$/i;
const SEVERITIES: Severity[] = ["Critical", "High", "Medium", "Low"];
const CATEGORIES: VulnerabilityItem["category"][] = [
  "RCE",
  "SQLi",
  "Path Traversal",
  "Secrets",
  "Auth",
  "Prompt Injection",
  "IDOR",
];

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function text(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

async function fetchGitHubJson<T>(url: string): Promise<T> {
  const response = await fetch(url, {
    headers: {
      Accept: "application/vnd.github+json",
      "User-Agent": "GemmaGuard-AI",
    },
    cache: "no-store",
    signal: AbortSignal.timeout(15_000),
  });

  if (!response.ok) {
    throw new Error(
      `GitHub request failed (${response.status}). Check that the public repository and branch exist.`,
    );
  }

  return (await response.json()) as T;
}

async function fetchRepositorySources(
  repoUrl: string,
  branch: string,
): Promise<RepositorySnapshot> {
  const repository = parseGitHubRepositoryUrl(repoUrl);
  if (!repository) {
    throw new Error("Enter a valid public GitHub repository URL.");
  }
  if (!branch.trim() || branch.length > 255) {
    throw new Error("Enter a valid branch name.");
  }

  const apiRepo = `https://api.github.com/repos/${encodeURIComponent(repository.owner)}/${encodeURIComponent(repository.repo)}`;
  const commits = await fetchGitHubJson<Array<{ sha: string }>>(
    `${apiRepo}/commits?sha=${encodeURIComponent(branch)}&per_page=1`,
  );
  const commitHash = commits[0]?.sha;
  if (!commitHash) {
    throw new Error("GitHub did not return a commit for that branch.");
  }

  const tree = await fetchGitHubJson<{ tree?: GitHubTreeItem[] }>(
    `${apiRepo}/git/trees/${encodeURIComponent(commitHash)}?recursive=1`,
  );
  const candidates = (tree.tree || [])
    .filter(
      (item) =>
        item.type === "blob" &&
        typeof item.size === "number" &&
        item.size <= MAX_SOURCE_BYTES &&
        CODE_FILE_EXTENSION.test(item.path),
    )
    .slice(0, MAX_SOURCE_FILES);

  if (candidates.length === 0) {
    throw new Error("No small, supported source files were found on that branch.");
  }

  const files = await Promise.all(
    candidates.map(async ({ path, size }) => {
      const encodedPath = path
        .split("/")
        .map((segment) => encodeURIComponent(segment))
        .join("/");
      const url = `${apiRepo}/contents/${encodedPath}?ref=${encodeURIComponent(commitHash)}`;
      const file = await fetchGitHubJson<GitHubSourceFile>(url);

      if (file.encoding !== "base64" || typeof file.content !== "string") {
        throw new Error(`GitHub did not return readable source for ${path}.`);
      }

      const content = Buffer.from(file.content, "base64").toString("utf8");
      if (
        Buffer.byteLength(content, "utf8") > MAX_SOURCE_BYTES ||
        content.includes("\0")
      ) {
        throw new Error(`The source file ${path} is too large or is not text.`);
      }

      return { path, content };
    }),
  );

  return { commitHash, files };
}

async function callLocalOllama(prompt: string): Promise<string> {
  let response: Response;
  try {
    response = await fetch(`${OLLAMA_URL}/api/generate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model: OLLAMA_MODEL,
        prompt,
        format: "json",
        stream: false,
        options: { temperature: 0.2, num_predict: 1000 },
      }),
      signal: AbortSignal.timeout(30_000),
    });
  } catch (error) {
    console.error("[GemmaGuard] Local Ollama request failed:", error);
    throw new Error("Local Ollama is unavailable. Start Ollama and try again.");
  }

  if (!response.ok) {
    throw new Error(`Local Ollama returned an error (${response.status}).`);
  }

  const result: unknown = await response.json();
  if (!isRecord(result) || typeof result.response !== "string") {
    throw new Error("Local Ollama returned an unreadable response.");
  }
  return result.response;
}

function normalizeFindings(
  rawFindings: unknown[],
  sources: RepositorySource[],
): VulnerabilityItem[] {
  return rawFindings.flatMap((raw, index) => {
    if (!isRecord(raw) || !isFindingSupportedBySource(raw, sources)) return [];

    const severity = raw.severity;
    const category = raw.category;
    const title = text(raw.title);
    const fileName = text(raw.file_name);
    const lineNumbers = text(raw.line_numbers);
    const vulnerableCode = text(raw.vulnerable_code);
    const healedPatch = text(raw.healed_patch);

    if (
      typeof severity !== "string" ||
      !SEVERITIES.includes(severity as Severity) ||
      typeof category !== "string" ||
      !CATEGORIES.includes(category as VulnerabilityItem["category"]) ||
      !title ||
      !fileName ||
      !lineNumbers ||
      !vulnerableCode ||
      !healedPatch
    ) {
      return [];
    }

    const color =
      severity === "Critical"
        ? "rose"
        : severity === "High"
          ? "amber"
          : severity === "Medium"
            ? "sky"
            : "slate";

    return [
      {
        id: `finding-${index + 1}`,
        title,
        severity: severity as Severity,
        severity_color: color,
        cvss_score:
          typeof raw.cvss_score === "number" &&
          raw.cvss_score >= 0 &&
          raw.cvss_score <= 10
            ? raw.cvss_score
            : undefined,
        cwe: text(raw.cwe) || "Not provided",
        file_name: fileName,
        line_numbers: lineNumbers,
        category: category as VulnerabilityItem["category"],
        impact: text(raw.impact) || "Review this source location manually.",
        upstream_blast_radius: Array.isArray(raw.upstream_blast_radius)
          ? raw.upstream_blast_radius.filter(
              (item): item is string => typeof item === "string",
            )
          : [],
        vulnerable_code: vulnerableCode,
        healed_patch: healedPatch,
        patch_explanation: Array.isArray(raw.patch_explanation)
          ? raw.patch_explanation.filter(
              (item): item is string => typeof item === "string",
            )
          : [],
        gemma_reasoning_logs: [
          `AI suggestion from configured Ollama model ${OLLAMA_MODEL}.`,
          `The cited code snippet was matched against ${fileName}.`,
          "Review and test this suggestion before using it.",
        ],
        status: "unresolved",
      },
    ];
  });
}

function createPatchSolution(
  finding: VulnerabilityItem | undefined,
): PatchSolution | null {
  if (!finding) return null;

  return {
    title: finding.title,
    file_name: finding.file_name || "",
    summary: finding.impact || "Review this AI-generated suggestion.",
    architectural_risk:
      "This is an AI-generated suggestion and has not been applied or independently verified.",
    markdown_report: `### GemmaGuard AI review
This is an AI-generated suggestion, not a verified security finding.

- **Finding:** ${finding.title}
- **Severity suggested by model:** ${finding.severity}
- **Location:** \`${finding.file_name}:${finding.line_numbers}\`

#### Source snippet
\`\`\`
${finding.vulnerable_code || ""}
\`\`\`

#### Suggested replacement (not applied)
\`\`\`
${finding.healed_patch || ""}
\`\`\`

Review and test any change before using it.`,
    vulnerable_snippet: finding.vulnerable_code || "",
    refactored_code: finding.healed_patch || "",
    validation_badges: ["Source snippet matched"],
    diff_additions: 0,
    diff_deletions: 0,
  };
}

async function generateAudit(
  repoUrl: string,
  branch: string,
): Promise<AuditApiResponse> {
  const snapshot = await fetchRepositorySources(repoUrl, branch);
  const repoName =
    parseGitHubRepositoryUrl(repoUrl)?.repo || "repository";
  const rawModelResponse = await callLocalOllama(
    buildAuditPrompt(repoName, snapshot.files),
  );

  let parsed: unknown;
  try {
    parsed = JSON.parse(rawModelResponse);
  } catch {
    throw new Error("Local Ollama returned invalid JSON. Please try again.");
  }

  if (!isRecord(parsed) || !Array.isArray(parsed.vulnerabilities)) {
    throw new Error("Local Ollama returned an invalid audit result.");
  }

  const vulnerabilities = normalizeFindings(
    parsed.vulnerabilities,
    snapshot.files,
  );
  const critical = vulnerabilities.filter((item) => item.severity === "Critical").length;
  const high = vulnerabilities.filter((item) => item.severity === "High").length;
  const medium = vulnerabilities.filter((item) => item.severity === "Medium").length;
  const low = vulnerabilities.filter((item) => item.severity === "Low").length;
  const linesScanned = snapshot.files.reduce(
    (total, file) => total + file.content.split(/\r\n|\r|\n/).length,
    0,
  );

  return {
    repo_url: repoUrl.trim(),
    branch,
    commit_hash: snapshot.commitHash,
    timestamp: new Date().toISOString(),
    trace: {
      metadata: {
        file_count: snapshot.files.length,
        loc_count: linesScanned,
        severities: {
          total_found: vulnerabilities.length,
          critical,
          high,
          medium,
          low,
        },
        suggestions_available: vulnerabilities.length,
        compute_cluster: `Configured Ollama endpoint (${OLLAMA_URL})`,
      },
      dependencies_traversed: Array.isArray(parsed.dependencies_traversed)
        ? parsed.dependencies_traversed.filter(
            (item): item is string => typeof item === "string",
          )
        : [],
      routing_engine: `Ollama (${OLLAMA_MODEL})`,
      reasoning_engine: `Ollama (${OLLAMA_MODEL})`,
    },
    vulnerabilities_list: vulnerabilities,
    patch_solution: createPatchSolution(vulnerabilities[0]),
  };
}

async function handleAudit(request: Request) {
  try {
    const body: unknown = await request.json();
    if (!isRecord(body)) {
      return NextResponse.json({ error: "Invalid audit request." }, { status: 400 });
    }

    const repoUrl = text(body.repoUrl) || text(body.repo_url);
    const branch = text(body.branch) || "main";
    if (!repoUrl) {
      return NextResponse.json(
        { error: "A GitHub repository URL is required." },
        { status: 400 },
      );
    }
    if (!parseGitHubRepositoryUrl(repoUrl)) {
      return NextResponse.json(
        { error: "Enter a valid public GitHub repository URL." },
        { status: 400 },
      );
    }
    if (branch.length > 255) {
      return NextResponse.json(
        { error: "The branch name is too long." },
        { status: 400 },
      );
    }

    return NextResponse.json(await generateAudit(repoUrl, branch));
  } catch (error) {
    const message =
      error instanceof Error ? error.message : "The audit could not be completed.";
    console.error("[GemmaGuard API Error]:", error);
    return NextResponse.json({ error: message }, { status: 502 });
  }
}

export async function POST(request: Request) {
  return handleAudit(request);
}

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const repoUrl = searchParams.get("repoUrl") || "";
  const branch = searchParams.get("branch") || "main";
  const body = new Request(request.url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ repoUrl, branch }),
  });
  return handleAudit(body);
}
