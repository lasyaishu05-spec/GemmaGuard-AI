import { RepositoryScanResult, RepoVulnerability } from "@/types";

export const SAMPLE_REPOS = [
  {
    name: "payment-gateway-service",
    url: "https://github.com/enterprise-security/payment-gateway-service",
    branch: "main",
    desc: "FastAPI transaction gateway with PostgreSQL & Redis",
    vulnSummary: "5 issues (2 Critical, 2 High, 1 Medium)",
  },
  {
    name: "auth-microservice",
    url: "https://github.com/fintech-corp/auth-microservice",
    branch: "main",
    desc: "JWT authentication and RBAC identity broker",
    vulnSummary: "3 issues (1 Critical, 2 High)",
  },
  {
    name: "cloud-admin-portal",
    url: "https://github.com/cloud-infra/cloud-admin-portal",
    branch: "release-v2",
    desc: "Flask management dashboard and telemetry export engine",
    vulnSummary: "4 issues (2 Critical, 1 High, 1 Medium)",
  },
];

export const DEFAULT_VULNERABILITIES: RepoVulnerability[] = [
  {
    id: "vuln-rce-01",
    title: "Remote Code Execution via Unsafe Object Evaluation in process_user_data",
    severity: "Critical",
    cvssScore: 9.8,
    cwe: "CWE-95: Eval Injection / Dynamic Execution",
    file: "src/main.py",
    lineRange: "L12 - L17",
    category: "RCE",
    impactSummary:
      "The function `process_user_data` directly executes untrusted input strings using the global Python eval() handler. Upstream files importing this route are vulnerable to arbitrary host command execution.",
    upstreamBlastRadius: [
      "/src/gateway/route.py (direct HTTP payload forwarder)",
      "/src/auth/jwt.py (authenticates session before trigger)",
      "/src/workers/queue_listener.py (async task executor)"
    ],
    vulnerableCode: `def process_user_data(input_str):
    """
    Ingests dynamic command packet from external API gateway.
    CRITICAL: Direct evaluation of untrusted user-supplied payload
    """
    print(f"[DEBUG] Raw incoming packet: {input_str}")
    result = eval(input_str)
    return f"Processed: {result}"`,
    healedPatch: `import json
import secrets

def process_user_data(input_str):
    """
    Refactored via Gemma 2 27B.
    Replaced dynamic execution with explicit cryptographic parsing and schema white-listing.
    """
    try:
        clean_payload = json.loads(input_str)
        # Structural whitelist verification loop
        if "action" not in clean_payload:
            raise ValueError("Invalid structural key payload")
        return f"Secure Data Processed: {secrets.token_hex(8)}"
    except (json.JSONDecodeError, ValueError) as err:
        return f"Execution Blocked: Secure Log Ingestion Triggered"`,
    patchExplanation: [
      "Eliminated Python global eval() execution primitive entirely.",
      "Introduced strict JSON deserialization barrier with strict key schema enforcement.",
      "Integrated cryptographic entropy verification using secrets.token_hex(8).",
      "Added granular exception handling for JSONDecodeError and ValueError with secure logging."
    ],
    gemmaReasoningLogs: [
      "[AST Router Gemma 9B] Detected CallNode `eval()` at line 14 with untrusted parameter `input_str`.",
      "[Graph-RAG] Discovered upstream consumer `/src/gateway/route.py` exposing endpoint `/api/v1/process`.",
      "[Reasoning Gemma 27B] Dynamic evaluation permits arbitrary symbol injection (`__import__('os').system()`).",
      "[Transformation Engine] Generating safe AST replacement: JSON schema validator + CSP token generation.",
      "[Formal Verification] Passed Bandit B307 AST check, MyPy strict typing, and invariant simulation."
    ],
    diffStats: { additions: 16, deletions: 4 },
    status: "unresolved"
  },
  {
    id: "vuln-sqli-02",
    title: "SQL Injection via String Interpolation in fetch_account_balance",
    severity: "Critical",
    cvssScore: 9.4,
    cwe: "CWE-89: SQL Injection",
    file: "src/db/billing.py",
    lineRange: "L45 - L53",
    category: "SQLi",
    impactSummary:
      "Direct string interpolation inside SQL statement allows attackers to bypass query constraints, extract hashed credentials, or dump account balances through boolean/union-based injections.",
    upstreamBlastRadius: [
      "/src/api/v1/billing.py (exposes GET /billing/{id})",
      "/src/services/ledger.py (calculates user financial balances)"
    ],
    vulnerableCode: `def fetch_account_balance(account_id):
    conn = sqlite3.connect("enterprise.db")
    cursor = conn.cursor()
    # Flawed raw interpolation
    query = f"SELECT balance, ssn FROM users WHERE user_id = '{account_id}'"
    cursor.execute(query)
    return cursor.fetchone()`,
    healedPatch: `import sqlite3
from typing import Optional, Tuple

def fetch_account_balance(account_id: str) -> Optional[Tuple[float, str]]:
    """
    Refactored via Gemma 2 27B.
    Replaced string formatting with parameterized positional placeholders.
    """
    with sqlite3.connect("enterprise.db") as conn:
        cursor = conn.cursor()
        # Parameterized query neutralizes SQL injection unconditionally
        cursor.execute(
            "SELECT balance, ssn FROM users WHERE user_id = ?",
            (account_id,)
        )
        return cursor.fetchone()`,
    patchExplanation: [
      "Replaced string interpolation with parameterized positional query binding ('?').",
      "Adopted context manager ('with sqlite3.connect') for deterministic connection pooling.",
      "Added explicit type annotations and Optional return types for compile-time safety."
    ],
    gemmaReasoningLogs: [
      "[AST Router Gemma 9B] Flagged FormattedValue inside execute() call.",
      "[Graph-RAG] Query parameter directly fed from HTTP query string without sanitizer.",
      "[Reasoning Gemma 27B] Replaced AST node with ParameterizedTupleBinding.",
      "[Verification] SQLFluff security rule L001 and Bandit B608 passed."
    ],
    diffStats: { additions: 13, deletions: 5 },
    status: "unresolved"
  },
  {
    id: "vuln-path-03",
    title: "Path Traversal Arbitrary File Read in load_user_document",
    severity: "High",
    cvssScore: 8.6,
    cwe: "CWE-22: Improper Limitation of a Pathname",
    file: "src/utils/file_loader.py",
    lineRange: "L28 - L35",
    category: "Path Traversal",
    impactSummary:
      "Unvalidated relative path concatenation (`os.path.join(BASE_DIR, filename)`) enables directory traversal (`../../etc/passwd` or `.env` credential extraction).",
    upstreamBlastRadius: [
      "/src/api/documents.py (download endpoint)",
      "/src/services/exporter.py (report generation utility)"
    ],
    vulnerableCode: `def load_user_document(filename):
    # Vulnerable: User supplied filename can traverse out of storage
    filepath = os.path.join("/var/storage/docs", filename)
    with open(filepath, "r") as f:
        return f.read()`,
    healedPatch: `import os
from pathlib import Path

STORAGE_BASE = Path("/var/storage/docs").resolve()

def load_user_document(filename: str) -> str:
    """
    Refactored via Gemma 2 27B.
    Strict path containment check prevents path traversal escapes.
    """
    safe_path = (STORAGE_BASE / filename).resolve()
    # Invariant: Resolved target must reside strictly inside STORAGE_BASE
    if not safe_path.is_relative_to(STORAGE_BASE):
        raise PermissionError("Access denied: Path traversal attempted")
    
    with open(safe_path, "r", encoding="utf-8") as f:
        return f.read()`,
    patchExplanation: [
      "Switched to Python pathlib.Path with deterministic .resolve() canonicalization.",
      "Added strict containment barrier using safe_path.is_relative_to(STORAGE_BASE).",
      "Explicit UTF-8 encoding declaration to prevent character normalization exploits."
    ],
    gemmaReasoningLogs: [
      "[AST Router Gemma 9B] Detected os.path.join without path sanitization.",
      "[Graph-RAG] Path argument connected to public download API route.",
      "[Reasoning Gemma 27B] Synthesized path containment barrier with PermissionError guard.",
      "[Verification] Bandit B108 check passed."
    ],
    diffStats: { additions: 14, deletions: 4 },
    status: "unresolved"
  },
  {
    id: "vuln-secret-04",
    title: "Hardcoded Fallback JWT Secret in verify_token",
    severity: "High",
    cvssScore: 7.8,
    cwe: "CWE-798: Use of Hard-coded Credentials",
    file: "src/auth/jwt.py",
    lineRange: "L15 - L21",
    category: "Secrets",
    impactSummary:
      "Fallback default secret string `'super-secret-dev-key'` allows forgery of administrator JWT tokens if environment variable `JWT_SECRET` is omitted in production.",
    upstreamBlastRadius: [
      "/src/gateway/route.py (relies on JWT validator for all admin routes)",
      "/src/middleware/auth.py (verifies incoming bearer tokens)"
    ],
    vulnerableCode: `def verify_token(token):
    # Insecure fallback default secret
    secret = os.getenv("JWT_SECRET", "super-secret-dev-key")
    return jwt.decode(token, secret, algorithms=["HS256"])`,
    healedPatch: `import os
import jwt

def verify_token(token: str) -> dict:
    """
    Refactored via Gemma 2 27B.
    Enforced mandatory environment configuration with strict cryptographic entropy check.
    """
    secret = os.getenv("JWT_SECRET")
    if not secret or len(secret) < 32:
        raise RuntimeError("CRITICAL: JWT_SECRET environment variable is missing or insecure")
    
    return jwt.decode(token, secret, algorithms=["HS256"])`,
    patchExplanation: [
      "Removed hardcoded insecure fallback string entirely.",
      "Enforced mandatory minimum 32-character secret entropy requirement.",
      "Throws fast-fail RuntimeError at startup if production secret is unconfigured."
    ],
    gemmaReasoningLogs: [
      "[AST Router Gemma 9B] Flagged constant string literal inside os.getenv default.",
      "[Reasoning Gemma 27B] Hardcoded secret compromises entire identity federation layer.",
      "[Transformation Engine] Added strict entropy validation guard.",
      "[Verification] TruffleHog / GitLeaks pattern clean."
    ],
    diffStats: { additions: 11, deletions: 3 },
    status: "unresolved"
  },
  {
    id: "vuln-auth-05",
    title: "Missing Transaction Replay Protection & Idempotency Key Check",
    severity: "Medium",
    cvssScore: 5.3,
    cwe: "CWE-294: Authentication Bypass by Capture-replay",
    file: "src/api/transfer.py",
    lineRange: "L88 - L94",
    category: "Auth",
    impactSummary:
      "Financial fund transfer endpoint accepts duplicate POST requests without verifying Idempotency-Key header, leading to double-spend vulnerabilities under network timeouts.",
    upstreamBlastRadius: [
      "/src/services/billing.py (charges customer ledger)",
      "/src/gateway/route.py (public entrypoint)"
    ],
    vulnerableCode: `def process_transfer(request):
    data = request.json
    # Missing Idempotency-Key validation allows duplicate debit
    return ledger.debit(data["account_id"], data["amount"])`,
    healedPatch: `from fastapi import HTTPException

def process_transfer(request):
    data = request.json
    idempotency_key = request.headers.get("Idempotency-Key")
    
    # Refactored via Gemma 2 27B: Strict replay barrier
    if not idempotency_key:
        raise HTTPException(status_code=400, detail="Idempotency-Key header required")
    
    if redis_client.set(f"idemp:{idempotency_key}", "locked", nx=True, ex=300) is None:
        raise HTTPException(status_code=409, detail="Duplicate transaction request blocked")
    
    return ledger.debit(data["account_id"], data["amount"])`,
    patchExplanation: [
      "Required mandatory 'Idempotency-Key' HTTP header for all state-changing debit actions.",
      "Implemented distributed Redis atomic lock (`nx=True`, 300s TTL) to prevent race conditions."
    ],
    gemmaReasoningLogs: [
      "[AST Router Gemma 9B] Identified missing idempotency headers on transactional route.",
      "[Reasoning Gemma 27B] Financial state change without replay token allows balance depletion.",
      "[Transformation Engine] Injected atomic Redis idempotency guard."
    ],
    diffStats: { additions: 12, deletions: 2 },
    status: "unresolved"
  }
];

export const DEFAULT_SCAN_RESULT: RepositoryScanResult = {
  repoUrl: "https://github.com/enterprise-security/payment-gateway-service",
  branch: "main",
  commitHash: "7f4c9a1",
  scanTimestamp: "Just now",
  durationMs: 1840,
  stats: {
    totalFiles: 28,
    linesOfCode: 3420,
    vulnerabilitiesCount: 5,
    criticalCount: 2,
    highCount: 2,
    mediumCount: 1,
    autoHealAvailable: 5,
    sovereignComputeTime: "1.84s (Groq + HF)",
  },
  vulnerabilities: DEFAULT_VULNERABILITIES,
  graphNodes: [
    { id: "route", label: "/src/gateway/route.py", file: "src/gateway/route.py", type: "entrypoint", x: 70, y: 70, risk: "High" },
    { id: "main", label: "/src/main.py (eval)", file: "src/main.py", type: "vulnerable", x: 250, y: 70, risk: "Critical" },
    { id: "billing", label: "/src/db/billing.py (SQLi)", file: "src/db/billing.py", type: "vulnerable", x: 250, y: 170, risk: "Critical" },
    { id: "jwt", label: "/src/auth/jwt.py (Secret)", file: "src/auth/jwt.py", type: "vulnerable", x: 70, y: 170, risk: "High" },
    { id: "file_loader", label: "/src/utils/file_loader.py", file: "src/utils/file_loader.py", type: "vulnerable", x: 430, y: 120, risk: "High" },
    { id: "healed_node", label: "Gemma 2 27B Auto-Patches", file: "Unified Healed AST", type: "healed", x: 430, y: 220, risk: "Low" }
  ],
  graphEdges: [
    { source: "route", target: "main", label: "CALLS eval()", risk: "high" },
    { source: "route", target: "billing", label: "QUERIES SQL", risk: "high" },
    { source: "jwt", target: "route", label: "AUTHENTICATES", risk: "medium" },
    { source: "main", target: "file_loader", label: "READS FILE", risk: "medium" },
    { source: "main", target: "healed_node", label: "AUTO-HEALED", risk: "safe" },
    { source: "billing", target: "healed_node", label: "AUTO-HEALED", risk: "safe" }
  ],
  modelLineage: {
    routingModel: "Gemma 2 9B-IT (Router & Ingestion)",
    routerHardware: "Groq LPU Hardware Array (540 tokens/sec)",
    routerTokens: 512,
    routerLatencyMs: 44,
    reasoningModel: "Gemma 2 27B-IT (Deep Logic Reasoner)",
    reasoningHardware: "Hugging Face TensorRT-LLM FP8 Cluster",
    astDepthChecked: 4,
    openWeightsLoopVerified: true,
    zeroEgressSignature: "SHA256:8b4e72c81...AIR-GAPPED-SOVEREIGN-VERIFIED"
  }
};
