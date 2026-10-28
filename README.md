# 🛡️ GemmaGuard AI: Agentic Graph-RAG Code-Reviewer & Auto-Healer

> Built for the **MLH Hackathon** — An enterprise-grade developer security tool powered by a tiered architecture of 100% open-weights **Gemma 2** models.

[![Next.js](https://img.shields.io/badge/Next.js-14-black?style=flat&logo=next.js)](https://nextjs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0-blue?style=flat&logo=typescript)](https://www.typescriptlang.org/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-3%2F4-38B2AC?style=flat&logo=tailwind-css)](https://tailwindcss.com/)
[![Gemma 2](https://img.shields.io/badge/Gemma_2-9B_%26_27B-emerald?style=flat)](https://ai.google.dev/gemma)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

---

## 🏛️ Architecture & Tiered Model Strategy

GemmaGuard AI implements an autonomous multi-tier pipeline to audit repositories, trace upstream dependency blast radius, and synthesize auto-healing patches with zero physical hardware dependencies:

```
[ Target Repository URL ]
          │
          ▼
┌───────────────────────────────────────────────┐
│  Tier 1: Gemma 2 9B Ingestion & Router       │
│  • Tokenizes multi-file code chunks           │
│  • Traverses Python AST call graph hierarchy  │
│  • Applies Qdrant vector indexing filters     │
│  • Hardware: Groq LPU Array (540 tokens/s)    │
└──────────────────────┬────────────────────────┘
                       │
                       ▼
┌───────────────────────────────────────────────┐
│  Tier 2: Gemma 2 27B Deep Reasoner & Healer  │
│  • Multi-file vulnerability & CVSS evaluation │
│  • Upstream blast radius tracing              │
│  • Synthesizes cryptographic refactor patches │
│  • Bandit SAST & MyPy strict AST verification │
│  • Hardware: Hugging Face TensorRT FP8        │
└──────────────────────┬────────────────────────┘
                       │
                       ▼
┌───────────────────────────────────────────────┐
│  Tier 3: Privacy Guard Verification           │
│  • 100% sovereign air-gapped local execution  │
│  • Zero cloud data egress guaranteed          │
└───────────────────────────────────────────────┘
```

---

## 🚀 Key Features

- **Paste Any Repository URL:** Instant analysis across GitHub / GitLab repositories and specific branches (`main`, `dev`, `release-v2`).
- **Pre-Configured Demo Blueprints:**
  - `payment-gateway-service`: FastAPI & PostgreSQL billing microservice (5 vulnerabilities: RCE, SQLi, Path Traversal, Secrets, Replay).
  - `auth-microservice`: JWT broker & identity management (3 vulnerabilities: Weak JWT Secret, SQLi, Broken Access).
  - `cloud-admin-portal`: Flask dashboard & telemetry export (4 vulnerabilities: SSRF, IDOR, Path Traversal, RCE).
- **At-a-Glance Repository Health KPI:** Files Scanned, Issues Found, Severity Spectrum, and Auto-Healed Patch Tracker.
- **Vulnerability Triage Queue:** Filter by severity (`Critical`, `High`, `Medium`) or search by file path / CWE identifier.
- **Unified GitHub-Style AST Code Diff:** Side-by-side or unified view with red deletions and auto-healed green additions.
- **Interactive Graph-RAG Topology Visualizer:** Interactive SVG network map showing how vulnerabilities traverse caller/callee links and how the auto-healed node neutralizes the exploit.
- **One-Click PR Markdown Export:** Formatted pull-request audit ready to paste into GitHub PR reviews.
- **Cybernetic Sound Feedback:** Lightweight Web Audio API synthesizer for tactile developer feedback.

---

## 🛠️ Quick Start & Local Development

### Prerequisites
- Node.js 18+ (tested on Node.js 20 & 24)
- npm or pnpm

### Installation

```bash
# 1. Clone repository
git clone https://github.com/lasyaishu05-spec/GemmaGuard-AI.git
cd GemmaGuard-AI

# 2. Install dependencies
npm install

# 3. Start local development server
npm run dev
```

Open **[http://localhost:3000](http://localhost:3000)** in your browser.

### Production Build

```bash
npm run build
npm run start
```

---

## 🔒 100% Sovereign & Private

GemmaGuard AI operates entirely on open-weights foundation models (**Gemma 2 9B** and **Gemma 2 27B**). Source code files and AST tokens are analyzed in sovereign memory without external 3rd-party cloud egress.

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
