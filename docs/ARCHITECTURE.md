# SIFT-HUNTER Architecture

## System Overview

SIFT-HUNTER combines **Custom MCP Server (Pattern 2)** with **Multi-Agent Orchestration (Pattern 3)** to create a forensic analysis system that is architecturally secure, self-correcting, and auditable.

## Component Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                         SIFT-HUNTER                                  │
│                                                                      │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │                    MCP Server Layer                            │  │
│  │  ┌──────────────────────────────────────────────────────┐     │  │
│  │  │              SECURITY BOUNDARY (Python)              │     │  │
│  │  │  @read_only @validated_path — enforced by decorator  │     │  │
│  │  │  BLOCKED: rm,dd,wget,curl,nc,ssh,chmod,kill,bash...  │     │  │
│  │  │  ALLOWED: vol3,MFTECmd,PECmd,RegRipper,log2timeline  │     │  │
│  │  └──────────────────────────────────────────────────────┘     │  │
│  │                              │                                  │  │
│  │  ┌──────────────────────────────────────────────────────┐     │  │
│  │  │                  Forensic Tools                       │     │  │
│  │  │  Disk: timeline│mft│prefetch│amcache│registry│usnjrnl│     │  │
│  │  │  Memory: volatility│processes│network│credentials     │     │  │
│  │  │  Enrichment: virustotal│abuseipdb│mitre_attack        │     │  │
│  │  └──────────────────────────────────────────────────────┘     │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                              │ MCP calls                             │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │              Multi-Agent Orchestrator (LangGraph)              │  │
│  │                                                                │  │
│  │  START ──► Triage ──► Disk Analyst ──► Memory Analyst ──►     │  │
│  │                                                       │       │  │
│  │           ◄──────────────────────────────────────── Correlator│  │
│  │           │                                                    │  │
│  │           ▼                                                    │  │
│  │        Verifier ◄─────────────────────────────────────────►  │  │
│  │           │  (self-correction:                                 │  │
│  │           │   detects hallucinations,                          │  │
│  │           │   routes back up to 3x)                           │  │
│  │           ▼                                                    │  │
│  │        Reporter ──► END                                        │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                              │                                       │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │                    Core System                                  │  │
│  │  Audit Logger (JSONL)  │  Hallucination Detector               │  │
│  │  Evidence Integrity    │  Confidence Assignment                 │  │
│  │  Chain of Custody      │  Pydantic Models (typed everywhere)   │  │
│  └───────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

## Security Boundaries

| Layer | Mechanism | What It Prevents |
|-------|-----------|-----------------|
| Path Validator | Python `Path.resolve()` + allowlist | Traversal, symlink escape, system dir access |
| Command Safety | Blocklist + metacharacter scan | rm/dd/wget/curl injection, shell escapes |
| `@read_only` decorator | Applied to ALL tool functions | Write operations, destructive commands |
| `@validated_path` decorator | Applied to ALL path arguments | Evidence root escape |
| Subprocess isolation | `shell=False` on all `subprocess.run()` calls | Shell injection via arguments |

## Agent Responsibilities

| Agent | Phase | Primary Responsibility |
|-------|-------|----------------------|
| Triage | 1 | Evidence inventory, integrity hashing, analysis planning |
| Disk Analyst | 2 | MFT, Prefetch, Registry, Amcache, USN, ShellBags |
| Memory Analyst | 3 | Process analysis, network connections, credentials (Volatility3) |
| Correlator | 4 | Cross-reference findings, build timeline, MITRE mapping |
| **Verifier** | **5** | **Hallucination detection, confidence validation, self-correction routing** |
| Reporter | 6 | Final report generation with executive summary and self-assessment |

## Self-Correction Loop Detail

```
Verifier receives all findings
    │
    ├─ Automated: batch_verify() checks raw_evidence_excerpt vs tool outputs
    │              (catches claims not grounded in evidence)
    │
    ├─ LLM: Claude reviews findings vs tool output excerpts
    │       (catches semantic hallucinations, contradiction detection)
    │
    ├─ If issues found:
    │   ├─ Create Correction object (logged to audit trail)
    │   ├─ Check correction depth (max 3 per finding)
    │   ├─ Route to target agent (disk_analyst / memory_analyst)
    │   └─ Agent re-runs with correction context
    │
    └─ If clean OR max loops reached:
        └─ Route to Reporter
```

## Data Flow

```
Evidence Files
    │
    ▼ (ingest_evidence: hash, type detection)
Evidence Objects (SHA256 verified)
    │
    ▼ (forensic tools via MCP server)
ToolExecution objects (raw_output, output_hash, command)
    │
    ▼ (LLM agent analysis)
Finding objects (title, description, confidence, raw_evidence_excerpt, mitre_ttps)
    │
    ▼ (verifier + hallucination detector)
Verified Findings + Corrections
    │
    ▼ (reporter)
IncidentReport (Markdown + JSON)
```
