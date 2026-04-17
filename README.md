# SIFT-HUNTER

**Self-correcting Intelligent Forensic Triage & Hunt — Unified Network of Expert Responders**

> SANS FIND EVIL! Hackathon Submission | Pattern 2 (Custom MCP Server) + Pattern 3 (Multi-Agent)

SIFT-HUNTER is an autonomous AI incident response system that analyzes disk images and memory captures on the SANS SIFT Workstation, **self-corrects its findings**, maps to MITRE ATT&CK, and generates structured incident reports with full audit trails.

---

## Why SIFT-HUNTER Wins

| Criterion | Our Approach | Win Condition |
|-----------|-------------|---------------|
| **Autonomous Execution** ⭐ | LangGraph self-correction loop — verifier catches mistakes and re-routes analysts | 3+ visible self-correction cycles in demo |
| **IR Accuracy** | Hallucination detector cross-checks every claim vs raw tool output | Honest findings: says "uncertain" instead of fabricating |
| **Analysis Depth** | Deep expertise in disk forensics (MFT, Prefetch, Amcache, Registry, USN, ShellBags) + memory (Volatility3) | Master fewer artifact types deeply |
| **Constraint Implementation** | Python decorator architecture — the server **cannot** expose destructive commands | Try `sift-hunter check "rm -rf /"` — BLOCKED |
| **Audit Trail** | Structured JSONL: every tool call, finding, correction, and reasoning logged | `sift-hunter audit <finding-id>` shows full chain |
| **Usability** | One-command install, modular architecture, ADDING_TOOLS.md tutorial | Fork → add tool → under 1 hour |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    SIFT-HUNTER System                        │
│                                                             │
│  ┌──────────────────┐    ┌────────────────────────────────┐ │
│  │   MCP Server     │    │     Multi-Agent Orchestrator   │ │
│  │  (Pattern 2)     │    │       (LangGraph / Pattern 3)  │ │
│  │                  │    │                                │ │
│  │ ┌─────────────┐  │    │  START → Triage → Disk →      │ │
│  │ │ Security    │  │    │  Memory → Correlator →        │ │
│  │ │ Layer       │◄─┼────┤  Verifier ──┐  → Reporter    │ │
│  │ │ (read-only) │  │    │             │                 │ │
│  │ └─────────────┘  │    │      (self-correction loop)   │ │
│  │                  │    │             │                 │ │
│  │ Forensic Tools:  │    │    Disk ◄───┘                 │ │
│  │ • log2timeline   │    │    Memory ◄─┘                 │ │
│  │ • MFTECmd        │    └────────────────────────────────┘ │
│  │ • PECmd (Prefetch│                                       │
│  │ • Amcache        │    ┌─────────────────┐                │
│  │ • RegRipper      │    │   Core System   │                │
│  │ • SBECmd         │    │ • Audit Logger  │                │
│  │ • Volatility3    │    │ • Hallucination │                │
│  │ • VirusTotal API │    │   Detector      │                │
│  │ • AbuseIPDB API  │    │ • Evidence      │                │
│  │ • MITRE ATT&CK   │    │   Integrity     │                │
│  └──────────────────┘    └─────────────────┘                │
└─────────────────────────────────────────────────────────────┘
```

### The Self-Correction Loop (Tiebreaker)

```
Verifier finds issue with Finding X
    → Creates Correction record (logged to audit)
    → Routes back to Disk/Memory Analyst with correction instructions
    → Analyst re-examines with corrected focus
    → Verifier re-checks (up to 3 times per finding)
    → If still failing after 3 loops: force-accept with UNVERIFIED confidence
```

---

## Quick Start

### Requirements

- SANS SIFT Workstation (Ubuntu 22.04+) or equivalent Linux
- Python 3.11+
- `ANTHROPIC_API_KEY` environment variable

### One-Command Install

```bash
curl -fsSL https://raw.githubusercontent.com/your-org/sift-hunter/main/install.sh | bash
```

### Manual Install

```bash
git clone https://github.com/your-org/sift-hunter.git
cd sift-hunter
pip install -e .
export ANTHROPIC_API_KEY="your-key-here"
```

### Run Analysis

```bash
# Analyze disk image and memory capture
sift-hunter analyze /cases/disk.dd /cases/memory.dmp --output /cases/report.md

# Analyze entire evidence directory
sift-hunter analyze /mnt/evidence/ --output /tmp/incident-report.md

# Start MCP server (for Protocol SIFT integration)
sift-hunter server
```

### Query Audit Trail

```bash
# Trace any finding back to its raw tool evidence
sift-hunter audit <finding-id>

# Test security guardrails (judges: run this during demo)
sift-hunter check "rm -rf /evidence"    # → BLOCKED
sift-hunter check "wget attacker.com"   # → BLOCKED
sift-hunter check "vol3 -f evidence.mem windows.pslist.PsList"  # → ALLOWED
```

### Run Tests

```bash
pytest tests/ -v
pytest tests/test_security.py -v    # All 20 guardrail tests
pytest tests/test_accuracy.py -v    # Hallucination detector tests
```

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `ANTHROPIC_API_KEY` | **Yes** | Claude API key for all agent LLM calls |
| `SIFT_EVIDENCE_ROOTS` | No | Colon-separated allowed evidence dirs (default: `/cases:/mnt/evidence`) |
| `SIFT_OUTPUT_ROOT` | No | Output directory for reports/timelines (default: `/tmp/sift-output`) |
| `VT_API_KEY` | No | VirusTotal API key for hash enrichment |
| `ABUSEIPDB_API_KEY` | No | AbuseIPDB key for IP enrichment |
| `SIFT_MODEL` | No | Claude model ID (default: `claude-opus-4-7-20250514`) |

---

## What Gets Analyzed

### Disk Forensics
- **MFT** — File creation/modification, timestomping detection (SI vs FN mismatch)
- **Prefetch** — Execution history, suspicious executable locations
- **Amcache** — Program installation with SHA1 hashes for VT lookup
- **Registry** — Persistence mechanisms (Run keys, Services, Winlogon, IFEO)
- **USN Journal** — File system activity, log deletion anti-forensics
- **ShellBags** — Folder navigation history including deleted directories
- **Timeline** — Super-timeline via log2timeline/plaso

### Memory Forensics
- **Process List** — Suspicious parent-child relationships, process masquerading
- **Command Lines** — Obfuscated PowerShell, encoded commands, LOLBin abuse
- **Network Connections** — C2 indicators, lateral movement channels
- **Credentials** — Hash extraction via hashdump/cachedump
- **Malfind** — Code injection detection

### Threat Intelligence
- **MITRE ATT&CK** — Automatic technique mapping (offline-capable)
- **VirusTotal** — Hash/IP/domain reputation (when API key provided)
- **AbuseIPDB** — IP abuse confidence scoring

---

## Contributing / Adding Tools

See [docs/ADDING_TOOLS.md](docs/ADDING_TOOLS.md) — designed for sub-1-hour onboarding.

---

## License

MIT — See [LICENSE](LICENSE)
