<!-- Authentic SIFT-HUNTER run on benchmarks/cases/case001 (model claude-sonnet-4-6):
     6 findings, 7 self-corrections applied, 4 hallucinations caught, 503s.
     Reproduce: export ANTHROPIC_API_KEY=... && sift-hunter analyze benchmarks/cases/case001/evidence/*.csv -->

# Incident Report: SIFT-HUNTER Analysis
> **Generated:** 2026-06-01T10:24:23.355081Z  
> **Report ID:** `IR-331be5dc`  
> **Tool:** SIFT-HUNTER v1.0.0

---
## Executive Summary

A host compromise was identified on the system associated with user 'victim', involving a malicious executable (svchost_helper.exe) deployed to a Temp directory and registered for persistence via a Windows Registry Run key (T1547.001). The executable masquerades as a legitimate Windows system process and has been confirmed executed at least twice, with the last recorded execution on 2024-01-15 at 14:23:11. An active SMB connection from the System process to an internal host (192.168.1.10:445) was observed concurrently with evidence of a C2 channel, raising concern for lateral movement. Overall impact is assessed as significant: persistence is established, execution is confirmed, and potential spread to at least one additional internal host cannot be ruled out.

## Finding Confidence Summary

| Level | Count |
|-------|-------|
| 🔴 CONFIRMED | 0 |
| 🟠 PROBABLE | 5 |
| 🟡 POSSIBLE | 1 |
| ⚪ UNVERIFIED | 0 |
| **Total** | **6** |
| Hallucinations Caught | 4 |
| Self-Corrections Applied | 7 |

## Detailed Findings

### 1. Malicious Executable Registered in Registry Run Key

**Type:** PERSISTENCE  
**Confidence:** 🟠 PROBABLE  
**Agent:** disk_analyst  

The registry key SOFTWARE\Microsoft\Windows\CurrentVersion\Run contains a value named 'WindowsHelper' pointing to C:\Users\victim\AppData\Local\Temp\svchost_helper.exe. This is a well-known persistence mechanism (T1547.001) that causes the executable to launch at every user logon. The use of a Temp directory path and a name mimicking a legitimate Windows service (svchost) further indicates malicious intent. This is corroborated by MFT and prefetch evidence confirming the file exists and has been executed.  

**Evidence Excerpt:**
```
registry_raw row: KeyPath=SOFTWARE\Microsoft\Windows\CurrentVersion\Run, ValueName=WindowsHelper, ValueData=C:\Users\victim\AppData\Local\Temp\svchost_helper.exe
```

**MITRE ATT&CK:**
- [T1547.001](#) — Registry Run Keys (Persistence)
- [T1543.003](#) — Windows Service (Persistence)
- [T1036](#) — Masquerading (Defense Evasion)

**Artifact:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\WindowsHelper`

**Verification:** Approved by verification agent

---

### 2. SMB Connection to Internal Host (Possible Lateral Movement)

**Type:** LATERAL_MOVEMENT  
**Confidence:** 🟡 POSSIBLE  
**Agent:** disk_analyst  

The System process (PID 4) has an ESTABLISHED SMB connection (port 445) to internal host 192.168.1.10. While SMB connections from System are not inherently malicious, in the context of an active compromise with a C2 channel present, this warrants investigation as a potential lateral movement attempt — e.g., pass-the-hash, remote service creation, or file share access to pivot to 192.168.1.10.  

**Evidence Excerpt:**
```
TCPv4,192.168.1.50,50122,192.168.1.10,445,ESTABLISHED,4,System
```

**MITRE ATT&CK:**
- [T1021.002](#) — SMB/Windows Admin Shares (Lateral Movement)
- [T1570](#) — Lateral Tool Transfer (Lateral Movement)
- [T1543.003](#) — Windows Service (Persistence)
- [T1071](#) — Application Layer Protocol (Command and Control)

**Artifact:** `Network connection from PID 4 (System) to 192.168.1.10:445`

**Verification:** Approved by verification agent

---

### 3. svchost_helper.exe Executed from Temp Directory (Prefetch Evidence)

**Type:** EXECUTION  
**Confidence:** 🟠 PROBABLE  
**Agent:** disk_analyst  

Prefetch analysis confirms that svchost_helper.exe was executed at least twice from C:\Users\victim\AppData\Local\Temp, with the last recorded run at 2024-01-15 14:23:11. The executable name mimics the legitimate Windows svchost.exe process (process masquerading). Execution from a Temp directory is anomalous for any legitimate system binary. The prefetch hash in the source filename (SVCHOST_HELPER.EXE-1A2B3C4D.pf) is consistent with this path. NOTE: The prefetch tool output uses a two-level structure — 'executable' at the top level and 'ExecutableName' nested inside an 'entry' sub-object; the evidence excerpt below reflects this accurately.  

**Evidence Excerpt:**
```
prefetch_suspicious entry: top-level 'executable'='C:\Users\victim\AppData\Local\Temp\svchost_helper.exe', issues=['EXECUTION_FROM_TEMP', 'PROCESS_MASQUERADING'], entry.ExecutableName='C:\Users\victim\AppData\Local\Temp\svchost_helper.exe', entry.RunCount='2', entry.LastRun='2024-01-15 14:23:11', entry.SourceFilename='SVCHOST_HELPER.EXE-1A2B3C4D.pf'
```

**MITRE ATT&CK:**
- [T1036](#) — Masquerading (Defense Evasion)
- [T1190](#) — Exploit Public-Facing Application (Initial Access)

**Artifact:** `C:\Windows\Prefetch\SVCHOST_HELPER.EXE-1A2B3C4D.pf`

**Verification:** [accepted at iteration cap]

---

### 4. Suspicious svchost.exe Spawned by winword.exe

**Type:** EXECUTION  
**Confidence:** 🟠 PROBABLE  
**Agent:** disk_analyst  

The process list shows a svchost.exe (PID 4288) with a parent process of winword.exe (PPID 3120). Legitimate svchost.exe processes are always spawned by services.exe; a Word document spawning svchost.exe is a strong indicator of malicious macro execution or exploitation of Microsoft Word. Furthermore, the path of this svchost.exe is C:\Users\victim\AppData\Local\Temp\svchost.exe — not the legitimate C:\Windows\System32\svchost.exe — confirming this is a masquerading malicious binary.  

**Evidence Excerpt:**
```
4288,3120,svchost.exe,winword.exe,C:\Users\victim\AppData\Local\Temp\svchost.exe
```

**MITRE ATT&CK:**
- [T1543.003](#) — Windows Service (Persistence)
- [T1057](#) — Process Discovery (Discovery)
- [T1566](#) — Phishing (Initial Access)
- [T1036](#) — Masquerading (Defense Evasion)
- [T1190](#) — Exploit Public-Facing Application (Initial Access)

**Artifact:** `C:\Users\victim\AppData\Local\Temp\svchost.exe (PID 4288)`

**Verification:** [accepted at iteration cap]

---

### 5. Timestomping Detected on svchost_helper.exe

**Type:** DEFENSE_EVASION  
**Confidence:** 🟠 PROBABLE  
**Agent:** disk_analyst  

The MFT entry for svchost_helper.exe shows a discrepancy between the $STANDARD_INFORMATION (SI) timestamps and the $FILE_NAME (FN) timestamps. The SI Created timestamp is 2024-01-15 14:00:00 while the FN Created timestamp is 2024-01-13 08:00:00. This two-day gap is a classic indicator of timestomping — a technique used to manipulate file metadata to evade timeline-based forensic analysis. The FN timestamps, which are harder to manipulate, are considered more reliable.  

**Evidence Excerpt:**
```
"_flags": ["TIMESTOMPING: SI=2024-01-15 14:00:00 FN=2024-01-13 08:00:00", "SUSPICIOUS_LOCATION: C:\\Users\\victim\\AppData\\Local\\Temp\\svchost_helper.exe"]
```

**MITRE ATT&CK:**
- [T1070.006](#) — Timestomp (Defense Evasion)
- [T1036](#) — Masquerading (Defense Evasion)
- [T1021.002](#) — SMB/Windows Admin Shares (Lateral Movement)

**Artifact:** `C:\Users\victim\AppData\Local\Temp\svchost_helper.exe (MFT Entry 1334)`

**Verification:** [accepted at iteration cap]

---

### 6. Outbound C2 Connection to 45.137.21.9:4444 from Malicious svchost.exe

**Type:** EXECUTION  
**Confidence:** 🟠 PROBABLE  
**Agent:** disk_analyst  

An established TCP connection was observed from the victim host (192.168.1.50:49671) to the external IP 45.137.21.9 on port 4444, attributed to PID 4288 (the malicious svchost.exe spawned by winword.exe). Port 4444 is a well-known default listener port for post-exploitation frameworks. This connection is corroborated by the process list showing PID 4288 as a masquerading malicious binary in the Temp directory. NOTE: Per correction review, the Meterpreter/framework attribution is an inference and is not directly confirmed by tool output; the connection itself is confirmed. The type has been corrected from LATERAL_MOVEMENT to reflect the outbound C2 nature of this activity.  

**Evidence Excerpt:**
```
TCPv4,192.168.1.50,49671,45.137.21.9,4444,ESTABLISHED,4288,svchost.exe
```

**MITRE ATT&CK:**
- [T1071](#) — Application Layer Protocol (Command and Control)
- [T1057](#) — Process Discovery (Discovery)
- [T1570](#) — Lateral Tool Transfer (Lateral Movement)
- [T1036](#) — Masquerading (Defense Evasion)
- [T1190](#) — Exploit Public-Facing Application (Initial Access)

**Artifact:** `PID 4288 — C:\Users\victim\AppData\Local\Temp\svchost.exe`

**Verification:** [accepted at iteration cap]

---

## Attack Timeline

- `2026-06-01T10:23:58.430316Z` — Malicious Executable Registered in Registry Run Key *(Confidence: PROBABLE)*
- `2026-06-01T10:23:58.430326Z` — SMB Connection to Internal Host (Possible Lateral Movement) *(Confidence: POSSIBLE)*
- `2024-01-15T14:23:11Z` — svchost_helper.exe Executed from Temp Directory (Prefetch Evidence) *(Confidence: PROBABLE)*
- `2026-06-01T10:23:58.430332Z` — Suspicious svchost.exe Spawned by winword.exe *(Confidence: PROBABLE)*
- `2024-01-15T14:00:00` — Timestomping Detected on svchost_helper.exe *(Confidence: PROBABLE)*
- `2026-06-01T10:23:58.430336Z` — Outbound C2 Connection to 45.137.21.9:4444 from Malicious svchost.exe *(Confidence: PROBABLE)*

## Evidence Inventory

| File | SHA256 |
|------|--------|
| `mft.csv` | computed on ingest |
| `prefetch.csv` | computed on ingest |
| `registry.csv` | computed on ingest |
| `pslist.csv` | computed on ingest |
| `netscan.csv` | computed on ingest |

## Self-Assessment & Limitations

Evidence available included registry hive data, MFT records, prefetch artifacts, and live network connection state — providing a reasonably strong basis for the persistence and execution findings. No findings reached CONFIRMED confidence; five are rated PROBABLE and one POSSIBLE, reflecting the absence of full forensic corroboration (e.g., memory analysis, full packet capture, or endpoint telemetry) for several conclusions. The lateral movement finding (disk_006) rests solely on a single observed SMB connection from PID 4 and contextual inference; without authentication logs, event logs (e.g., 4624/4648), or SMB session details from 192.168.1.10, this cannot be confirmed as malicious. Four hallucinations were caught and corrected during analysis, indicating some initial over-inference from limited evidence — the final findings reflect those corrections. We may have missed: additional persistence mechanisms not captured in the registry snapshot, staging or dropper activity that preceded the Temp-directory placement, lateral movement to hosts beyond 192.168.1.10, and any actions taken by the attacker during the window between first and last execution of svchost_helper.exe.

## Recommendations

1. Immediately isolate the compromised host from the network to prevent further lateral movement or C2 communication while investigation continues.  
2. Investigate 192.168.1.10 as a potential secondary victim: collect authentication logs, SMB session records, and run endpoint triage (prefetch, registry, MFT) to determine whether lateral movement succeeded.  
3. Acquire and analyze a full memory image from the compromised host to identify the running svchost_helper.exe process, injected code, C2 configuration, and any in-memory artifacts not visible on disk.  
4. Collect and review Windows Security Event Logs (particularly Event IDs 4624, 4648, 4688, 7045) from both the compromised host and 192.168.1.10 to reconstruct the full attack timeline and confirm or refute pass-the-hash or remote service creation.  
5. Submit svchost_helper.exe for static and dynamic malware analysis (sandbox detonation and reverse engineering) to identify malware family, C2 infrastructure, capabilities, and any additional payloads or dropped files.  
6. Conduct a broader hunt across the environment for the same IOCs: the file hash of svchost_helper.exe, the registry value name 'WindowsHelper', Temp-directory executables mimicking system process names, and outbound connections to the identified C2 address.  
7. Preserve all forensic artifacts (registry hives, prefetch files, MFT, network logs) under chain-of-custody before any remediation actions are taken on the affected host.  
8. After containment, perform a full credential reset for the 'victim' account and any accounts that authenticated to or from the compromised host, given the possibility of credential theft or pass-the-hash activity.  

---

*Report generated by SIFT-HUNTER — Self-correcting Intelligent Forensic Triage & Hunt*  
*All findings include confidence levels and evidence citations.*
