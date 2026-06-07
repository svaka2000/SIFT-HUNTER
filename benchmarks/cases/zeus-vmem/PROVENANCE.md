# Provenance — zeus.vmem

**Source sample:** `zeus.vmem` — a Zeus/Zbot infection, one of the canonical public
memory images on the **Volatility Foundation "Memory Samples"** page
(https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples), Windows XP
SP2 x86. It is one of the most widely taught images in DFIR and is instantly
recognizable to SANS practitioners.

**The evidence/ files** are normalized parsed-tool-output (the columns produced by
`vol3 windows.pslist / windows.malfind / windows.netscan` and a registry export)
representing this sample's **publicly documented indicators**. Realistic benign
processes and connections are included so that precision is a meaningful measurement
(the detector must distinguish the malicious artifacts from the benign ones), not a
trivial 100%. Anyone can reproduce equivalent input by running Volatility 3 on the
public zeus.vmem image; the harness scores identically on a fresh export.

## Documented ground-truth indicators (with citations)

| Indicator | Detail | Source |
|-----------|--------|--------|
| Injected code (malfind) | `winlogon.exe` PID 624 and `svchost.exe` PID 856 — MZ header in PAGE_EXECUTE_READWRITE region | malwarereversing, "Zeus analysis in Volatility 2.0" (2011-09-23) https://malwarereversing.wordpress.com/2011/09/23/zeus-analysis-in-volatility-2-0/ |
| C2 connection | `svchost.exe` PID 856 → **193.104.41.75:80** (Moldova) | behindthefirewalls, "Zeus Trojan — memory forensics with Volatility" (2013-07) http://www.behindthefirewalls.com/2013/07/zeus-trojan-memory-forensics-with.html |
| Persistence | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` → `Userinit = ...,C:\WINDOWS\system32\sdra64.exe,` | malwarereversing (2011); behindthefirewalls (2013) |
| Dropped file | `\WINDOWS\system32\sdra64.exe` (handle held by winlogon.exe) | behindthefirewalls (2013) |
| Defense evasion | Windows Firewall disabled — `...FirewallPolicy\StandardProfile\EnableFirewall = 0` | behindthefirewalls (2013) |

Index of the public samples: Volatility Foundation wiki — Memory Samples
(https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples).
