# Provenance - cridex.vmem

**Source sample:** `cridex.vmem` - a Cridex/Feodo banking-trojan infection from the
**Volatility Foundation "Memory Samples"** page
(https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples), Windows XP
SP2 x86. Alongside zeus.vmem it is one of the most widely used teaching images in DFIR.

**The evidence/ files** are normalized parsed-tool-output (`vol3 windows.pslist /
windows.malfind / windows.netscan`) representing this sample's **publicly documented
indicators**, with realistic benign processes and connections added so precision is a
meaningful measurement. Equivalent input is reproducible by running Volatility 3 on the
public cridex.vmem image.

## Documented ground-truth indicators (with citations)

| Indicator | Detail | Source |
|-----------|--------|--------|
| Injected code (malfind) | `explorer.exe` PID 1484 @ 0x1460000 and `reader_sl.exe` PID 1640 @ 0x3d0000 - MZ header, PAGE_EXECUTE_READWRITE | SemperSecurus (A. DiMino), "Cridex analysis using Volatility" (2012-08) http://www.sempersecurus.org/2012/08/cridex-analysis-using-volatility.html |
| Process anomaly | `reader_sl.exe` (PID 1640, Adobe Reader SpeedLauncher) running as a **child of explorer.exe** (PID 1484) | SemperSecurus (2012); contagio mirror https://contagiodump.blogspot.com/2012/08/cridex-analysis-using-volatility-by.html |
| C2 connections | `explorer.exe` (1484) → **41.168.5.140:8080** and **125.19.103.198:8080**; beacon path `/zb/v_01_a/in/` | SemperSecurus (2012); aleprada cridex notes https://github.com/aleprada/memory-forensics-challenges/blob/main/Volatility%20Foundation%20samples/cridex.md |
| Listener | `explorer.exe` listening on 127.0.0.1:1038 (local, benign per external-only C2 heuristic) | SemperSecurus (2012) |

Index of the public samples: Volatility Foundation wiki - Memory Samples
(https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples).
