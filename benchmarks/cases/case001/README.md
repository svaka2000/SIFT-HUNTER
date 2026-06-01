# Benchmark Case 001 — Spear-phish → Metasploit C2

A self-contained, **reproducible** incident used to prove SIFT-HUNTER's detection
engine. The evidence is synthetic *pre-exported* forensic artifacts (the CSV formats
Eric Zimmerman tools and Volatility produce), so the case runs with **no SIFT
Workstation, no forensic binaries, and no API key**.

## The incident

A Windows 10 host was compromised via spear-phishing:

1. **Initial access / execution** — an MSHTA (`T1218.005`) payload runs.
2. **Defense evasion** — it drops `svchost_helper.exe` into `AppData\Local\Temp` and
   **timestomps** it (`$STANDARD_INFORMATION` ≠ `$FILE_NAME`, `T1070.006`).
3. **Persistence** — a `...\CurrentVersion\Run\WindowsHelper` key points at the payload
   (`T1547.001`).
4. **Masquerade** — a fake `svchost.exe` runs from Temp with parent `winword.exe`
   (`T1036`).
5. **Command & control** — it beacons to `45.137.21.9:4444` (Metasploit default, `T1071`).

## Run the deterministic detector (no key, no binaries)

```bash
python -m benchmarks.detect_case benchmarks/cases/case001
```

This parses each artifact, runs the tool `find_suspicious` / `find_persistence`
detectors, and maps the results to MITRE ATT&CK offline. `tests/test_case001.py` locks
the expected detections in CI.

## Run the full agent pipeline (needs an LLM key)

```bash
export GROQ_API_KEY=...   # or ANTHROPIC_API_KEY
python -m benchmarks.runner --case benchmarks/cases/case001
```

## Files

| File | Tool / format | Planted IOC |
|------|---------------|-------------|
| `evidence/mft.csv` | MFTECmd | timestomped `svchost_helper.exe` in Temp |
| `evidence/prefetch.csv` | PECmd | Temp execution + MSHTA LOLBin |
| `evidence/registry.csv` | RECmd | `Run\WindowsHelper` persistence |
| `evidence/pslist.csv` | Volatility pslist | `svchost.exe` masquerade (parent `winword.exe`) |
| `evidence/netscan.csv` | Volatility netscan | C2 to `45.137.21.9:4444` |
| `ground_truth.json` | — | expected findings (runner-compatible) |
