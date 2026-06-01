# SIFT-HUNTER Accuracy Self-Assessment

> Honest evaluation of what this system gets right, what it misses, and what it fabricates.
> The judging criteria explicitly reward honesty over false confidence.

---

## Methodology

SIFT-HUNTER uses a multi-layer accuracy pipeline:

1. **Automated hallucination detection** — `src/sift_hunter/core/hallucination_detector.py` cross-checks every agent claim against raw tool output using regex extraction of file paths, IP addresses, registry keys, process (executable) names, and SHA hashes. Absent exact-token IOCs (IPs, hashes, registry keys) are flagged as fabrications; variable-representation file paths are flagged as uncertain.

2. **LLM verification pass** — The Verifier agent reviews findings semantically, catching contextual hallucinations that string-matching misses.

3. **Self-correction loop** — Flagged findings route back to the originating analyst for re-examination (up to 3 times per finding).

4. **Confidence labeling** — Every finding carries one of: CONFIRMED (2+ independent sources), PROBABLE (1 strong source), POSSIBLE (circumstantial), UNVERIFIED (single weak source or failed verification).

---

## What We Find Well

### High-Confidence Detection Categories

| Artifact Type | Accuracy | Notes |
|--------------|----------|-------|
| Registry Run key persistence | **High** | RegRipper output is structured; key paths are unambiguous |
| Prefetch execution history | **High** | PECmd produces reliable CSV; timestamps and paths are precise |
| MFT timestomping | **High** | SI vs FN timestamp comparison is deterministic |
| Network C2 on known ports | **High** | Port 4444, 31337, 1337 are known indicators |
| LOLBin process execution | **High** | Keyword matching against known LOLBin list |
| Volatility pslist anomalies | **High** | Parent-child relationships are structural, not interpretive |
| Credential hash extraction | **High** | hashdump output is structured and machine-parseable |

### Medium-Confidence Detection Categories

| Artifact Type | Accuracy | Notes |
|--------------|----------|-------|
| Encoded PowerShell | **Medium** | Regex catches `-EncodedCommand` and Base64 patterns; novel obfuscation may evade |
| MITRE ATT&CK mapping | **Medium** | Keyword-based offline mapping; may assign multiple techniques, not all correct |
| Timeline correlation | **Medium** | Depends on quality of log2timeline output; compressed or corrupted images degrade |
| Amcache program attribution | **Medium** | SHA1 hashes present but VT lookup requires API key; without it, attribution is incomplete |
| ShellBags path recovery | **Medium** | Deleted directory paths in ShellBags are indicative but not conclusive |

---

## Known Limitations

### False Positives (What We Over-Report)

1. **LOLBin usage in legitimate admin contexts** — `mshta.exe`, `regsvr32.exe` appear in legitimate enterprise software. SIFT-HUNTER flags all LOLBin executions; the analyst must assess context. We label these POSSIBLE unless additional supporting evidence exists.

2. **High ephemeral port connections** — Port scan activity, backup software, and legitimate services can trigger high port connection alerts. Confidence level will be POSSIBLE at most without behavioral context.

3. **MITRE over-attribution** — A finding may receive 2-3 MITRE techniques when only 1 is correct. We include all candidates and let the analyst filter.

4. **Registry "persistence" from legitimate software** — Many installers write Run keys. Without hash verification against known-good software, we may flag legitimate persistence.

### False Negatives (What We Miss)

1. **Novel malware families** — SIFT-HUNTER has no ML-based anomaly detection. Unknown malware not using known LOLBins, standard C2 ports, or typical persistence mechanisms may be missed.

2. **In-memory only attacks (fileless malware)** — Without a memory capture, purely fileless execution leaves no disk artifacts. We analyze what we have and explicitly report when memory evidence is absent.

3. **Encrypted/obfuscated registry data** — Some sophisticated malware stores payloads in encrypted registry values. RegRipper extracts values but we cannot decode arbitrary encryption.

4. **Anti-forensics with timestamp normalization** — Advanced timestomping that also modifies $STANDARD_INFORMATION and $FILE_NAME to the same value defeats our SI/FN comparison heuristic.

5. **Log gaps** — If VSS shadows or Windows Event Logs were deleted before imaging, timeline gaps appear as gaps in our output, not as findings. We report missing data as a separate finding type.

6. **Disk images without partition tables** — Timeline generation requires valid partition structure. Corrupted or partial images may fail at the log2timeline stage.

### Hallucination Risk Areas

These areas carry elevated risk of LLM hallucination:

1. **Exact file paths** — LLMs may generate plausible-looking but non-existent paths. The hallucination detector catches most of these by comparing against raw tool output.

2. **Timestamp interpolation** — When timeline data has gaps, the LLM may infer intermediate timestamps. These are labeled UNVERIFIED or POSSIBLE.

3. **Attribution claims** — "This looks like APT29 activity" type claims are inherently speculative. Reporter agent is instructed to avoid attribution claims; they appear only in the self-assessment section with explicit uncertainty labeling.

4. **Command line reconstruction** — When Volatility cmdline plugin shows truncated output, the LLM may complete the command. These are labeled accordingly.

---

## Hallucination Detection Rates

These numbers are **measured, not estimated**. They come from a deterministic,
no-API-key benchmark and are locked by CI (`tests/test_benchmark.py`). Reproduce
them yourself in two seconds:

```bash
python -m benchmarks.hallucination_benchmark
```

The benchmark feeds the detector 21 labelled findings (14 fabricated, 7 grounded)
across five IOC categories, including adversarial near-misses (off-by-one IPs,
typo'd executables) and substring traps.

| Claim type (automated detector) | Detection rate | False-positive rate |
|---|---|---|
| Cryptographic hash not in tool output | 100% | 0% |
| IP address not in tool output | 100% | 0% |
| Registry key not in tool output | 100% | 0% |
| File path not in tool output | 100% | 0% |
| Executable name not in tool output | 80% | 0% |
| **Overall** | **93%** | **0%** |

The single executable miss is a substring false-negative: a fabricated
`host.exe` is not flagged because it is a literal substring of the real
`svchost.exe` present in the tool output. This is a known limitation of
substring matching, surfaced here deliberately rather than hidden.

Separately, the **LLM verifier** adds a semantic layer that catches contextual
hallucinations string-matching cannot (wrong attribution, fabricated narrative).
Its catch rate is inherently lower (~65% in informal testing — an LLM verifying
LLM output) and is *additive* to the deterministic detector above; the two layers
are independent. The deterministic layer alone reliably catches the most
dangerous claim types (specific IOCs).

---

## Self-Correction Effectiveness

The self-correction loop has been tested against cases with deliberately introduced errors:

- **1st loop correction rate:** ~80% of flagged findings are corrected or downgraded on first re-examination
- **Remaining after 3 loops:** ~5% of original findings have unresolved issues, which are force-accepted at UNVERIFIED confidence with an explicit flag in the report

---

## What "Confirmed" Really Means

A CONFIRMED finding requires:
- Evidence from 2+ independent tool executions
- Hallucination detector returns no flags
- LLM verifier approves

Even CONFIRMED findings should be treated as strong leads, not proven facts, until validated by a human analyst. The system is an aid to human investigation, not a replacement.

---

## Honest Assessment

SIFT-HUNTER is designed for the common case: Windows endpoint compromise with disk image and memory capture. It excels at:

- Rapid artifact enumeration (minutes, not hours)
- Pattern recognition across known persistence mechanisms
- Cross-referencing disk and memory findings for corroboration
- Maintaining a verifiable evidence chain from finding to raw tool output

It should not be relied upon as the sole tool for:

- Novel or zero-day malware
- Sophisticated APT activity with anti-forensics
- Mobile, macOS, or Linux forensics (Windows-optimized)
- Cloud forensics or container forensics

Every finding is labeled with confidence level. Every CONFIRMED finding has a traceable evidence chain (`sift-hunter audit <finding-id>`). Every UNVERIFIED finding is clearly marked. The goal is to make uncertainty visible, not to hide it behind confident-sounding language.
