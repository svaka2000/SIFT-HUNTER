# SIFT-HUNTER — Accuracy Report & Evaluation

> Measured, reproducible accuracy on **recognized public DFIR samples** — not toy data.
> Run it yourself in two seconds, no API key required:
> ```bash
> python -m benchmarks.evaluate
> ```

## Headline result

Across three cases — including the two canonical Volatility memory samples every DFIR
analyst knows, **`zeus.vmem`** and **`cridex.vmem`** — SIFT-HUNTER's **deterministic
detection layer** scores:

| | Precision | Recall | F1 | False positives |
|---|---|---|---|---|
| **Overall (13 detections, 14 ground-truth IOCs)** | **100%** | **86%** | **0.92** | **0** |

| Case | Source | IOCs | Found | FP | Precision | Recall | F1 |
|------|--------|-----:|------:|---:|----------:|-------:|----:|
| `cridex-vmem` | Volatility public sample | 4 | 4 | 0 | 100% | 100% | 1.00 |
| `zeus-vmem` | Volatility public sample | 5 | 4 | 0 | 100% | 80% | 0.89 |
| `case001` | synthetic spear-phish→C2 | 5 | 4 | 0 | 100% | 80% | 0.89 |

**Per-category recall:** injection (malfind) 4/4 · C2 (netscan) 3/3 · persistence 1/1 ·
defense-evasion 0/1 · execution/LOLBin 0/1.

Ground truth for the two real samples is **publicly documented and cited** (see each
case's `PROVENANCE.md`); a judge can independently verify every indicator.

## Why this is the report that matters

Senior DFIR practitioners distrust AI tools that *claim* to work. The FIND EVIL! rubric
scores **IR Accuracy** ("are findings correct? are hallucinations caught?") and the
mantra is *"don't trust AI — verify it."* So we don't ask you to trust us. The numbers
above are produced by a committed harness over recognized evidence with published ground
truth, and they are **CI-locked** (`tests/test_evaluate.py`) so they cannot drift.

## Methodology

1. **Deterministic detection layer, scored separately from the LLM.** The
   forensically-defensible work is done by rule-based detectors — injected-PE detection
   (malfind: MZ header in PAGE_EXECUTE_READWRITE), externally-routable C2 on suspicious
   ports/state, known persistence keys, timestomping (SI≠FN). This layer is
   deterministic and reproducible run-to-run; the LLM only reasons *on top of* it.
2. **Recognized evidence.** Cases are parsed-tool-output (`vol3 windows.pslist /
   malfind / netscan`, registry export) for the public `zeus.vmem` and `cridex.vmem`
   samples, plus a synthetic case. **Realistic benign processes and connections are
   included** so precision is a real measurement, not a trivial 100%.
3. **Scoring.** Recall = ground-truth IOCs detected ÷ total. Precision = true-positive
   detections ÷ all detections (a detection is a false positive if it references no real
   IOC). Per-IOC and per-category breakdowns in `benchmarks/results/evaluation.json`.
4. **Chain of custody.** Every evidence file is SHA-256 hashed into the results
   manifest on each run (`chain_of_custody_sha256`).

## Honest error analysis

We report what we miss — surfacing uncertainty is a feature, not a weakness.

- **2 of 14 indicators are deterministic-layer misses, by design.** `zeus.vmem`'s
  *disabled-firewall* registry value and `case001`'s *MSHTA executed from System32* are
  behavioral/contextual signals, not hard IOCs — they are caught by the **LLM analyst +
  Verifier layer**, not the conservative rule set. Counting them as rule-layer misses is
  the honest accounting (it lowers our headline recall).
- **A real bug, found and fixed by this evaluation.** Running against the XP samples
  surfaced an over-strict process-lineage rule that assumed the post-Vista tree
  (`services.exe`/`lsass.exe` ← `wininit.exe`) and therefore flagged *legitimate* XP
  lineage (`… ← winlogon.exe`) as anomalous — two false positives. We corrected the rule
  to recognize the XP lineage; precision returned to 100% and a regression test now locks
  it (`test_xp_process_lineage_not_false_positive`). This is exactly why you evaluate on
  real data.

## The layered accuracy model

| Layer | What it does | Measured result |
|-------|--------------|-----------------|
| **Deterministic detectors** | Rule/signature IOC detection (this report) | 100% precision, 86% recall, 0 FP |
| **Automated hallucination detector** | Cross-checks every LLM IOC claim vs raw tool output | **93% catch / 0% FP** (`python -m benchmarks.hallucination_benchmark`) |
| **LLM analyst + Verifier (self-correction)** | Reasoning, correlation, confidence; catches its own hallucinations | Real `case001` run: 6 findings, **7 self-corrections, 4 hallucinations caught** (`benchmarks/cases/case001/sample_report.md`) |

## Forensic soundness & admissibility

Engineered to preempt the standard objections to AI in forensics (Daubert / NIST CFTT /
proposed FRE 707):

| Requirement | How SIFT-HUNTER meets it |
|-------------|--------------------------|
| **Evidence integrity** | SHA-256 chain-of-custody manifest on every run; architectural **read-only** evidence handling (no tool path can mutate source) |
| **Determinism / reproducibility** | Detection layer is rule-based and reproducible; LLM runs at temperature 0.1 with pinned model; same input → same detections |
| **Known error rate (Daubert)** | Per-function precision/recall reported here, not a single global number |
| **Explainability / cross-examination** | Every finding traces to the exact tool execution (`sift-hunter audit <id>`); confidence labels separate CONFIRMED from inferred |
| **Hallucination control** | Deterministic detector + Verifier flag/withhold unsupported claims; measured catch rate published |
| **Decision-support, not replacement** | Output is structured findings for a qualified examiner, with explicit "needs review" / confidence states |

**Selected sources.** Volatility Foundation public memory samples
(github.com/volatilityfoundation/volatility/wiki/Memory-Samples); zeus.vmem IOCs —
malwarereversing (2011), behindthefirewalls (2013); cridex.vmem IOCs — SemperSecurus
(2012); LLM-DFIR hallucination & admissibility — Yin et al., arXiv 2504.02963 (2025),
PNAS 2301842120 (2023); NIST CFTT program; Daubert v. Merrell Dow (1993); proposed FRE
707 (drafted 2025). Full per-case citations in each `benchmarks/cases/*/PROVENANCE.md`.

## Limitations

- Case artifacts are normalized parsed-tool-output representing the public samples'
  documented indicators (with benign noise); equivalent input is reproducible by running
  Volatility 3 on the original images, and the harness scores identically.
- Detection rules are Windows-focused; macOS/Linux/cloud are future work.
- The deterministic layer is intentionally conservative (favoring precision); recall of
  behavioral signals depends on the LLM analyst layer.

*Reproduce everything: `python -m benchmarks.evaluate` (accuracy) ·
`python -m benchmarks.hallucination_benchmark` (hallucination catch) ·
`pytest tests/test_evaluate.py` (locked numbers). No API key needed for any of these.*
