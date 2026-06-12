"""
Benchmark runner - measures accuracy against known cases.

Runs the shipped `sift_hunter` pipeline against a benchmark case directory and
scores its findings against ground truth, producing TP/FP/FN, precision/recall/F1,
and self-correction counts for the accuracy report.

Usage:
    python -m benchmarks.runner --case benchmarks/cases/case001
    python -m benchmarks.runner --case benchmarks/cases/case001 --output result.json

Requires an LLM key (GROQ_API_KEY or ANTHROPIC_API_KEY) since analysis is agent-driven.
"""
from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
from typing import Any

from sift_hunter.core.models import ConfidenceLevel


# Highest-confidence first, so a lower index means *more* confident.
CONFIDENCE_ORDER = [
    ConfidenceLevel.CONFIRMED,
    ConfidenceLevel.PROBABLE,
    ConfidenceLevel.POSSIBLE,
    ConfidenceLevel.UNVERIFIED,
]


def _as_dict(finding: Any) -> dict:
    """Normalize a finding to a plain dict (it may be a pydantic model or a dict)."""
    if isinstance(finding, dict):
        return finding
    if hasattr(finding, "model_dump"):
        return finding.model_dump(mode="json")
    return dict(getattr(finding, "__dict__", {}) or {})


def run_benchmark(case_dir: str) -> dict[str, Any]:
    """Run analysis against a benchmark case and compare to ground truth."""
    case_path = Path(case_dir)
    case_file = case_path / "case.json"
    ground_truth_file = case_path / "ground_truth.json"

    if not case_file.exists():
        return {"error": f"No case.json in {case_dir}"}

    with open(case_file) as f:
        case = json.load(f)

    ground_truth: list[dict] = []
    if ground_truth_file.exists():
        with open(ground_truth_file) as f:
            ground_truth = json.load(f)

    evidence_paths = [
        str(case_path / ep)
        for ep in case.get("evidence_paths", [])
        if (case_path / ep).exists()
    ]
    if not evidence_paths:
        return {"error": "No evidence files found for this case"}

    # The shipped pipeline is async - drive it with asyncio.run.
    from sift_hunter.agents.orchestrator import run_analysis

    result = asyncio.run(run_analysis(evidence_paths, max_iterations=20))
    findings = [_as_dict(f) for f in result.get("findings", [])]

    # Score against ground truth
    tp = 0
    fn = 0
    matched_findings: set[int] = set()

    for expected in ground_truth:
        matched = False
        for i, finding in enumerate(findings):
            if i in matched_findings:
                continue
            if _matches_expected(finding, expected):
                expected_min = expected.get("confidence_min", "POSSIBLE")
                actual_conf = finding.get("confidence", "UNVERIFIED")
                if _confidence_gte(actual_conf, expected_min):
                    tp += 1
                    matched_findings.add(i)
                    matched = True
                    break
        if not matched:
            fn += 1

    # Any finding not matched to ground truth counts as a false positive.
    fp = sum(1 for i in range(len(findings)) if i not in matched_findings)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    audit_stats = result.get("audit_stats", {}) or {}
    hallucinations_caught = (
        audit_stats.get("hallucinations_caught")
        or audit_stats.get("corrections")
        or len(result.get("corrections", []))
    )

    return {
        "case_id": case.get("case_id", case_dir),
        "description": case.get("description", ""),
        "total_findings": len(findings),
        "expected_findings": len(ground_truth),
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1_score": round(f1, 3),
        "corrections_applied": len(result.get("corrections", [])),
        "hallucinations_caught": hallucinations_caught,
    }


def _matches_expected(finding: dict, expected: dict) -> bool:
    """Check if a finding matches an expected ground-truth entry."""
    if expected.get("finding_type") and finding.get("finding_type") != expected["finding_type"]:
        return False

    if expected.get("mitre_technique"):
        finding_techniques = [
            ttp.get("technique_id")
            for ttp in (finding.get("mitre_ttps") or finding.get("mitre_mappings") or [])
            if isinstance(ttp, dict)
        ]
        if expected["mitre_technique"] not in finding_techniques:
            return False

    for must_contain in expected.get("must_contain", []):
        desc = (
            str(finding.get("description", ""))
            + " "
            + str(finding.get("raw_evidence_excerpt", ""))
            + " "
            + str(finding.get("title", ""))
        ).lower()
        if must_contain.lower() not in desc:
            return False

    return True


def _confidence_gte(actual: str, minimum: str) -> bool:
    """Return True if `actual` confidence is at least `minimum`."""
    try:
        actual_idx = CONFIDENCE_ORDER.index(ConfidenceLevel(actual))
        min_idx = CONFIDENCE_ORDER.index(ConfidenceLevel(minimum))
        return actual_idx <= min_idx  # lower index = higher confidence
    except (KeyError, ValueError):
        return False


def main() -> None:
    parser = argparse.ArgumentParser(description="SIFT-HUNTER Accuracy Benchmark")
    parser.add_argument("--case", required=True, help="Path to benchmark case directory")
    parser.add_argument("--output", default="", help="Output JSON file for results")
    args = parser.parse_args()

    result = run_benchmark(args.case)
    print(json.dumps(result, indent=2))

    if args.output:
        with open(args.output, "w") as f:
            json.dump(result, f, indent=2)
        print(f"\nResults written to {args.output}")


if __name__ == "__main__":
    main()
