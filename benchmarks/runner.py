"""
Benchmark runner — measures accuracy against known cases.
Calculates TP, FP, FN, and hallucination rates for the submission's accuracy report.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from core.models import ConfidenceLevel, Finding


CONFIDENCE_ORDER = [
    ConfidenceLevel.CONFIRMED,
    ConfidenceLevel.PROBABLE,
    ConfidenceLevel.POSSIBLE,
    ConfidenceLevel.UNVERIFIED,
]


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

    # Run analysis
    from agents.orchestrator import run_analysis
    evidence_paths = [
        str(case_path / ep)
        for ep in case.get("evidence_paths", [])
        if (case_path / ep).exists()
    ]

    if not evidence_paths:
        return {"error": "No evidence files found for this case"}

    final_state = run_analysis(evidence_paths, max_iterations=20)
    findings = final_state.get("findings", [])

    # Score against ground truth
    tp, fp, fn = 0, 0, 0
    matched_expected: set[int] = set()

    for expected in ground_truth:
        matched = False
        for i, finding in enumerate(findings):
            if _matches_expected(finding, expected):
                # Check confidence is at least the minimum expected
                expected_min = expected.get("confidence_min", "POSSIBLE")
                actual_conf = finding.get("confidence", "UNVERIFIED")
                if _confidence_gte(actual_conf, expected_min):
                    tp += 1
                    matched_expected.add(i)
                    matched = True
                    break
        if not matched:
            fn += 1

    # Any finding not matching ground truth is a FP
    for i, finding in enumerate(findings):
        if i not in matched_expected:
            fp += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    corrections = len(final_state.get("corrections", []))
    hallucinations = len(final_state.get("_hallucinations", []))

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
        "corrections_applied": corrections,
        "hallucinations_caught": hallucinations,
    }


def _matches_expected(finding: dict, expected: dict) -> bool:
    """Check if a finding matches an expected ground truth entry."""
    # Type match
    if expected.get("finding_type") and finding.get("finding_type") != expected["finding_type"]:
        return False

    # MITRE technique match
    if expected.get("mitre_technique"):
        finding_techniques = [
            ttp.get("technique_id") for ttp in finding.get("mitre_ttps", [])
        ]
        if expected["mitre_technique"] not in finding_techniques:
            return False

    # Content match — must_contain strings in description
    for must_contain in expected.get("must_contain", []):
        desc = (finding.get("description", "") + finding.get("raw_evidence_excerpt", "")).lower()
        if must_contain.lower() not in desc:
            return False

    return True


def _confidence_gte(actual: str, minimum: str) -> bool:
    """Return True if actual confidence >= minimum confidence."""
    try:
        actual_idx = CONFIDENCE_ORDER.index(ConfidenceLevel[actual])
        min_idx = CONFIDENCE_ORDER.index(ConfidenceLevel[minimum])
        return actual_idx <= min_idx  # Lower index = higher confidence
    except (KeyError, ValueError):
        return False


def main():
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
