"""Reproducibility test for the deterministic hallucination benchmark.

Locks the detection / false-positive rates published in docs/ACCURACY_REPORT.md
so the numbers in the report can never silently drift away from what the code
actually does. These assertions are thresholds, not brittle exact matches.
"""
from __future__ import annotations

from benchmarks.hallucination_benchmark import run


def test_zero_false_positives_on_grounded_claims():
    m = run()
    assert m["overall"]["false_positive_rate"] == 0.0
    for cat in ("exe", "ip", "hash", "registry", "path"):
        assert m[cat]["false_positive_rate"] == 0.0


def test_exact_token_categories_fully_detected():
    # Hashes, IPs, registry keys and (synthetic) file paths are exact tokens -
    # an absent one is unambiguously fabricated and must always be flagged.
    m = run()
    for cat in ("hash", "ip", "registry", "path"):
        assert m[cat]["detection_rate"] == 1.0


def test_exe_substring_limitation_is_bounded():
    # One documented miss: a fabricated exe that is a substring of a real one
    # ("host.exe" inside "svchost.exe"). Detection stays high despite it.
    m = run()
    assert m["exe"]["detection_rate"] >= 0.75


def test_overall_detection_rate_meets_published_floor():
    m = run()
    assert m["overall"]["detection_rate"] >= 0.9
