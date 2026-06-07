"""Reproducibility lock for the measured-accuracy evaluation (docs/EVALUATION.md).

These assertions pin the numbers published in the Accuracy Report so they can never
silently drift from the code. Deterministic, no API key, no SIFT binaries.
"""
from __future__ import annotations

from benchmarks.evaluate import CASES_DIR, evaluate, score_case

ALL = ["case001", "zeus-vmem", "cridex-vmem"]


def test_zero_false_positives_overall():
    r = evaluate(ALL)
    assert r["overall"]["false_positives"] == 0
    assert r["overall"]["precision"] == 1.0


def test_overall_recall_meets_published_floor():
    r = evaluate(ALL)
    assert r["overall"]["recall"] >= 0.85
    assert r["overall"]["f1"] >= 0.90


def test_zeus_injection_c2_persistence_detected():
    c = score_case(CASES_DIR / "zeus-vmem")
    assert c["false_positives"] == 0
    assert c["iocs_found"] >= 4
    # Honest documented miss: firewall-disable is an LLM-layer catch, not a rule IOC.
    assert "zeus-firewall" in c["iocs_missed"]
    assert "T1055" in c["mitre_found"] and "T1071" in c["mitre_found"]


def test_cridex_full_recall_zero_fp():
    c = score_case(CASES_DIR / "cridex-vmem")
    assert c["metrics_all"]["recall"] == 1.0
    assert c["false_positives"] == 0


def test_chain_of_custody_sha256_emitted():
    c = score_case(CASES_DIR / "zeus-vmem")
    coc = c["chain_of_custody_sha256"]
    assert "malfind.csv" in coc
    assert all(len(h) == 64 for h in coc.values())  # SHA-256 hex


def test_xp_process_lineage_not_false_positive():
    # Regression: evaluation on the XP samples surfaced an over-strict lineage rule.
    # On Windows XP, services.exe and lsass.exe are children of winlogon.exe (no wininit.exe).
    from sift_hunter.mcp_server.tools.memory.processes import ProcessTool

    xp_legit = [
        {"ImageFileName": "services.exe", "Parent": "winlogon.exe", "Path": "C:\\WINDOWS\\system32\\services.exe"},
        {"ImageFileName": "lsass.exe", "Parent": "winlogon.exe", "Path": "C:\\WINDOWS\\system32\\lsass.exe"},
    ]
    assert ProcessTool().find_suspicious(xp_legit) == []
