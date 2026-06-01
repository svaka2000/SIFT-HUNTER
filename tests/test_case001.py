"""Integration test — deterministic detection on benchmark case001 (no LLM, no binaries).

Proves the forensic detection engine flags every planted IOC in a realistic
multi-artifact incident and maps them to the right MITRE techniques, with zero false
positives on the benign control rows.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from benchmarks.detect_case import detect

CASE = Path(__file__).resolve().parents[1] / "benchmarks" / "cases" / "case001"


@pytest.fixture(scope="module")
def result():
    return detect(str(CASE))


def _flat(result) -> str:
    return " ".join(s for d in result["detections"] for s in d["summary"])


def test_each_artifact_flags_exactly_the_malicious_row(result):
    # one malicious row + one benign control row per artifact → exactly 1 detection each
    assert result["artifacts"] == {"mft": 1, "prefetch": 1, "registry": 1, "pslist": 1, "netscan": 1}


def test_timestomping_detected(result):
    text = _flat(result)
    assert "TIMESTOMP" in text.upper()
    assert "svchost_helper.exe" in text


def test_temp_execution_detected(result):
    assert "TEMP" in _flat(result).upper()


def test_run_key_persistence_detected(result):
    text = _flat(result)
    assert "PERSISTENCE_KEY" in text and "WindowsHelper" in text


def test_process_masquerade_detected(result):
    text = _flat(result)
    assert "UNEXPECTED_PARENT" in text or "WRONG_PATH" in text


def test_c2_detected(result):
    text = _flat(result)
    assert "C2_PORT" in text and "45.137.21.9" in text


def test_expected_mitre_techniques(result):
    ids = {t["technique_id"] for t in result["mitre_ttps"]}
    for tid in ("T1547.001", "T1071", "T1218.005", "T1070.006", "T1036"):
        assert tid in ids, f"missing {tid} (got {sorted(ids)})"


def test_ground_truth_techniques_all_detected(result):
    gt = json.loads((CASE / "ground_truth.json").read_text())
    detected = {t["technique_id"] for t in result["mitre_ttps"]}
    for expected in gt:
        tech = expected.get("mitre_technique")
        if tech:
            assert tech in detected, f"ground-truth technique {tech} not detected"


def test_case_evidence_files_exist():
    case = json.loads((CASE / "case.json").read_text())
    for ep in case["evidence_paths"]:
        assert (CASE / ep).exists(), f"missing evidence {ep}"
