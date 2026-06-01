"""Tests for report-time finding dedup + confidence-summary total serialization.

Both regressions were found by a real end-to-end run on case001: the
self-correction loop re-emitted findings (duplicates) and the confidence summary
reported a total of 0 because `total` was a non-serialized property.
"""
from __future__ import annotations

from sift_hunter.agents.nodes.reporter import _dedupe_findings, _finding_signature
from sift_hunter.core.models import ConfidenceSummary


def test_loop_duplicates_collapse_keep_richest():
    findings = [
        {"type": "DEFENSE_EVASION", "title": "Timestomp", "confidence": "POSSIBLE",
         "raw_evidence_excerpt": "svchost_helper.exe SI!=FN", "mitre_ttps": []},
        {"type": "DEFENSE_EVASION", "title": "Timestomp (re-run)", "confidence": "PROBABLE",
         "raw_evidence_excerpt": "svchost_helper.exe timestomp", "mitre_ttps": [{"technique_id": "T1070.006"}]},
        {"type": "DEFENSE_EVASION", "title": "Timestomp (re-run 2)", "confidence": "POSSIBLE",
         "raw_evidence_excerpt": "svchost_helper.exe", "mitre_ttps": []},
    ]
    out = _dedupe_findings(findings)
    assert len(out) == 1
    assert out[0]["confidence"] == "PROBABLE"  # richest copy kept


def test_distinct_findings_on_same_host_not_merged():
    # A C2 connection (IP IOC) and a masquerade (exe IOC) must stay separate.
    findings = [
        {"type": "EXECUTION", "title": "Masquerade", "confidence": "PROBABLE",
         "raw_evidence_excerpt": "ImageFileName=svchost.exe Path=C:/Temp/svchost.exe", "mitre_ttps": []},
        {"type": "EXECUTION", "title": "C2", "confidence": "POSSIBLE",
         "raw_evidence_excerpt": "ForeignAddr 45.137.21.9 port 4444 svchost.exe", "mitre_ttps": [{"technique_id": "T1071"}]},
    ]
    out = _dedupe_findings(findings)
    assert len(out) == 2


def test_signature_prefers_ip_then_exe():
    ip_sig = _finding_signature({"type": "X", "raw_evidence_excerpt": "conn to 45.137.21.9:4444 from svchost.exe"})
    exe_sig = _finding_signature({"type": "X", "raw_evidence_excerpt": "svchost_helper.exe in Temp"})
    assert ip_sig == ("X", "45.137.21.9")
    assert exe_sig == ("X", "svchost_helper.exe")


def test_confidence_summary_total_is_serialized():
    cs = ConfidenceSummary(probable=10, possible=5)
    assert cs.total == 15
    assert cs.model_dump(mode="json")["total"] == 15
