"""Tests for report generation."""
import pytest
from unittest.mock import MagicMock, patch
from pathlib import Path

from sift_hunter.agents.state import initial_state
from sift_hunter.agents.nodes.reporter import reporter_node
from sift_hunter.core.models import ConfidenceLevel


def _make_finding(fid, title, confidence="PROBABLE", ftype="PERSISTENCE", agent="disk_analyst"):
    return {
        "id": fid,
        "type": ftype,
        "title": title,
        "description": f"Description of {title}",
        "confidence": confidence,
        "raw_evidence_excerpt": "Evidence here",
        "agent": agent,
        "verified": True,
        "verification_notes": "Approved",
        "mitre_ttps": [{"technique_id": "T1547.001", "technique_name": "Registry Run Keys", "tactic": "Persistence", "confidence": 0.9}],
    }


def _make_state(findings):
    state = dict(initial_state(["/tmp/test.dmp"]))
    state["findings"] = findings
    state["corrections"] = [{"id": "C-001"}]
    state["_hallucinations"] = ["One hallucination caught"]
    state["_timeline_events"] = []
    return state


class TestReporterNode:
    def test_report_generated(self):
        state = _make_state([_make_finding("F-001", "Registry Persistence")])
        mock = MagicMock()
        mock.content = '{"executive_summary": "Malware found.", "self_assessment": "Done.", "recommendations": ["Isolate host"], "known_limitations": []}'
        with patch("sift_hunter.agents.nodes.reporter.get_llm") as ml:
            ml.return_value.invoke.return_value = mock
            result = reporter_node(state)
        assert result["report"] is not None
        assert result["report"]["summary"] == "Malware found."

    def test_report_contains_all_findings(self):
        findings = [_make_finding(f"F-{i:03d}", f"Finding {i}") for i in range(5)]
        state = _make_state(findings)
        mock = MagicMock()
        mock.content = '{"executive_summary": "5 findings.", "self_assessment": "Test.", "recommendations": [], "known_limitations": []}'
        with patch("sift_hunter.agents.nodes.reporter.get_llm") as ml:
            ml.return_value.invoke.return_value = mock
            result = reporter_node(state)
        report = result["report"]
        assert len(report["findings"]) == 5

    def test_confidence_summary_accurate(self):
        findings = [
            _make_finding("F-001", "F1", confidence="CONFIRMED"),
            _make_finding("F-002", "F2", confidence="PROBABLE"),
            _make_finding("F-003", "F3", confidence="POSSIBLE"),
        ]
        state = _make_state(findings)
        mock = MagicMock()
        mock.content = '{"executive_summary": "", "self_assessment": "", "recommendations": [], "known_limitations": []}'
        with patch("sift_hunter.agents.nodes.reporter.get_llm") as ml:
            ml.return_value.invoke.return_value = mock
            result = reporter_node(state)
        cs = result["report"]["confidence_summary"]
        assert cs["confirmed"] == 1
        assert cs["probable"] == 1
        assert cs["possible"] == 1
        assert cs["hallucinations_caught"] == 1
        assert cs["self_corrections_applied"] == 1

    def test_mitre_coverage_deduped(self):
        findings = [
            _make_finding("F-001", "F1"),
            _make_finding("F-002", "F2"),  # same TTP T1547.001
        ]
        state = _make_state(findings)
        mock = MagicMock()
        mock.content = '{"executive_summary": "", "self_assessment": "", "recommendations": [], "known_limitations": []}'
        with patch("sift_hunter.agents.nodes.reporter.get_llm") as ml:
            ml.return_value.invoke.return_value = mock
            result = reporter_node(state)
        techniques = [t["technique_id"] for t in result["report"]["mitre_mapping"]]
        assert techniques.count("T1547.001") == 1

    def test_report_llm_failure_graceful(self):
        state = _make_state([_make_finding("F-001", "Test")])
        with patch("sift_hunter.agents.nodes.reporter.get_llm") as ml:
            ml.return_value.invoke.side_effect = RuntimeError("LLM down")
            result = reporter_node(state)
        assert result["report"] is not None
        assert "unavailable" in result["report"]["summary"].lower() or len(result["report"]["summary"]) > 0

    def test_report_phase_complete(self):
        state = _make_state([])
        mock = MagicMock()
        mock.content = '{"executive_summary": "Nothing found.", "self_assessment": ".", "recommendations": [], "known_limitations": []}'
        with patch("sift_hunter.agents.nodes.reporter.get_llm") as ml:
            ml.return_value.invoke.return_value = mock
            result = reporter_node(state)
        assert result["current_phase"] == "complete"
