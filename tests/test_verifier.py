"""Tests for the verifier self-correction engine."""
import pytest
from unittest.mock import MagicMock, patch

from sift_hunter.agents.state import initial_state
from sift_hunter.agents.nodes.verifier import verifier_node
from sift_hunter.core.models import ConfidenceLevel


def _make_finding(fid, confidence="PROBABLE", agent="disk_analyst", excerpt="registry run key found"):
    return {
        "id": fid,
        "type": "PERSISTENCE",
        "title": f"Finding {fid}",
        "description": f"Description for {fid}",
        "confidence": confidence,
        "raw_evidence_excerpt": excerpt,
        "agent": agent,
        "verified": False,
        "verification_notes": "",
        "mitre_ttps": [],
    }


def _make_state_with_findings(findings, tool_executions=None, iteration=0, correction_counts=None):
    state = dict(initial_state(["/tmp/test.dmp"]))
    state["findings"] = findings
    state["tool_executions"] = tool_executions or []
    state["iteration_count"] = iteration
    state["correction_counts"] = correction_counts or {}
    return state


class TestVerifierNode:
    def test_empty_findings_passes(self):
        state = _make_state_with_findings([])
        result = verifier_node(state)
        assert result["verification_passed"] is True
        assert result["current_phase"] == "reporting"

    def test_verifier_approves_when_llm_approves(self):
        findings = [_make_finding("F-001", "PROBABLE")]
        state = _make_state_with_findings(findings, tool_executions=[
            {"id": "TE-1", "tool_name": "mft_parser", "command": "MFTECmd",
             "raw_output": "registry run key found in SOFTWARE\\...\\Run", "success": True}
        ])
        mock_response = MagicMock()
        mock_response.content = '{"approved_finding_ids": ["F-001"], "corrections_needed": [], "hallucinations_caught": [], "verification_summary": "All good", "overall_quality": "PASS"}'
        with patch("sift_hunter.agents.nodes.verifier.get_llm") as mock_llm:
            mock_llm.return_value.invoke.return_value = mock_response
            result = verifier_node(state)
        assert result["verification_passed"] is True
        approved = [f for f in result["findings"] if f.get("verified")]
        assert len(approved) == 1

    def test_verifier_creates_correction_for_flagged_finding(self):
        findings = [_make_finding("F-002", "CONFIRMED", excerpt="unicorn_malware_not_in_output.exe")]
        state = _make_state_with_findings(findings)
        mock_response = MagicMock()
        mock_response.content = '{"approved_finding_ids": [], "corrections_needed": [{"finding_id": "F-002", "action": "DOWNGRADE_CONFIDENCE", "issue": "Evidence not in tool output", "original_confidence": "CONFIRMED", "recommended_confidence": "UNVERIFIED", "target_agent": "disk_analyst"}], "hallucinations_caught": ["F-002 claims something not in output"], "verification_summary": "Issues found", "overall_quality": "FAIL"}'
        with patch("sift_hunter.agents.nodes.verifier.get_llm") as mock_llm:
            mock_llm.return_value.invoke.return_value = mock_response
            result = verifier_node(state)
        assert result["verification_passed"] is False
        assert len(result["pending_corrections"]) > 0
        assert result["current_phase"] == "disk"

    def test_correction_loop_depth_enforced(self):
        fid = "F-loop"
        findings = [_make_finding(fid, "CONFIRMED")]
        state = _make_state_with_findings(findings, correction_counts={fid: 3})
        mock_response = MagicMock()
        mock_response.content = f'{{"approved_finding_ids": [], "corrections_needed": [{{"finding_id": "{fid}", "action": "RE_EXAMINE", "issue": "Still bad", "original_confidence": "CONFIRMED", "recommended_confidence": "UNVERIFIED", "target_agent": "disk_analyst"}}], "hallucinations_caught": [], "verification_summary": "", "overall_quality": "FAIL"}}'
        with patch("sift_hunter.agents.nodes.verifier.get_llm") as mock_llm:
            mock_llm.return_value.invoke.return_value = mock_response
            result = verifier_node(state)
        # Finding should be force-accepted with downgraded confidence
        assert result["verification_passed"] is True
        f = next(f for f in result["findings"] if f["id"] == fid)
        assert f["confidence"] in ("UNVERIFIED", "POSSIBLE", "PROBABLE")

    def test_iteration_cap_forces_acceptance(self):
        findings = [_make_finding("F-cap", "PROBABLE")]
        state = _make_state_with_findings(findings, iteration=15)
        state["max_iterations"] = 20
        mock_response = MagicMock()
        mock_response.content = '{"approved_finding_ids": [], "corrections_needed": [{"finding_id": "F-cap", "action": "RE_EXAMINE", "issue": "x", "original_confidence": "PROBABLE", "recommended_confidence": "UNVERIFIED", "target_agent": "disk_analyst"}], "hallucinations_caught": [], "verification_summary": "", "overall_quality": "FAIL"}'
        with patch("sift_hunter.agents.nodes.verifier.get_llm") as mock_llm:
            mock_llm.return_value.invoke.return_value = mock_response
            result = verifier_node(state)
        # At 15/20 = 75% of max — should force accept
        assert result["verification_passed"] is True

    def test_verifier_llm_failure_degrades_gracefully(self):
        findings = [_make_finding("F-fail", "CONFIRMED")]
        state = _make_state_with_findings(findings)
        with patch("sift_hunter.agents.nodes.verifier.get_llm") as mock_llm:
            mock_llm.return_value.invoke.side_effect = RuntimeError("LLM unavailable")
            result = verifier_node(state)
        assert result["verification_passed"] is True
        # CONFIRMED finding should be downgraded
        f = next(f for f in result["findings"] if f["id"] == "F-fail")
        assert f["confidence"] != "CONFIRMED"

    def test_hallucination_count_tracked(self):
        findings = [_make_finding("F-003", "PROBABLE")]
        state = _make_state_with_findings(findings)
        mock_response = MagicMock()
        mock_response.content = '{"approved_finding_ids": ["F-003"], "corrections_needed": [], "hallucinations_caught": ["Agent claimed X which was not in output"], "verification_summary": "One hallucination caught", "overall_quality": "PARTIAL"}'
        with patch("sift_hunter.agents.nodes.verifier.get_llm") as mock_llm:
            mock_llm.return_value.invoke.return_value = mock_response
            result = verifier_node(state)
        assert result["_confidence_summary_update"]["hallucinations_caught"] == 1
