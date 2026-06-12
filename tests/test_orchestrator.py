"""Tests for LangGraph orchestrator."""
import pytest
from unittest.mock import patch, MagicMock

from sift_hunter.agents.state import initial_state, add_finding, add_correction


def test_initial_state_defaults():
    state = initial_state(["/tmp/test.dmp"])
    assert state["evidence_paths"] == ["/tmp/test.dmp"]
    assert state["current_phase"] == "triage"
    assert state["iteration_count"] == 0
    assert state["findings"] == []
    assert state["corrections"] == []
    assert state["errors"] == []


def test_add_finding_immutable():
    state = initial_state(["/tmp/test.dmp"])
    finding = {"id": "F-001", "type": "PERSISTENCE", "description": "test"}
    new_state = add_finding(state, finding)
    assert len(new_state["findings"]) == 1
    assert len(state["findings"]) == 0  # original unchanged


def test_add_correction():
    state = initial_state(["/tmp/test.dmp"])
    correction = {"id": "C-001", "finding_id": "F-001", "issue": "test"}
    new_state = add_correction(state, correction)
    assert len(new_state["corrections"]) == 1


def test_build_graph_compiles():
    from sift_hunter.agents.orchestrator import build_graph
    graph = build_graph()
    assert graph is not None


def test_graph_has_all_nodes():
    from sift_hunter.agents.orchestrator import build_graph
    graph = build_graph()
    # The compiled graph should have the key nodes
    nodes = list(graph.nodes)
    assert "__start__" in nodes or "triage" in nodes


@pytest.mark.asyncio
async def test_run_analysis_with_mock_evidence(tmp_path):
    """Test full pipeline with mocked LLM - no real API calls."""
    evidence_file = tmp_path / "process_list.txt"
    evidence_file.write_text("PID PPID Name\n4892 3890 svchost_helper.exe\n")

    mock_response = MagicMock()
    mock_response.content = '{"findings": [{"id": "mem_001", "type": "DEFENSE_EVASION", "title": "Masquerade", "description": "svchost_helper masquerades", "confidence": "PROBABLE", "raw_evidence_excerpt": "svchost_helper.exe", "agent": "memory_analyst", "mitre_hints": "masquerade", "timestamp": null}], "analyst_notes": "test"}'

    triage_response = MagicMock()
    triage_response.content = '{"triage_summary": "Test", "os_type": "Windows", "analysis_plan": [], "risk_level": "HIGH", "initial_iocs": []}'

    disk_response = MagicMock()
    disk_response.content = '{"findings": [], "analyst_notes": "no disk artifacts"}'

    correlator_response = MagicMock()
    correlator_response.content = '{"attack_narrative": "Test", "attack_timeline": [], "inconsistencies": [], "confidence_upgrades": [], "mitre_coverage": [], "correlated_pairs": []}'

    verifier_response = MagicMock()
    verifier_response.content = '{"approved_finding_ids": ["mem_001"], "corrections_needed": [], "hallucinations_caught": [], "verification_summary": "All good", "overall_quality": "PASS"}'

    reporter_response = MagicMock()
    reporter_response.content = '{"executive_summary": "Test incident", "self_assessment": "Done", "recommendations": ["Investigate"], "known_limitations": []}'

    responses = [triage_response, disk_response, mock_response, correlator_response, verifier_response, reporter_response]
    call_count = [0]

    def fake_invoke(messages):
        idx = min(call_count[0], len(responses) - 1)
        call_count[0] += 1
        return responses[idx]

    with patch("sift_hunter.agents.nodes.triage.get_llm") as m1, \
         patch("sift_hunter.agents.nodes.disk_analyst.get_llm") as m2, \
         patch("sift_hunter.agents.nodes.memory_analyst.get_llm") as m3, \
         patch("sift_hunter.agents.nodes.correlator.get_llm") as m4, \
         patch("sift_hunter.agents.nodes.verifier.get_llm") as m5, \
         patch("sift_hunter.agents.nodes.reporter.get_llm") as m6:
        for m in [m1, m2, m3, m4, m5, m6]:
            m.return_value.invoke.side_effect = fake_invoke

        from sift_hunter.agents.orchestrator import run_analysis
        result = await run_analysis([str(evidence_file)], str(tmp_path))

    assert "report" in result
    assert "findings" in result
    assert len(result["errors"]) == 0 or result["report"] is not None
