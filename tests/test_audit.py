"""Tests for audit logger."""
import json
import pytest
from sift_hunter.core.audit import AuditLogger, reset_audit_logger
from sift_hunter.core.models import AuditEntry


@pytest.fixture
def audit_log(tmp_path):
    log_file = tmp_path / "audit.jsonl"
    reset_audit_logger()
    logger = AuditLogger(str(log_file))
    yield logger, log_file
    reset_audit_logger()


def test_log_creates_file(audit_log):
    logger, log_file = audit_log
    logger.log_agent_transition("test_agent", "TEST_ACTION", "test phase")
    assert log_file.exists()


def test_log_is_valid_jsonl(audit_log):
    logger, log_file = audit_log
    logger.log_agent_transition("agent1", "ACTION1", "phase1", reasoning="test1")
    logger.log_agent_transition("agent2", "ACTION2", "phase2", reasoning="test2")
    lines = log_file.read_text().strip().split("\n")
    assert len(lines) == 2
    for line in lines:
        entry = json.loads(line)
        assert "timestamp" in entry
        assert "agent" in entry
        assert "action" in entry


def test_log_tool_call_primitive(audit_log):
    logger, log_file = audit_log
    logger.log_tool_call("mft_parser", "/evidence/mft.csv", "EntryNumber,FileName...", "disk_analyst")
    lines = [json.loads(l) for l in log_file.read_text().strip().split("\n")]
    assert lines[0]["action"] == "tool_call"


def test_log_finding_primitive(audit_log):
    logger, log_file = audit_log
    logger.log_finding("F-abc123", "disk_analyst", "PERSISTENCE", "PROBABLE", "disk")
    lines = [json.loads(l) for l in log_file.read_text().strip().split("\n")]
    assert lines[0]["action"] == "finding_created"
    assert lines[0]["finding_id"] == "F-abc123"


def test_log_correction_primitive(audit_log):
    logger, log_file = audit_log
    logger.log_correction("verifier", "F-abc123", "C-xyz456", "Evidence not found", "verification", 2)
    lines = [json.loads(l) for l in log_file.read_text().strip().split("\n")]
    assert lines[0]["action"] == "correction_issued"
    assert lines[0]["finding_id"] == "F-abc123"


def test_trace_chain(audit_log):
    logger, log_file = audit_log
    fid = "F-trace001"
    logger.log_tool_call("mft_parser", "/ev/mft.csv", "raw output", "disk_analyst")
    logger.log_finding(fid, "disk_analyst", "PERSISTENCE", "PROBABLE", "disk")
    logger.log_correction("verifier", fid, "C-001", "Issue", "verification", 1)
    chain = logger.trace_chain(fid)
    assert len(chain["chronological"]) >= 2


def test_get_statistics(audit_log):
    logger, log_file = audit_log
    logger.log_tool_call("mft", "/e/f", "out", "disk_analyst")
    logger.log_finding("F-001", "disk_analyst", "PERSISTENCE", "PROBABLE", "disk")
    stats = logger.get_statistics()
    assert stats["total_entries"] >= 2


def test_log_error(audit_log):
    logger, log_file = audit_log
    logger.log_error("disk_analyst", "tool_run", "Tool not found", phase="disk")
    lines = [json.loads(l) for l in log_file.read_text().strip().split("\n")]
    assert lines[0]["action"] == "error"


def test_log_agent_transition(audit_log):
    logger, log_file = audit_log
    logger.log_agent_transition("triage", "PHASE_START", "triage", iteration=0, reasoning="Starting")
    lines = [json.loads(l) for l in log_file.read_text().strip().split("\n")]
    assert lines[0]["action"] == "PHASE_START"
    assert lines[0]["agent"] == "triage"


def test_query_finding_returns_related_entries(audit_log):
    logger, log_file = audit_log
    fid = "F-query001"
    logger.log_finding(fid, "disk_analyst", "PERSISTENCE", "PROBABLE", "disk")
    logger.log_finding("F-other", "memory_analyst", "EXECUTION", "POSSIBLE", "memory")
    related = logger.query_finding(fid)
    assert all(e.finding_id == fid for e in related)
    assert len(related) >= 1
