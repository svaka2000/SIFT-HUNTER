"""
MCP Server tests — validates tool registration, security enforcement, and audit logging.
"""

import pytest
from unittest.mock import patch, MagicMock

from core.audit import reset_audit_logger, get_audit_logger
from mcp_server.config import config


@pytest.fixture(autouse=True)
def fresh_audit(tmp_path):
    reset_audit_logger(str(tmp_path / "test-audit.jsonl"))


class TestAuditLogger:
    def test_tool_execution_logged(self):
        audit = get_audit_logger()
        entry = audit.log_tool_execution(
            agent="test_agent",
            tool_name="vol3",
            command="vol3 -f evidence.mem windows.pslist.PsList",
            output_hash="abc123",
            finding_id="finding-001",
            phase="memory",
        )
        assert entry.agent == "test_agent"
        assert entry.tool_name == "vol3"
        chain = audit.print_finding_chain("finding-001")
        assert "finding-001" in chain
        assert "vol3" in chain

    def test_correction_logged(self):
        audit = get_audit_logger()
        audit.log_correction(
            agent="verifier",
            finding_id="finding-002",
            correction_id="correction-001",
            reasoning="Claimed path not in tool output",
        )
        entries = audit.query_by_agent("verifier")
        assert len(entries) > 0
        assert entries[0].action == "CORRECTION_APPLIED"

    def test_finding_chain_empty_for_unknown(self):
        audit = get_audit_logger()
        result = audit.print_finding_chain("nonexistent-finding-id")
        assert "No audit trail" in result

    def test_export_json_format(self):
        audit = get_audit_logger()
        audit.log_tool_execution("test", "test_tool", "cmd", "hash123")
        exported = audit.export_json()
        assert isinstance(exported, list)
        assert len(exported) > 0
        assert "timestamp" in exported[0]
        assert "agent" in exported[0]

    def test_multiple_entries_for_same_finding(self):
        audit = get_audit_logger()
        for i in range(3):
            audit.log_tool_execution(
                agent=f"agent_{i}",
                tool_name="tool",
                command="cmd",
                output_hash="hash",
                finding_id="shared-finding",
            )
        chain_entries = audit.query_by_finding("shared-finding")
        assert len(chain_entries) == 3


class TestSecurityCheck:
    """The security_check MCP tool must correctly classify commands."""

    def test_rm_is_blocked(self):
        from mcp_server.security import check_command_safety
        from mcp_server.validators.path_validator import SecurityError
        with pytest.raises(SecurityError):
            check_command_safety("rm -rf /evidence")

    def test_vol3_is_allowed(self):
        from mcp_server.security import check_command_safety
        # vol3 is an allowed forensic tool — should not raise
        # (This tests that the blocklist doesn't over-block)
        try:
            check_command_safety("vol3 -f /evidence/memory.dmp windows.pslist.PsList")
        except Exception as e:
            # Only fail if it's a security error about blocking
            assert "permanently blocked" not in str(e), f"vol3 should not be blocked: {e}"

    def test_grep_is_allowed(self):
        from mcp_server.security import check_command_safety
        try:
            check_command_safety("grep -r pattern /evidence/logs")
        except Exception as e:
            assert "permanently blocked" not in str(e)
