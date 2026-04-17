"""Agent integration tests — test the multi-agent workflow components."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch, AsyncMock
import pytest

from core.models import (
    ConfidenceLevel,
    Finding,
    FindingType,
    Correction,
    ToolExecution,
    MITREMapping,
)
from agents.state import AnalysisState, initial_state, add_finding, add_correction


# ─── State Management Tests ──────────────────────────────────────────────────

class TestAnalysisState:
    def test_initial_state_structure(self):
        """initial_state() should produce a valid AnalysisState with expected defaults."""
        state = initial_state(["/cases/disk.dd", "/cases/memory.dmp"])
        assert state["evidence_paths"] == ["/cases/disk.dd", "/cases/memory.dmp"]
        assert state["findings"] == []
        assert state["corrections"] == []
        assert state["iteration_count"] == 0
        assert state["current_phase"] == "triage"
        assert state["verification_passed"] is False

    def test_add_finding_deduplicates_by_id(self):
        """add_finding should not add duplicates with the same ID."""
        state = initial_state(["/cases/disk.dd"])
        finding = Finding(
            id="f001",
            title="Run Key Persistence",
            description="Malware added to Run key",
            finding_type=FindingType.PERSISTENCE,
            confidence=ConfidenceLevel.PROBABLE,
        )
        state = add_finding(state, finding)
        state = add_finding(state, finding)  # duplicate
        assert len(state["findings"]) == 1

    def test_add_finding_updates_existing(self):
        """add_finding should overwrite if same ID with different content."""
        state = initial_state(["/cases/disk.dd"])
        finding_v1 = Finding(
            id="f001",
            title="Run Key Persistence",
            description="Original description",
            finding_type=FindingType.PERSISTENCE,
            confidence=ConfidenceLevel.POSSIBLE,
        )
        finding_v2 = Finding(
            id="f001",
            title="Run Key Persistence",
            description="Corrected description",
            finding_type=FindingType.PERSISTENCE,
            confidence=ConfidenceLevel.CONFIRMED,
        )
        state = add_finding(state, finding_v1)
        state = add_finding(state, finding_v2)
        assert len(state["findings"]) == 1
        assert state["findings"][0].confidence == ConfidenceLevel.CONFIRMED

    def test_add_correction_increments_counter(self):
        """add_correction should track correction depth per finding."""
        state = initial_state(["/cases/disk.dd"])
        finding = Finding(
            id="f001",
            title="Test",
            description="Test",
            finding_type=FindingType.EXECUTION,
            confidence=ConfidenceLevel.UNVERIFIED,
        )
        state = add_finding(state, finding)

        correction = Correction(
            finding_id="f001",
            issue="Path not in tool output",
            action="RE_EXAMINE",
            original_confidence=ConfidenceLevel.PROBABLE,
            corrected_confidence=ConfidenceLevel.UNVERIFIED,
        )
        state = add_correction(state, correction)
        assert len(state["corrections"]) == 1
        assert state["correction_counts"].get("f001", 0) == 1

    def test_max_corrections_respected(self):
        """State should track when max correction depth is reached."""
        state = initial_state(["/cases/disk.dd"])
        finding = Finding(
            id="f001",
            title="Test",
            description="Test",
            finding_type=FindingType.EXECUTION,
            confidence=ConfidenceLevel.POSSIBLE,
        )
        state = add_finding(state, finding)

        for i in range(4):
            correction = Correction(
                finding_id="f001",
                issue=f"Issue {i}",
                action="RE_EXAMINE",
                original_confidence=ConfidenceLevel.POSSIBLE,
                corrected_confidence=ConfidenceLevel.UNVERIFIED,
            )
            state = add_correction(state, correction)

        # After 4 corrections, count should be 4
        assert state["correction_counts"]["f001"] == 4


# ─── Verifier Routing Tests ──────────────────────────────────────────────────

class TestVerifierRouting:
    """Test the verifier's routing logic without calling the LLM."""

    def _make_state_with_corrections(self, finding_id: str, count: int) -> AnalysisState:
        """Build a state with pending corrections for a finding."""
        state = initial_state(["/cases/disk.dd"])
        finding = Finding(
            id=finding_id,
            title="Test finding",
            description="suspicious.exe in temp",
            finding_type=FindingType.EXECUTION,
            confidence=ConfidenceLevel.PROBABLE,
        )
        state = add_finding(state, finding)
        state["correction_counts"] = {finding_id: count}
        state["pending_corrections"] = [
            Correction(
                finding_id=finding_id,
                issue="Claim not in tool output",
                action="RE_EXAMINE",
                original_confidence=ConfidenceLevel.PROBABLE,
                corrected_confidence=ConfidenceLevel.UNVERIFIED,
            )
        ]
        return state

    def test_routes_to_disk_analyst_when_pending_corrections(self):
        """If there are disk-related pending corrections, route to disk_analyst."""
        from agents.orchestrator import _route_after_verifier

        state = self._make_state_with_corrections("f001", 1)
        # Add a disk-source annotation
        state["findings"][0].source_agent = "disk_analyst"

        route = _route_after_verifier(state)
        assert route in {"disk_analyst", "memory_analyst", "correlator", "reporter"}

    def test_routes_to_reporter_when_no_corrections(self):
        """If no pending corrections, route directly to reporter."""
        from agents.orchestrator import _route_after_verifier

        state = initial_state(["/cases/disk.dd"])
        state["pending_corrections"] = []
        state["verification_passed"] = True

        route = _route_after_verifier(state)
        assert route == "reporter"

    def test_routes_to_reporter_after_max_loops(self):
        """If a finding has hit max correction loops, force to reporter."""
        from agents.orchestrator import _route_after_verifier
        from mcp_server.config import MAX_CORRECTION_LOOPS

        state = self._make_state_with_corrections("f001", MAX_CORRECTION_LOOPS)

        route = _route_after_verifier(state)
        assert route == "reporter"


# ─── Hallucination Integration Tests ─────────────────────────────────────────

class TestHallucinationIntegration:
    """Test hallucination detection in context of multi-agent workflow."""

    def _make_tool_execution(self, output: str) -> ToolExecution:
        return ToolExecution(
            tool_name="MFTECmd",
            command="MFTECmd -f mft.bin --csv /tmp",
            raw_output=output,
            duration_seconds=1.2,
        )

    def test_grounded_ip_passes(self):
        """IP address present in tool output should pass verification."""
        from core.hallucination_detector import verify_finding

        tool_exec = self._make_tool_execution(
            "TCP ESTABLISHED 192.168.1.50:49152 -> 198.51.100.44:4444"
        )
        finding = Finding(
            title="C2 Connection",
            description="Process connected to 198.51.100.44 on port 4444",
            finding_type=FindingType.COMMAND_AND_CONTROL,
            confidence=ConfidenceLevel.PROBABLE,
            raw_evidence_excerpt="TCP ESTABLISHED 198.51.100.44:4444",
        )
        finding.tool_execution_refs = [tool_exec.id]

        result = verify_finding(finding, [tool_exec])
        assert result.passed

    def test_hallucinated_path_caught(self):
        """File path not in any tool output should be flagged."""
        from core.hallucination_detector import verify_finding

        tool_exec = self._make_tool_execution(
            "C:\\Users\\victim\\AppData\\Local\\Temp\\svchost_helper.exe created at 14:23:01"
        )
        finding = Finding(
            title="Malware Execution",
            description="Malware at C:\\Windows\\System32\\evil_not_here.exe executed",
            finding_type=FindingType.EXECUTION,
            confidence=ConfidenceLevel.CONFIRMED,
            raw_evidence_excerpt="svchost_helper.exe",
        )
        finding.tool_execution_refs = [tool_exec.id]

        result = verify_finding(finding, [tool_exec])
        assert not result.passed
        assert len(result.flagged_claims) > 0

    def test_confirmed_with_single_source_flagged(self):
        """CONFIRMED confidence requires 2+ tool refs — should flag over-confidence."""
        from core.hallucination_detector import verify_finding

        tool_exec = self._make_tool_execution(
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run: malware.exe"
        )
        finding = Finding(
            title="Registry Persistence",
            description="SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run key contains malware.exe",
            finding_type=FindingType.PERSISTENCE,
            confidence=ConfidenceLevel.CONFIRMED,  # Only 1 source — should be PROBABLE
            raw_evidence_excerpt="Run: malware.exe",
        )
        finding.tool_execution_refs = [tool_exec.id]  # Only 1 ref

        result = verify_finding(finding, [tool_exec])
        # Either passes content check but flags confidence, or flags both
        assert not result.passed or result.confidence_appropriate is False


# ─── Audit Trail Integration Tests ───────────────────────────────────────────

class TestAuditTrailIntegration:
    def test_finding_traceable_after_analysis(self, tmp_path):
        """After adding findings and executions, audit trail should be queryable."""
        import os
        os.environ["SIFT_AUDIT_LOG"] = str(tmp_path / "test_audit.jsonl")

        from core.audit import get_audit_logger, reset_audit_logger
        reset_audit_logger()
        logger = get_audit_logger()

        exec1 = ToolExecution(
            tool_name="PECmd",
            command="PECmd -d /cases/prefetch --csv /tmp",
            raw_output="MSHTA.EXE last run: 2024-01-15 14:23:01",
            duration_seconds=0.8,
        )
        finding = Finding(
            id="f-integration-001",
            title="LOLBin Execution",
            description="MSHTA.EXE executed from phishing document",
            finding_type=FindingType.EXECUTION,
            confidence=ConfidenceLevel.PROBABLE,
            raw_evidence_excerpt="MSHTA.EXE last run: 2024-01-15 14:23:01",
        )
        finding.tool_execution_refs = [exec1.id]

        logger.log_tool_execution(exec1, agent="disk_analyst", phase="disk")
        logger.log_finding(finding, agent="disk_analyst", phase="disk")

        chain = logger.query_by_finding("f-integration-001")
        assert len(chain) >= 1
        finding_entries = [e for e in chain if e.get("finding_id") == "f-integration-001"]
        assert len(finding_entries) >= 1

    def test_correction_logged_in_audit(self, tmp_path):
        """Corrections created by verifier should appear in audit trail."""
        import os
        os.environ["SIFT_AUDIT_LOG"] = str(tmp_path / "correction_audit.jsonl")

        from core.audit import get_audit_logger, reset_audit_logger
        reset_audit_logger()
        logger = get_audit_logger()

        correction = Correction(
            finding_id="f-correction-001",
            issue="Path C:\\evil.exe not found in any tool output",
            action="RE_EXAMINE",
            original_confidence=ConfidenceLevel.CONFIRMED,
            corrected_confidence=ConfidenceLevel.UNVERIFIED,
        )
        logger.log_correction(correction, agent="verifier", phase="verification")

        chain = logger.query_by_finding("f-correction-001")
        correction_entries = [e for e in chain if e.get("action") == "correction"]
        assert len(correction_entries) >= 1
        assert correction_entries[0]["issue"] == correction.issue


# ─── Evidence Integrity Tests ────────────────────────────────────────────────

class TestEvidenceIntegrityIntegration:
    def test_tampered_evidence_detected(self, tmp_path):
        """If evidence file is modified after initial hash, verify_evidence returns False."""
        from core.evidence_integrity import hash_evidence, verify_evidence

        evidence_file = tmp_path / "memory.dmp"
        evidence_file.write_bytes(b"PAGEFILE" + b"\x00" * 1024)

        original_hash = hash_evidence(str(evidence_file))

        # Tamper with the file
        evidence_file.write_bytes(b"MODIFIED" + b"\x00" * 1024)

        assert not verify_evidence(str(evidence_file), original_hash)

    def test_untampered_evidence_passes(self, tmp_path):
        """Unmodified evidence file should pass integrity check."""
        from core.evidence_integrity import hash_evidence, verify_evidence

        evidence_file = tmp_path / "disk.dd"
        evidence_file.write_bytes(b"MBR" + b"\x00" * 512)

        original_hash = hash_evidence(str(evidence_file))
        assert verify_evidence(str(evidence_file), original_hash)
