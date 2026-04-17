"""
Accuracy tests — validates hallucination detector and confidence assignment.
These tests prove the system is honest, not just fast.
"""

import pytest
from datetime import datetime

from core.confidence import assign_confidence, downgrade_confidence
from core.evidence_integrity import hash_evidence, ingest_evidence
from core.hallucination_detector import verify_finding, batch_verify, VerificationResult
from core.models import (
    ConfidenceLevel,
    Evidence,
    EvidenceType,
    Finding,
    FindingType,
    ToolExecution,
)


class TestHallucinationDetector:
    """Core accuracy tests — the hallucination detector must catch agent fabrications."""

    def _make_finding_and_te(self, description: str, raw_output: str):
        te = ToolExecution(
            tool_name="test_tool",
            command="test cmd",
            raw_output=raw_output,
            exit_code=0,
        )
        finding = Finding(
            finding_type=FindingType.EXECUTION,
            title="Test Finding",
            description=description,
            raw_evidence_excerpt=description,
            confidence=ConfidenceLevel.CONFIRMED,
            tool_execution_refs=[te.id],
        )
        return finding, te

    def test_grounded_finding_passes(self):
        """Finding whose claims appear in tool output should pass."""
        finding, te = self._make_finding_and_te(
            "Malware found at C:\\Windows\\Temp\\evil.exe with SHA1 abc123",
            "FileName: evil.exe\nPath: C:\\Windows\\Temp\\evil.exe\nSHA1: abc123\nType: executable"
        )
        result = verify_finding(finding, [te])
        assert result.verified

    def test_hallucinated_path_caught(self):
        """Finding claiming a path not in tool output should be flagged."""
        finding, te = self._make_finding_and_te(
            "Malware at C:\\Users\\attacker\\payload.exe",
            "Nothing suspicious found. All processes appear legitimate."
        )
        result = verify_finding(finding, [te])
        assert not result.verified
        assert len(result.issues) > 0

    def test_no_tool_refs_flagged(self):
        """Finding with no tool execution references has no evidence — must fail."""
        finding = Finding(
            finding_type=FindingType.PERSISTENCE,
            title="Unsupported Finding",
            description="Persistence mechanism at HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            confidence=ConfidenceLevel.CONFIRMED,
            tool_execution_refs=[],  # No evidence
        )
        result = verify_finding(finding, [])
        assert not result.verified
        assert not result.confidence_appropriate

    def test_overconfident_single_source_caught(self):
        """CONFIRMED with single source is overconfident."""
        te = ToolExecution(
            tool_name="test",
            command="test",
            raw_output="process.exe found at path C:\\Windows\\process.exe",
            exit_code=0,
        )
        finding = Finding(
            finding_type=FindingType.EXECUTION,
            title="Process",
            description="process.exe at C:\\Windows\\process.exe",
            raw_evidence_excerpt="process.exe at C:\\Windows\\process.exe",
            confidence=ConfidenceLevel.CONFIRMED,  # Overconfident — only 1 source
            tool_execution_refs=[te.id],
        )
        result = verify_finding(finding, [te])
        # Should flag overconfidence (1 source ≠ CONFIRMED)
        assert not result.confidence_appropriate

    def test_batch_verify_sorts_worst_first(self):
        """Batch verification should return worst findings first for triage."""
        te = ToolExecution(
            tool_name="test", command="cmd",
            raw_output="legit.exe present in output",
            exit_code=0,
        )
        good_finding = Finding(
            finding_type=FindingType.EXECUTION,
            title="Legitimate",
            description="legit.exe",
            raw_evidence_excerpt="legit.exe present in output",
            confidence=ConfidenceLevel.POSSIBLE,
            tool_execution_refs=[te.id],
        )
        bad_finding = Finding(
            finding_type=FindingType.EXECUTION,
            title="Hallucinated",
            description="totally-fake-malware-not-in-output.exe at C:\\fake\\path",
            raw_evidence_excerpt="totally-fake-malware-not-in-output.exe",
            confidence=ConfidenceLevel.CONFIRMED,
            tool_execution_refs=[te.id],
        )
        results = batch_verify([good_finding, bad_finding], [te])
        # Worst (unverified) should come first
        assert not results[0].verified


class TestConfidenceAssignment:
    def test_two_sources_confirmed(self):
        ev1 = Evidence(path="/tmp/test1", evidence_type=EvidenceType.MFT)
        ev2 = Evidence(path="/tmp/test2", evidence_type=EvidenceType.PREFETCH)
        finding = Finding(finding_type=FindingType.EXECUTION, title="T", description="D",
                          confidence=ConfidenceLevel.POSSIBLE)
        level = assign_confidence(finding, [ev1, ev2])
        assert level == ConfidenceLevel.CONFIRMED

    def test_single_strong_source_probable(self):
        ev1 = Evidence(path="/tmp/test", evidence_type=EvidenceType.MFT)
        finding = Finding(finding_type=FindingType.EXECUTION, title="T", description="D",
                          confidence=ConfidenceLevel.POSSIBLE)
        level = assign_confidence(finding, [ev1])
        assert level == ConfidenceLevel.PROBABLE

    def test_no_sources_unverified(self):
        finding = Finding(finding_type=FindingType.EXECUTION, title="T", description="D",
                          confidence=ConfidenceLevel.CONFIRMED)
        level = assign_confidence(finding, [])
        assert level == ConfidenceLevel.UNVERIFIED

    def test_downgrade_confirmed_to_probable(self):
        assert downgrade_confidence(ConfidenceLevel.CONFIRMED) == ConfidenceLevel.PROBABLE

    def test_downgrade_unverified_stays(self):
        assert downgrade_confidence(ConfidenceLevel.UNVERIFIED) == ConfidenceLevel.UNVERIFIED


class TestEvidenceIntegrity:
    def test_hash_and_verify_roundtrip(self, tmp_path):
        test_file = tmp_path / "evidence.dd"
        test_file.write_bytes(b"A" * 1024)
        from core.evidence_integrity import hash_evidence, verify_evidence
        h = hash_evidence(str(test_file))
        assert len(h) == 64  # SHA256 hex
        assert verify_evidence(str(test_file), h)

    def test_tampered_file_fails_verification(self, tmp_path):
        test_file = tmp_path / "evidence.dd"
        test_file.write_bytes(b"original content")
        from core.evidence_integrity import hash_evidence, verify_evidence
        original_hash = hash_evidence(str(test_file))
        # Tamper
        test_file.write_bytes(b"tampered content")
        assert not verify_evidence(str(test_file), original_hash)

    def test_ingest_detects_disk_image(self, tmp_path):
        disk_file = tmp_path / "case001.dd"
        disk_file.write_bytes(b"\x00" * 512)
        ev = ingest_evidence(str(disk_file))
        assert ev.hash_sha256 is not None
        assert ev.evidence_type == EvidenceType.DISK_IMAGE

    def test_ingest_detects_memory_capture(self, tmp_path):
        mem_file = tmp_path / "memory.dmp"
        mem_file.write_bytes(b"\x00" * 512)
        ev = ingest_evidence(str(mem_file))
        assert ev.evidence_type == EvidenceType.MEMORY_CAPTURE
