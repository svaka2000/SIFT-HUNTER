"""Tests for core Pydantic models."""
import pytest
from sift_hunter.core.models import (
    ConfidenceLevel, FindingType, EvidenceType, AgentName,
    Finding, EvidenceItem, ToolExecution, Correction,
    IncidentReport, ConfidenceSummary, AttackTimelineEvent, MITREMapping,
)
from datetime import datetime, timezone


def test_confidence_level_values():
    assert ConfidenceLevel.CONFIRMED.value == "CONFIRMED"
    assert ConfidenceLevel.PROBABLE.value == "PROBABLE"
    assert ConfidenceLevel.POSSIBLE.value == "POSSIBLE"
    assert ConfidenceLevel.UNVERIFIED.value == "UNVERIFIED"


def test_finding_creation():
    f = Finding(
        type="PERSISTENCE",
        title="Test Finding",
        description="A test finding",
        confidence=ConfidenceLevel.PROBABLE,
        raw_evidence_excerpt="Run key at HKLM\\...\\Run: evil.exe",
        agent="disk_analyst",
    )
    assert f.id.startswith("F-")
    assert f.confidence == ConfidenceLevel.PROBABLE
    assert f.verified is False


def test_finding_excerpt_sync():
    f = Finding(
        type="EXECUTION",
        title="Exec",
        description="Malware ran",
        confidence=ConfidenceLevel.CONFIRMED,
        raw_evidence_excerpt="svchost_helper.exe",
        agent="memory_analyst",
    )
    # Single form should be synced to list form
    assert "svchost_helper.exe" in f.raw_evidence_excerpts


def test_finding_model_dump():
    f = Finding(
        type="EXECUTION",
        title="Execution",
        description="Malware ran",
        confidence=ConfidenceLevel.CONFIRMED,
        raw_evidence_excerpt="svchost_helper.exe",
        agent="memory_analyst",
    )
    d = f.model_dump(mode="json")
    assert d["confidence"] == "CONFIRMED"
    assert d["type"] == "EXECUTION"
    assert d["agent"] == "memory_analyst"


def test_finding_extra_fields_ignored():
    # Extra fields from LLM output should be silently ignored
    f = Finding(
        type="PERSISTENCE",
        title="Test",
        description="test",
        confidence=ConfidenceLevel.POSSIBLE,
        raw_evidence_excerpt="registry key",
        agent="disk_analyst",
        nonexistent_field="should be ignored",
    )
    assert f.title == "Test"


def test_evidence_item():
    e = EvidenceItem(path="/tmp/test.img", evidence_type=EvidenceType.DISK_IMAGE)
    assert e.hash_sha256 == ""
    assert e.hash_verified is False


def test_tool_execution():
    te = ToolExecution(
        tool_name="mft_parser",
        command_args=["MFTECmd", "-f", "mft.csv"],
        raw_output="EntryNumber,FileName...",
    )
    assert te.success is True
    assert te.id.startswith("T-")


def test_confidence_summary():
    cs = ConfidenceSummary(confirmed=1, probable=3, possible=2, unverified=0)
    assert cs.total == 6


def test_mitre_mapping():
    m = MITREMapping(technique_id="T1059.001", technique_name="PowerShell", tactic="Execution")
    assert m.technique_id == "T1059.001"


def test_attack_timeline_event():
    e = AttackTimelineEvent(
        timestamp=datetime.now(timezone.utc),
        description="Malware executed",
        confidence=ConfidenceLevel.PROBABLE,
    )
    d = e.model_dump(mode="json")
    assert "timestamp" in d


def test_correction_model():
    c = Correction(
        finding_id="F-abc123",
        issue_description="Evidence excerpt not found in tool output",
        action="DOWNGRADE_CONFIDENCE",
        original_confidence=ConfidenceLevel.CONFIRMED,
        corrected_confidence=ConfidenceLevel.POSSIBLE,
        corrected_by="verifier",
        correction_reasoning="Not in raw output",
    )
    assert c.id.startswith("C-")
    d = c.model_dump(mode="json")
    assert d["original_confidence"] == "CONFIRMED"
    assert d["action"] == "DOWNGRADE_CONFIDENCE"


def test_incident_report_minimal():
    cs = ConfidenceSummary(confirmed=0, probable=1, possible=0, unverified=0)
    r = IncidentReport(
        summary="Test incident",
        findings=[],
        attack_timeline=[],
        mitre_mapping=[],
        confidence_summary=cs,
        self_assessment="Test",
        recommendations=["Investigate further"],
        known_limitations=[],
        evidence_paths=["/tmp/test.dmp"],
    )
    assert r.id.startswith("IR-")
    d = r.model_dump(mode="json")
    assert d["summary"] == "Test incident"
