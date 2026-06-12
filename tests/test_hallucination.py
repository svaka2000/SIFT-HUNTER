"""Tests for hallucination detector."""
import pytest
from sift_hunter.core.hallucination_detector import verify_finding, batch_verify
from sift_hunter.core.models import Finding, FindingType, ConfidenceLevel, AgentName, ToolExecution


def _make_finding(excerpt: str, confidence: ConfidenceLevel = ConfidenceLevel.PROBABLE) -> Finding:
    return Finding(
        type=FindingType.PERSISTENCE,
        title="Test",
        description="Test finding",
        confidence=confidence,
        raw_evidence_excerpt=excerpt,
        agent=AgentName.DISK_ANALYST,
    )


def _make_te(raw: str) -> ToolExecution:
    return ToolExecution(tool_name="mft_parser", command="MFTECmd", raw_output=raw)


def test_finding_with_matching_evidence_passes():
    finding = _make_finding("svchost_helper.exe found in C:\\Temp")
    te = _make_te("EntryNumber,1234,svchost_helper.exe,C:\\Temp,2024-01-15")
    result = verify_finding(finding, [te])
    assert result.verified is True


def test_finding_with_no_matching_evidence_flagged():
    finding = _make_finding("unicorn_malware.exe present in system32")
    te = _make_te("normal.exe,system32,benign stuff only")
    result = verify_finding(finding, [te])
    # unicorn_malware.exe not in tool output - should flag
    assert result.verified is False or len(result.issues) > 0


def test_ip_address_verification():
    finding = _make_finding("Connection to 198.51.100.44:4444 established")
    te = _make_te("TCPv4 192.168.1.50 49152 198.51.100.44 4444 ESTABLISHED svchost_helper.exe")
    result = verify_finding(finding, [te])
    assert result.verified is True


def test_registry_key_verification():
    finding = _make_finding("Registry key HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run modified")
    te = _make_te("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\nWindowsHelper=svchost_helper.exe")
    result = verify_finding(finding, [te])
    assert result.verified is True


def test_confirmed_finding_with_no_tool_output_downgraded():
    finding = _make_finding("evil.exe injected into lsass.exe", ConfidenceLevel.CONFIRMED)
    result = verify_finding(finding, [])
    assert not result.confidence_appropriate


def test_batch_verify_empty_returns_empty():
    results = batch_verify([], [])
    assert results == []


def test_batch_verify_multiple_findings():
    f1 = _make_finding("svchost_helper.exe in temp")
    f2 = _make_finding("registry run key modified")
    te = _make_te("svchost_helper.exe temp\nHKLM\\...\\Run: svchost_helper.exe")
    results = batch_verify([f1, f2], [te])
    assert len(results) == 2


def test_finding_id_preserved_in_result():
    finding = _make_finding("evil.exe")
    te = _make_te("evil.exe present")
    result = verify_finding(finding, [te])
    assert result.finding_id == finding.id


def test_empty_excerpt_flagged():
    finding = _make_finding("")
    te = _make_te("some tool output")
    result = verify_finding(finding, [te])
    assert len(result.issues) > 0
