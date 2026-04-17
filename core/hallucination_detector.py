"""
Hallucination detector — compares agent natural language claims against structured tool output.
If an agent claims "malware at C:\\evil.exe" but no tool output contains that path, FLAG IT.
This is the backbone of IR Accuracy (Criterion 2) and the tiebreaker (Criterion 1).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from core.models import ConfidenceLevel, Finding, ToolExecution


@dataclass
class VerificationResult:
    finding_id: str
    verified: bool
    confidence_appropriate: bool
    issues: list[str] = field(default_factory=list)
    supporting_excerpts: list[str] = field(default_factory=list)
    recommendation: str = ""

    @property
    def passed(self) -> bool:
        return self.verified

    @property
    def flagged_claims(self) -> list[str]:
        return self.issues


def verify_finding(
    finding: Finding,
    tool_executions: list[ToolExecution],
) -> VerificationResult:
    """
    Cross-check a finding's claims against the raw tool outputs that produced it.
    Returns VerificationResult with verified=True only if claims are grounded in tool output.
    """
    issues: list[str] = []
    supporting_excerpts: list[str] = []

    # Collect all raw outputs from tools referenced by this finding
    relevant_outputs: list[str] = []
    for te in tool_executions:
        if te.id in finding.tool_execution_refs:
            relevant_outputs.append(te.raw_output.lower())

    if not relevant_outputs:
        issues.append("No tool executions referenced — finding has no grounded evidence.")
        return VerificationResult(
            finding_id=finding.id,
            verified=False,
            confidence_appropriate=False,
            issues=issues,
            recommendation="Downgrade to UNVERIFIED. No tool output cited.",
        )

    combined_output = "\n".join(relevant_outputs)

    # Extract key claims from the finding description
    claims = _extract_claims(finding)
    unverified_claims: list[str] = []

    for claim_type, claim_value in claims:
        if not _claim_in_output(claim_value, combined_output):
            unverified_claims.append(f"{claim_type}: '{claim_value}' not found in tool output")
        else:
            # Grab the matching excerpt for transparency
            excerpt = _get_excerpt(claim_value, combined_output)
            if excerpt:
                supporting_excerpts.append(excerpt)

    if unverified_claims:
        issues.extend(unverified_claims)

    # Check confidence level appropriateness
    confidence_ok = _check_confidence_appropriate(
        finding.confidence,
        len(finding.tool_execution_refs),
        len(unverified_claims),
    )
    if not confidence_ok:
        issues.append(
            f"Confidence {finding.confidence} not appropriate for "
            f"{len(finding.tool_execution_refs)} tool refs and "
            f"{len(unverified_claims)} unverified claims."
        )

    verified = len(unverified_claims) == 0
    recommendation = _build_recommendation(verified, confidence_ok, finding.confidence, unverified_claims)

    return VerificationResult(
        finding_id=finding.id,
        verified=verified,
        confidence_appropriate=confidence_ok,
        issues=issues,
        supporting_excerpts=supporting_excerpts,
        recommendation=recommendation,
    )


def _extract_claims(finding: Finding) -> list[tuple[str, str]]:
    """Extract verifiable claims from finding description and raw_evidence_excerpt."""
    claims: list[tuple[str, str]] = []
    text = f"{finding.description} {finding.raw_evidence_excerpt} {finding.title}"

    # File paths (Windows and Unix)
    for path in re.findall(r"[A-Za-z]:\\(?:[^\s\"'<>|\\/:*?]+\\)*[^\s\"'<>|\\/:*?]*", text):
        claims.append(("file_path", path.lower()))
    for path in re.findall(r"/(?:[^\s\"'<>|\\/:*?]+/)*[^\s\"'<>|\\/:*?]+", text):
        if len(path) > 3:
            claims.append(("unix_path", path.lower()))

    # IP addresses
    for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
        claims.append(("ip_address", ip))

    # Hash values (MD5, SHA1, SHA256)
    for h in re.findall(r"\b[0-9a-fA-F]{32,64}\b", text):
        claims.append(("hash", h.lower()))

    # Process names
    for proc in re.findall(r"\b\w+\.exe\b", text, re.IGNORECASE):
        claims.append(("process", proc.lower()))

    # Registry keys
    for key in re.findall(r"HKEY_[A-Z_]+\\[^\s\"']+", text, re.IGNORECASE):
        claims.append(("registry_key", key.lower()))

    return claims


def _claim_in_output(claim: str, output: str) -> bool:
    return claim.lower() in output.lower()


def _get_excerpt(claim: str, output: str, context: int = 100) -> str:
    idx = output.lower().find(claim.lower())
    if idx == -1:
        return ""
    start = max(0, idx - context)
    end = min(len(output), idx + len(claim) + context)
    return output[start:end].strip()


def _check_confidence_appropriate(
    confidence: ConfidenceLevel,
    tool_ref_count: int,
    unverified_count: int,
) -> bool:
    if unverified_count > 0 and confidence == ConfidenceLevel.CONFIRMED:
        return False
    if tool_ref_count == 0 and confidence != ConfidenceLevel.UNVERIFIED:
        return False
    if tool_ref_count == 1 and confidence == ConfidenceLevel.CONFIRMED:
        return False
    return True


def _build_recommendation(
    verified: bool,
    confidence_ok: bool,
    current_confidence: ConfidenceLevel,
    unverified_claims: list[str],
) -> str:
    if verified and confidence_ok:
        return "Finding verified. No issues found."
    parts = []
    if not verified:
        parts.append(f"{len(unverified_claims)} claim(s) not grounded in tool output — potential hallucination.")
    if not confidence_ok:
        parts.append(f"Confidence {current_confidence} overstated — recommend downgrade.")
    return " ".join(parts)


def batch_verify(
    findings: list[Finding],
    tool_executions: list[ToolExecution],
) -> list[VerificationResult]:
    """Verify all findings in batch. Returns results sorted worst-first."""
    te_by_id = {te.id: te for te in tool_executions}
    results = [
        verify_finding(f, [te_by_id[ref] for ref in f.tool_execution_refs if ref in te_by_id])
        for f in findings
    ]
    return sorted(results, key=lambda r: (r.verified, r.confidence_appropriate))
