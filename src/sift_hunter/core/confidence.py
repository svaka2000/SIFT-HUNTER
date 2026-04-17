"""Confidence level assignment rules for forensic findings."""
from __future__ import annotations

from sift_hunter.core.models import ConfidenceLevel, Finding, ToolExecution


def assign_confidence(
    supporting_tool_count: int,
    evidence_source_types: list[str],
    has_direct_tool_output: bool,
    is_circumstantial: bool,
) -> ConfidenceLevel:
    """Assign a confidence level based on evidence quality.

    Rules:
      CONFIRMED  — 2+ independent tool types agree
      PROBABLE   — 1 strong direct tool output
      POSSIBLE   — circumstantial or single weak source
      UNVERIFIED — no direct evidence or tool failure
    """
    unique_sources = len(set(evidence_source_types))
    if unique_sources >= 2 and has_direct_tool_output:
        return ConfidenceLevel.CONFIRMED
    if supporting_tool_count >= 1 and has_direct_tool_output and not is_circumstantial:
        return ConfidenceLevel.PROBABLE
    if supporting_tool_count >= 1 or is_circumstantial:
        return ConfidenceLevel.POSSIBLE
    return ConfidenceLevel.UNVERIFIED


def upgrade_confidence(
    finding: Finding,
    new_evidence_types: list[str],
) -> ConfidenceLevel:
    """Upgrade confidence when new corroborating evidence is found."""
    all_types = set(finding.evidence_refs) | set(new_evidence_types)
    if finding.confidence == ConfidenceLevel.UNVERIFIED and all_types:
        return ConfidenceLevel.POSSIBLE
    if finding.confidence == ConfidenceLevel.POSSIBLE and len(all_types) >= 2:
        return ConfidenceLevel.PROBABLE
    if finding.confidence == ConfidenceLevel.PROBABLE and len(all_types) >= 3:
        return ConfidenceLevel.CONFIRMED
    return finding.confidence


def downgrade_confidence(finding: Finding, reason: str) -> ConfidenceLevel:
    """Downgrade confidence one level when verifier finds an issue."""
    order = [
        ConfidenceLevel.CONFIRMED,
        ConfidenceLevel.PROBABLE,
        ConfidenceLevel.POSSIBLE,
        ConfidenceLevel.UNVERIFIED,
    ]
    idx = order.index(finding.confidence)
    return order[min(idx + 1, len(order) - 1)]


def confidence_from_str(s: str) -> ConfidenceLevel:
    """Parse a confidence level string, returning UNVERIFIED on failure."""
    try:
        return ConfidenceLevel[s.upper()]
    except (KeyError, AttributeError):
        return ConfidenceLevel.UNVERIFIED
