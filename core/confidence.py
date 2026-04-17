"""
Confidence level assignment for findings.
Rules enforce forensic discipline: multiple independent sources required for CONFIRMED.
"""

from __future__ import annotations

from core.models import ConfidenceLevel, Evidence, Finding


def assign_confidence(
    finding: Finding,
    supporting_evidence: list[Evidence],
    independent_source_count: int = 0,
) -> ConfidenceLevel:
    """
    Assign a confidence level based on evidence quantity and quality.

    CONFIRMED  = 2+ independent evidence sources corroborate
    PROBABLE   = 1 strong direct evidence source
    POSSIBLE   = Circumstantial or indirect evidence
    UNVERIFIED = Single weak source, tool failure, or unverified claim
    """
    total_sources = len(supporting_evidence) + independent_source_count

    if total_sources >= 2:
        return ConfidenceLevel.CONFIRMED
    elif total_sources == 1 and _is_strong_evidence(supporting_evidence):
        return ConfidenceLevel.PROBABLE
    elif total_sources == 1:
        return ConfidenceLevel.POSSIBLE
    else:
        return ConfidenceLevel.UNVERIFIED


def _is_strong_evidence(evidence_list: list[Evidence]) -> bool:
    """Strong evidence = directly observed artifact (not inferred)."""
    from core.models import EvidenceType
    strong_types = {
        EvidenceType.MFT,
        EvidenceType.PREFETCH,
        EvidenceType.AMCACHE,
        EvidenceType.REGISTRY_HIVE,
        EvidenceType.MEMORY_CAPTURE,
    }
    return any(e.evidence_type in strong_types for e in evidence_list)


def downgrade_confidence(level: ConfidenceLevel) -> ConfidenceLevel:
    """Move down one confidence level — used when verifier flags an issue."""
    ladder = [
        ConfidenceLevel.CONFIRMED,
        ConfidenceLevel.PROBABLE,
        ConfidenceLevel.POSSIBLE,
        ConfidenceLevel.UNVERIFIED,
    ]
    idx = ladder.index(level)
    return ladder[min(idx + 1, len(ladder) - 1)]


def confidence_to_score(level: ConfidenceLevel) -> float:
    return {
        ConfidenceLevel.CONFIRMED: 1.0,
        ConfidenceLevel.PROBABLE: 0.75,
        ConfidenceLevel.POSSIBLE: 0.5,
        ConfidenceLevel.UNVERIFIED: 0.1,
    }[level]
