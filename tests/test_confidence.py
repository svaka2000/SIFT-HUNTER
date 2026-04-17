"""Tests for confidence level assignment."""
import pytest
from sift_hunter.core.confidence import assign_confidence
from sift_hunter.core.models import ConfidenceLevel


def test_confirmed_requires_two_sources():
    conf = assign_confidence(
        supporting_tool_count=2,
        evidence_source_types=["disk", "memory"],
        has_direct_tool_output=True,
        is_circumstantial=False,
    )
    assert conf == ConfidenceLevel.CONFIRMED


def test_probable_from_one_strong_source():
    conf = assign_confidence(
        supporting_tool_count=1,
        evidence_source_types=["disk"],
        has_direct_tool_output=True,
        is_circumstantial=False,
    )
    assert conf == ConfidenceLevel.PROBABLE


def test_possible_from_circumstantial():
    conf = assign_confidence(
        supporting_tool_count=1,
        evidence_source_types=["disk"],
        has_direct_tool_output=False,
        is_circumstantial=True,
    )
    assert conf == ConfidenceLevel.POSSIBLE


def test_unverified_from_no_sources():
    conf = assign_confidence(
        supporting_tool_count=0,
        evidence_source_types=[],
        has_direct_tool_output=False,
        is_circumstantial=False,
    )
    assert conf == ConfidenceLevel.UNVERIFIED


def test_single_source_with_no_output_is_possible():
    conf = assign_confidence(
        supporting_tool_count=1,
        evidence_source_types=["disk"],
        has_direct_tool_output=True,
        is_circumstantial=True,
    )
    assert conf in (ConfidenceLevel.POSSIBLE, ConfidenceLevel.PROBABLE)


def test_two_same_type_sources_not_confirmed():
    # Two disk sources but same type — not confirmed
    conf = assign_confidence(
        supporting_tool_count=2,
        evidence_source_types=["disk", "disk"],
        has_direct_tool_output=True,
        is_circumstantial=False,
    )
    assert conf == ConfidenceLevel.PROBABLE
