"""Shared state schema for LangGraph multi-agent workflow."""
from __future__ import annotations
from typing import TypedDict, Any


class AnalysisState(TypedDict, total=False):
    # Evidence
    evidence_paths: list[str]
    evidence_hashes: dict[str, str]
    evidence_types: dict[str, str]

    # Workflow control
    current_phase: str
    iteration_count: int
    max_iterations: int

    # Findings accumulated across all agents
    findings: list[dict[str, Any]]
    tool_executions: list[dict[str, Any]]

    # Triage outputs
    triage_complete: bool
    triage_summary: str
    analysis_plan: list[dict]

    # Disk agent outputs
    disk_findings_complete: bool
    disk_raw_outputs: dict[str, str]

    # Memory agent outputs
    memory_findings_complete: bool
    memory_raw_outputs: dict[str, str]

    # Correlation outputs
    correlation_complete: bool
    attack_narrative: str
    attack_timeline: list[dict]

    # Verification and self-correction
    verification_passed: bool
    corrections: list[dict[str, Any]]
    pending_corrections: list[dict]
    correction_counts: dict[str, int]

    # Report
    report: dict[str, Any] | None

    # Errors
    errors: list[str]

    # Internal (underscore = not shown to user)
    _timeline_events: list[dict]
    _inconsistencies: list[dict]
    _verification_summary: str
    _hallucinations: list[str]
    _confidence_summary_update: dict


def initial_state(evidence_paths: list[str], max_iterations: int = 20) -> AnalysisState:
    return AnalysisState(
        evidence_paths=evidence_paths,
        evidence_hashes={},
        evidence_types={},
        current_phase="triage",
        iteration_count=0,
        max_iterations=max_iterations,
        findings=[],
        tool_executions=[],
        triage_complete=False,
        triage_summary="",
        analysis_plan=[],
        disk_findings_complete=False,
        disk_raw_outputs={},
        memory_findings_complete=False,
        memory_raw_outputs={},
        correlation_complete=False,
        attack_narrative="",
        attack_timeline=[],
        verification_passed=False,
        corrections=[],
        pending_corrections=[],
        correction_counts={},
        report=None,
        errors=[],
        _timeline_events=[],
        _inconsistencies=[],
        _verification_summary="",
        _hallucinations=[],
        _confidence_summary_update={},
    )


def add_finding(state: AnalysisState, finding: dict) -> AnalysisState:
    updated = dict(state)
    updated["findings"] = list(state.get("findings", [])) + [finding]
    return AnalysisState(**updated)


def add_correction(state: AnalysisState, correction: dict) -> AnalysisState:
    updated = dict(state)
    updated["corrections"] = list(state.get("corrections", [])) + [correction]
    return AnalysisState(**updated)
