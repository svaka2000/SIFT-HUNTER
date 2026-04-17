"""
Shared state schema for the LangGraph multi-agent workflow.
Every agent reads from and writes to this TypedDict.
Immutable evidence + mutable findings = forensically sound state management.
"""

from __future__ import annotations

from typing import Annotated, Any, Optional
from typing_extensions import TypedDict

from langgraph.graph.message import add_messages

from core.models import (
    AuditEntry,
    Correction,
    Evidence,
    Finding,
    IncidentReport,
    ToolExecution,
)


class AnalysisState(TypedDict):
    # Evidence inventory — immutable after ingest
    evidence_paths: list[str]
    evidence_items: list[dict]          # Serialized Evidence objects
    evidence_hashes: dict[str, str]     # path -> sha256

    # Workflow control
    current_phase: str                  # triage | disk | memory | correlation | verification | reporting
    iteration_count: int
    max_iterations: int
    correction_counts: dict[str, int]   # finding_id -> number of correction loops

    # Accumulated findings
    findings: list[dict]                # Serialized Finding objects
    tool_executions: list[dict]         # Serialized ToolExecution objects

    # Self-correction system
    corrections: list[dict]             # Serialized Correction objects
    pending_corrections: list[dict]     # Corrections that need re-examination
    verification_passed: bool

    # Agent communication
    triage_plan: dict[str, Any]         # Analysis plan from triage agent
    disk_findings_complete: bool
    memory_findings_complete: bool
    correlation_complete: bool

    # Errors and degradation
    errors: list[str]
    tool_failures: list[str]

    # Final output
    report: Optional[dict]              # Serialized IncidentReport

    # LangGraph message history
    messages: Annotated[list, add_messages]


def initial_state(
    evidence_paths: list[str],
    max_iterations: int = 50,
) -> AnalysisState:
    """Create the initial state for a new analysis run."""
    return AnalysisState(
        evidence_paths=evidence_paths,
        evidence_items=[],
        evidence_hashes={},
        current_phase="triage",
        iteration_count=0,
        max_iterations=max_iterations,
        correction_counts={},
        findings=[],
        tool_executions=[],
        corrections=[],
        pending_corrections=[],
        verification_passed=False,
        triage_plan={},
        disk_findings_complete=False,
        memory_findings_complete=False,
        correlation_complete=False,
        errors=[],
        tool_failures=[],
        report=None,
        messages=[],
    )


def add_finding(state: AnalysisState, finding: Finding) -> None:
    """Append a finding to state (mutates in place for LangGraph reducer)."""
    state["findings"].append(finding.model_dump(mode="json"))


def add_tool_execution(state: AnalysisState, te: ToolExecution) -> None:
    state["tool_executions"].append(te.model_dump(mode="json"))


def add_correction(state: AnalysisState, correction: Correction) -> None:
    state["corrections"].append(correction.model_dump(mode="json"))
    # Track per-finding correction depth
    count = state["correction_counts"].get(correction.finding_id, 0) + 1
    state["correction_counts"][correction.finding_id] = count


def get_finding_by_id(state: AnalysisState, finding_id: str) -> Optional[dict]:
    for f in state["findings"]:
        if f.get("id") == finding_id:
            return f
    return None


def get_te_by_id(state: AnalysisState, te_id: str) -> Optional[dict]:
    for te in state["tool_executions"]:
        if te.get("id") == te_id:
            return te
    return None
