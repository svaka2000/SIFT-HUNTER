"""LangGraph orchestrator — multi-agent workflow with self-correction loop."""
from __future__ import annotations
import asyncio
import os
from pathlib import Path
from typing import Any

from langgraph.graph import StateGraph, END

from sift_hunter.agents.state import AnalysisState, initial_state
from sift_hunter.agents.nodes import (
    triage_node,
    disk_analyst_node,
    memory_analyst_node,
    correlator_node,
    verifier_node,
    reporter_node,
)
from sift_hunter.core.audit import get_audit_logger, reset_audit_logger
from sift_hunter.core.models import IncidentReport


def _route_after_triage(state: AnalysisState) -> str:
    return "disk_analyst"


def _route_after_disk(state: AnalysisState) -> str:
    return "memory_analyst"


def _route_after_memory(state: AnalysisState) -> str:
    return "correlator"


def _route_after_correlator(state: AnalysisState) -> str:
    return "verifier"


def _route_after_verifier(state: AnalysisState) -> str:
    """Self-correction routing: send back to analysts or advance to reporter."""
    phase = state.get("current_phase", "reporting")
    if phase == "disk":
        return "disk_analyst"
    elif phase == "memory":
        return "memory_analyst"
    elif phase == "reporting":
        return "reporter"
    # Safety: if iteration cap reached, go to reporter
    iteration = state.get("iteration_count", 0)
    max_iter = state.get("max_iterations", 20)
    if iteration >= max_iter:
        return "reporter"
    return "reporter"


def build_graph() -> StateGraph:
    """Build and compile the LangGraph workflow."""
    graph = StateGraph(AnalysisState)

    graph.add_node("triage", triage_node)
    graph.add_node("disk_analyst", disk_analyst_node)
    graph.add_node("memory_analyst", memory_analyst_node)
    graph.add_node("correlator", correlator_node)
    graph.add_node("verifier", verifier_node)
    graph.add_node("reporter", reporter_node)

    graph.set_entry_point("triage")

    graph.add_conditional_edges("triage", _route_after_triage, {
        "disk_analyst": "disk_analyst",
    })
    graph.add_conditional_edges("disk_analyst", _route_after_disk, {
        "memory_analyst": "memory_analyst",
    })
    graph.add_conditional_edges("memory_analyst", _route_after_memory, {
        "correlator": "correlator",
    })
    graph.add_conditional_edges("correlator", _route_after_correlator, {
        "verifier": "verifier",
    })
    graph.add_conditional_edges("verifier", _route_after_verifier, {
        "disk_analyst": "disk_analyst",
        "memory_analyst": "memory_analyst",
        "reporter": "reporter",
    })
    graph.add_edge("reporter", END)

    return graph.compile()


async def run_analysis(
    evidence_paths: list[str],
    output_dir: str = "/tmp/sift-output",
    max_iterations: int = 20,
) -> dict[str, Any]:
    """Run the full SIFT-HUNTER analysis pipeline."""
    os.makedirs(output_dir, exist_ok=True)
    os.environ.setdefault("SIFT_OUTPUT_ROOT", output_dir)

    audit = get_audit_logger()
    audit.log_agent_transition(
        agent="orchestrator",
        action="ANALYSIS_START",
        phase="init",
        reasoning=f"Starting analysis of {len(evidence_paths)} evidence items",
    )

    state = initial_state(evidence_paths, max_iterations=max_iterations)
    app = build_graph()

    # LangGraph invoke is sync; run in executor to keep async signature
    loop = asyncio.get_event_loop()
    final_state = await loop.run_in_executor(None, app.invoke, state)

    report_dict = final_state.get("report")
    stats = audit.get_statistics()

    audit.log_agent_transition(
        agent="orchestrator",
        action="ANALYSIS_COMPLETE",
        phase="complete",
        reasoning=(
            f"Findings: {len(final_state.get('findings', []))} | "
            f"Corrections: {len(final_state.get('corrections', []))} | "
            f"Errors: {len(final_state.get('errors', []))}"
        ),
    )

    return {
        "report": report_dict,
        # Prefer the reporter's de-duplicated findings so the CLI summary matches the report.
        "findings": (report_dict or {}).get("findings") or final_state.get("findings", []),
        "corrections": final_state.get("corrections", []),
        "errors": final_state.get("errors", []),
        "audit_stats": stats,
        "evidence_hashes": final_state.get("evidence_hashes", {}),
    }
