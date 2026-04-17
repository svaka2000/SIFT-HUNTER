"""
LangGraph orchestrator — the main multi-agent workflow.

Graph topology:
START -> triage -> disk_analyst -> memory_analyst -> correlator -> verifier -> reporter -> END
                                                                      |
                                                               (if corrections needed)
                                                                      |
                                                     +---- disk_analyst (re-run with corrections)
                                                     |---- memory_analyst (re-run with corrections)
                                                     +---- correlator (re-run after corrections)

The verifier's self-correction loop is the tiebreaker criterion (Criterion 1).
Max 3 correction loops per finding prevents infinite recursion.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Literal

from langgraph.graph import END, START, StateGraph

from agents.nodes.triage import triage_node
from agents.nodes.disk_analyst import disk_analyst_node
from agents.nodes.memory_analyst import memory_analyst_node
from agents.nodes.correlator import correlator_node
from agents.nodes.verifier import verifier_node
from agents.nodes.reporter import reporter_node
from agents.state import AnalysisState, initial_state
from core.audit import get_audit_logger, reset_audit_logger
from mcp_server.config import config


def _route_after_verifier(state: AnalysisState) -> Literal["disk_analyst", "memory_analyst", "correlator", "reporter", "__end__"]:
    """
    Conditional edge: after verifier runs, decide where to go.
    - If corrections needed for disk findings → disk_analyst
    - If corrections needed for memory findings → memory_analyst
    - If max iterations hit → reporter (force finish)
    - If all clean → reporter
    """
    if state["iteration_count"] >= state["max_iterations"]:
        get_audit_logger().log_warning(
            f"Max iterations ({state['max_iterations']}) reached — forcing report generation."
        )
        return "reporter"

    if state.get("verification_passed"):
        return "reporter"

    pending = state.get("pending_corrections", [])
    if not pending:
        return "reporter"

    # Route to the agent that needs to fix findings
    target_agents = {c.get("target_agent", "disk_analyst") for c in pending}
    if "disk_analyst" in target_agents:
        return "disk_analyst"
    elif "memory_analyst" in target_agents:
        return "memory_analyst"
    else:
        return "correlator"


def _route_after_disk(state: AnalysisState) -> Literal["memory_analyst", "verifier"]:
    """After disk analysis, go to memory analysis (first time) or straight to verifier (re-run)."""
    # If memory is already complete (this is a correction re-run), go to verifier
    if state.get("memory_findings_complete") and len(state.get("pending_corrections", [])) == 0:
        return "verifier"
    return "memory_analyst"


def build_graph() -> StateGraph:
    """Build and compile the LangGraph workflow."""
    graph = StateGraph(AnalysisState)

    # Add nodes
    graph.add_node("triage", triage_node)
    graph.add_node("disk_analyst", disk_analyst_node)
    graph.add_node("memory_analyst", memory_analyst_node)
    graph.add_node("correlator", correlator_node)
    graph.add_node("verifier", verifier_node)
    graph.add_node("reporter", reporter_node)

    # Static edges (always run in sequence)
    graph.add_edge(START, "triage")
    graph.add_edge("triage", "disk_analyst")

    # Conditional edge after disk analysis
    graph.add_conditional_edges(
        "disk_analyst",
        _route_after_disk,
        {"memory_analyst": "memory_analyst", "verifier": "verifier"},
    )

    graph.add_edge("memory_analyst", "correlator")
    graph.add_edge("correlator", "verifier")

    # THE SELF-CORRECTION LOOP — this is what wins the tiebreaker
    graph.add_conditional_edges(
        "verifier",
        _route_after_verifier,
        {
            "disk_analyst": "disk_analyst",
            "memory_analyst": "memory_analyst",
            "correlator": "correlator",
            "reporter": "reporter",
            "__end__": END,
        },
    )

    graph.add_edge("reporter", END)

    return graph.compile()


def run_analysis(
    evidence_paths: list[str],
    output_path: str = "",
    max_iterations: int = 50,
) -> dict[str, Any]:
    """
    Run the full SIFT-HUNTER analysis pipeline.
    Returns the final state including the incident report.
    """
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn

    console = Console()

    # Initialize audit logger
    reset_audit_logger(config.AUDIT_LOG_PATH)
    audit = get_audit_logger()

    console.print(f"\n[bold green]SIFT-HUNTER Analysis Starting[/]")
    console.print(f"[dim]Evidence: {evidence_paths}[/]")
    console.print(f"[dim]Output: {output_path or config.OUTPUT_ROOT}[/]\n")

    state = initial_state(evidence_paths, max_iterations=max_iterations)
    graph = build_graph()

    final_state: dict[str, Any] = {}

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Triage...", total=None)

        for event in graph.stream(state, stream_mode="updates"):
            for node_name, update in event.items():
                phase = update.get("current_phase", node_name)
                iteration = update.get("iteration_count", 0)
                progress.update(task, description=f"[{node_name}] Phase: {phase} | Iteration: {iteration}")
                final_state.update(update)

    # Generate final output
    report = final_state.get("report")
    if report:
        if output_path:
            from mcp_server.tools.reporting.markdown_report import generate_markdown_report
            from core.models import IncidentReport
            try:
                report_obj = IncidentReport(**report)
                generate_markdown_report(report_obj, output_path)
                console.print(f"\n[bold green]✓ Report written to:[/] {output_path}")
            except Exception as e:
                console.print(f"\n[yellow]⚠ Could not write report to {output_path}: {e}[/]")

        findings_count = len(final_state.get("findings", []))
        corrections_count = len(final_state.get("corrections", []))
        console.print(f"\n[bold]Analysis Complete:[/]")
        console.print(f"  • Findings: {findings_count}")
        console.print(f"  • Self-corrections: {corrections_count}")
        console.print(f"  • Audit log: {config.AUDIT_LOG_PATH}")

    return final_state


def main():
    parser = argparse.ArgumentParser(
        description="SIFT-HUNTER — Autonomous IR Analysis Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m agents.orchestrator --evidence /cases/disk.dd /cases/memory.dmp
  python -m agents.orchestrator --evidence /mnt/evidence/ --output /tmp/report.md
  python -m agents.orchestrator --evidence /cases/ --max-iterations 30
        """,
    )
    parser.add_argument(
        "--evidence",
        nargs="+",
        required=True,
        help="Path(s) to evidence files or directory",
    )
    parser.add_argument(
        "--output",
        default="",
        help="Output path for Markdown report (optional)",
    )
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=50,
        help="Maximum analysis iterations before forcing report (default: 50)",
    )

    args = parser.parse_args()

    # Expand directory to file list
    evidence_paths: list[str] = []
    for ep in args.evidence:
        p = Path(ep)
        if p.is_dir():
            for f in p.rglob("*"):
                if f.is_file() and not f.name.startswith("."):
                    evidence_paths.append(str(f))
        else:
            evidence_paths.append(str(p))

    if not evidence_paths:
        print("Error: No evidence files found.")
        sys.exit(1)

    final_state = run_analysis(evidence_paths, args.output, args.max_iterations)
    sys.exit(0 if final_state.get("report") else 1)


if __name__ == "__main__":
    main()
