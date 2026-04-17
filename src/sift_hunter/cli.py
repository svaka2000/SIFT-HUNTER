"""Click CLI for SIFT-HUNTER: analyze | server | audit | check | version."""
from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


@click.group()
def main() -> None:
    """SIFT-HUNTER — Autonomous AI incident response for SANS SIFT Workstation."""


@main.command()
@click.argument("evidence_paths", nargs=-1, required=True)
@click.option("--output", "-o", default="/tmp/sift-output/incident-report.md",
              help="Output report path")
@click.option("--max-iterations", default=None, type=int,
              help="Override max analysis iterations")
@click.option("--model", default=None, help="Override LLM model")
def analyze(evidence_paths: tuple[str, ...], output: str, max_iterations: int | None, model: str | None) -> None:
    """Run full autonomous analysis on EVIDENCE_PATHS."""
    from sift_hunter.config import config
    from sift_hunter.agents.orchestrator import run_analysis

    if max_iterations:
        os.environ["SIFT_MAX_ITERATIONS"] = str(max_iterations)
    if model:
        os.environ["SIFT_MODEL"] = model

    paths = list(evidence_paths)
    console.print(Panel(
        f"[bold cyan]SIFT-HUNTER[/] Analysis Starting\n"
        f"Evidence: {paths}\n"
        f"Output: {output}",
        border_style="cyan",
    ))

    out_dir = Path(output).parent
    out_dir.mkdir(parents=True, exist_ok=True)

    start = __import__("time").time()
    try:
        report = asyncio.run(run_analysis(paths, output))
        elapsed = __import__("time").time() - start

        cs = report.confidence_summary
        table = Table(title="Analysis Complete", border_style="green")
        table.add_column("Metric", style="bold")
        table.add_column("Value")
        table.add_row("Findings", str(cs.total))
        table.add_row("  CONFIRMED", f"[red]{cs.confirmed}[/]")
        table.add_row("  PROBABLE", f"[yellow]{cs.probable}[/]")
        table.add_row("  POSSIBLE", f"[cyan]{cs.possible}[/]")
        table.add_row("  UNVERIFIED", str(cs.unverified))
        table.add_row("Self-corrections", str(cs.corrections_made))
        table.add_row("Hallucinations caught", str(cs.hallucinations_caught))
        table.add_row("Duration", f"{elapsed:.1f}s")
        table.add_row("Report", f"[link={output}]{output}[/]")
        table.add_row("Audit log", config.AUDIT_LOG_PATH)
        console.print(table)

    except Exception as e:
        console.print(f"[red]Analysis failed: {e}[/]")
        import traceback
        console.print(traceback.format_exc())
        sys.exit(1)


@main.command()
@click.option("--host", default="127.0.0.1", help="Server host")
@click.option("--port", default=8765, type=int, help="Server port")
def server(host: str, port: int) -> None:
    """Start the MCP server for Protocol SIFT integration."""
    from sift_hunter.mcp_server.server import create_server
    console.print(f"[cyan]Starting SIFT-HUNTER MCP server on {host}:{port}[/]")
    srv = create_server()
    srv.run()


@main.command()
@click.argument("finding_id")
def audit(finding_id: str) -> None:
    """Trace a finding back through its full evidence chain.

    FINDING_ID: e.g., F-abc12345
    """
    from sift_hunter.config import config
    from sift_hunter.core.audit import AuditLogger

    logger = AuditLogger(config.AUDIT_LOG_PATH)
    chain = logger.trace_chain(finding_id)

    if not chain["chronological"]:
        console.print(f"[yellow]No audit entries found for finding {finding_id}[/]")
        return

    console.print(Panel(f"[bold]Evidence Chain for {finding_id}[/]", border_style="blue"))

    for entry in chain["chronological"]:
        ts = entry.timestamp.strftime("%H:%M:%S")
        action_color = {
            "tool_call": "cyan",
            "finding_created": "green",
            "verification_check": "yellow",
            "correction_issued": "red",
            "error": "red bold",
        }.get(entry.action, "white")
        console.print(
            f"  [{ts}] [{action_color}]{entry.action:25}[/] [dim]{entry.agent:20}[/] {entry.details[:100]}"
        )


@main.command()
@click.argument("command_string")
def check(command_string: str) -> None:
    """Test whether a command would be allowed by the security layer."""
    from sift_hunter.mcp_server.security.command_sanitizer import validate_command
    from sift_hunter.core.exceptions import SecurityViolation

    parts = command_string.split()
    if not parts:
        console.print("[red]Empty command[/]")
        return

    binary = parts[0]
    args = parts[1:]

    try:
        resolved, safe_args = validate_command(binary, args)
        console.print(Panel(
            f"[green]✓ ALLOWED[/]\n\nResolved binary: {resolved}\nSafe args: {safe_args}",
            border_style="green",
            title="Security Check",
        ))
    except SecurityViolation as e:
        console.print(Panel(
            f"[red]✗ BLOCKED[/]\n\nReason: {e}",
            border_style="red",
            title="Security Check",
        ))


@main.command("version")
def version_cmd() -> None:
    """Print version information."""
    from sift_hunter import __version__
    console.print(f"[bold cyan]sift-hunter[/] {__version__}")
    console.print("SANS FIND EVIL! Hackathon Submission")
    console.print("Pattern 2 (Custom MCP Server) + Pattern 3 (Multi-Agent)")
