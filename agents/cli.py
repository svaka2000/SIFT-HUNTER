"""
SIFT-HUNTER CLI — command-line interface for analysis and audit queries.
Entrypoint for `sift-hunter` command after installation.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

app = typer.Typer(
    name="sift-hunter",
    help="SIFT-HUNTER — Self-correcting Intelligent Forensic Triage & Hunt",
    add_completion=False,
)
console = Console()


@app.command("analyze")
def analyze(
    evidence: list[str] = typer.Argument(..., help="Evidence file(s) or directory"),
    output: str = typer.Option("", "--output", "-o", help="Output path for Markdown report"),
    max_iterations: int = typer.Option(50, "--max-iter", help="Max analysis iterations"),
):
    """Run full forensic analysis on evidence files."""
    from agents.orchestrator import run_analysis
    run_analysis(list(evidence), output, max_iterations)


@app.command("audit")
def audit_trail(
    finding_id: str = typer.Argument(..., help="Finding ID to trace"),
    log_path: str = typer.Option("", "--log", help="Path to audit log JSONL"),
):
    """Show the full evidence chain for a finding ID."""
    from core.audit import get_audit_logger, reset_audit_logger
    from mcp_server.config import config

    if log_path:
        logger = reset_audit_logger(log_path)
        # Reload entries from file
        try:
            from core.models import AuditEntry
            with open(log_path) as f:
                for line in f:
                    try:
                        entry = AuditEntry(**json.loads(line.strip()))
                        logger._entries.append(entry)
                        if entry.finding_id:
                            logger._index.setdefault(entry.finding_id, []).append(entry.id)
                    except Exception:
                        pass
        except FileNotFoundError:
            console.print(f"[red]Audit log not found: {log_path}[/]")
            raise typer.Exit(1)
    else:
        logger = get_audit_logger(config.AUDIT_LOG_PATH)

    chain = logger.print_finding_chain(finding_id)
    console.print(Panel(chain, title=f"Evidence Chain: {finding_id}", border_style="blue"))


@app.command("server")
def start_server():
    """Start the SIFT-HUNTER MCP server."""
    from mcp_server.server import main
    main()


@app.command("check")
def security_check(
    command: str = typer.Argument(..., help="Command to test against security guardrails"),
):
    """Test whether a command would be blocked by security guardrails."""
    from mcp_server.security import check_command_safety
    from mcp_server.validators.path_validator import SecurityError

    try:
        check_command_safety(command)
        console.print(f"[green]✓ ALLOWED:[/] {command}")
    except SecurityError as e:
        console.print(f"[red]✗ BLOCKED:[/] {command}")
        console.print(f"[dim]Reason: {e}[/]")


@app.command("status")
def show_status():
    """Show current configuration and environment status."""
    from mcp_server.config import config

    table = Table(title="SIFT-HUNTER Configuration")
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="white")
    table.add_column("Status", style="green")

    checks = [
        ("Anthropic API Key", "***configured***" if config.ANTHROPIC_API_KEY else "NOT SET",
         "✓" if config.ANTHROPIC_API_KEY else "✗"),
        ("VT API Key", "***configured***" if config.VT_API_KEY else "NOT SET (optional)",
         "✓" if config.VT_API_KEY else "○"),
        ("AbuseIPDB Key", "***configured***" if config.ABUSEIPDB_API_KEY else "NOT SET (optional)",
         "✓" if config.ABUSEIPDB_API_KEY else "○"),
        ("Evidence Roots", str(config.EVIDENCE_ROOTS), ""),
        ("Output Root", config.OUTPUT_ROOT, ""),
        ("Audit Log", config.AUDIT_LOG_PATH, ""),
        ("Model", config.MODEL, ""),
        ("Max Iterations", str(config.MAX_ITERATIONS), ""),
    ]

    for setting, value, status in checks:
        table.add_row(setting, value, status)

    console.print(table)

    warnings = config.validate()
    if warnings:
        console.print("\n[yellow]Warnings:[/]")
        for w in warnings:
            console.print(f"  [yellow]⚠[/] {w}")


def main():
    app()


if __name__ == "__main__":
    main()
