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
    """SIFT-HUNTER - Autonomous AI incident response for SANS SIFT Workstation."""


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

    # Preflight: the agents require an LLM. Fail loudly with guidance instead of
    # silently returning zero findings when no API key is configured.
    if not config.GROQ_API_KEY and not config.ANTHROPIC_API_KEY:
        console.print(Panel(
            "[bold red]No LLM API key configured.[/]\n\n"
            "SIFT-HUNTER's agents need an LLM to reason over evidence. Set one of\n"
            "the following and re-run:\n"
            "  [cyan]export GROQ_API_KEY=...[/]       # free tier, fast\n"
            "  [cyan]export ANTHROPIC_API_KEY=...[/]  # alternative\n\n"
            "(The security layer, [cyan]check[/], [cyan]audit[/], and the hallucination\n"
            "benchmark all run without a key.)",
            border_style="red",
            title="Configuration Required",
        ))
        sys.exit(2)
    for _warning in config.validate():
        console.print(f"[yellow]⚠ {_warning}[/]")

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
        result = asyncio.run(run_analysis(paths, str(out_dir)))
        elapsed = __import__("time").time() - start

        report_dict = result.get("report") or {}
        cs_dict = report_dict.get("confidence_summary", {})
        findings = result.get("findings", [])
        corrections = result.get("corrections", [])

        table = Table(title="Analysis Complete", border_style="green")
        table.add_column("Metric", style="bold")
        table.add_column("Value")
        table.add_row("Findings", str(len(findings)))
        table.add_row("  CONFIRMED", f"[red]{cs_dict.get('confirmed', 0)}[/]")
        table.add_row("  PROBABLE", f"[yellow]{cs_dict.get('probable', 0)}[/]")
        table.add_row("  POSSIBLE", f"[cyan]{cs_dict.get('possible', 0)}[/]")
        table.add_row("  UNVERIFIED", str(cs_dict.get("unverified", 0)))
        table.add_row("Self-corrections", str(len(corrections)))
        table.add_row("Hallucinations caught", str(cs_dict.get("hallucinations_caught", 0)))
        table.add_row("Duration", f"{elapsed:.1f}s")
        table.add_row("Output dir", str(out_dir))
        table.add_row("Audit log", config.AUDIT_LOG_PATH)
        console.print(table)

        # Write report to markdown file
        if report_dict:
            _write_markdown_report(report_dict, output)
            console.print(f"[green]Report written to {output}[/]")

    except Exception as e:
        console.print(f"[red]Analysis failed: {e}[/]")
        import traceback
        console.print(traceback.format_exc())
        sys.exit(1)


def _write_markdown_report(report: dict, output_path: str) -> None:
    """Write incident report as structured markdown."""
    from sift_hunter.core.models import ConfidenceLevel
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    lines = [
        f"# Incident Report: {report.get('title', 'SIFT-HUNTER Analysis')}\n",
        f"> **Generated:** {report.get('generated_at', 'n/a')}  \n",
        f"> **Report ID:** `{report.get('id', 'n/a')}`  \n",
        f"> **Tool:** SIFT-HUNTER v{report.get('tool_version', '1.0.0')}\n\n---\n",
        "## Executive Summary\n\n",
        report.get("summary", "No summary generated.") + "\n\n",
        "## Finding Confidence Summary\n\n",
        "| Level | Count |\n|-------|-------|\n",
    ]
    cs = report.get("confidence_summary", {})
    lines += [
        f"| 🔴 CONFIRMED | {cs.get('confirmed', 0)} |\n",
        f"| 🟠 PROBABLE | {cs.get('probable', 0)} |\n",
        f"| 🟡 POSSIBLE | {cs.get('possible', 0)} |\n",
        f"| ⚪ UNVERIFIED | {cs.get('unverified', 0)} |\n",
        f"| **Total** | **{cs.get('total', 0)}** |\n",
        f"| Hallucinations Caught | {cs.get('hallucinations_caught', 0)} |\n",
        f"| Self-Corrections Applied | {cs.get('self_corrections_applied', 0)} |\n\n",
        "## Detailed Findings\n\n",
    ]
    for i, f in enumerate(report.get("findings", []), 1):
        conf = f.get("confidence", "UNVERIFIED")
        icon = {"CONFIRMED": "🔴", "PROBABLE": "🟠", "POSSIBLE": "🟡", "UNVERIFIED": "⚪"}.get(conf, "⚪")
        lines.append(f"### {i}. {f.get('title', f.get('description', '')[:60])}\n\n")
        lines.append(f"**Type:** {f.get('type', 'UNKNOWN')}  \n")
        lines.append(f"**Confidence:** {icon} {conf}  \n")
        lines.append(f"**Agent:** {f.get('agent', 'unknown')}  \n\n")
        lines.append(f"{f.get('description', '')}  \n\n")
        excerpt = f.get("raw_evidence_excerpt", "")
        if excerpt:
            lines.append(f"**Evidence Excerpt:**\n```\n{excerpt}\n```\n\n")
        ttps = f.get("mitre_ttps", [])
        if ttps:
            lines.append("**MITRE ATT&CK:**\n")
            for t in ttps:
                lines.append(f"- [{t.get('technique_id')}](#) - {t.get('technique_name')} ({t.get('tactic')})\n")
            lines.append("\n")
        artifact = f.get("artifact_path", "")
        if artifact:
            lines.append(f"**Artifact:** `{artifact}`\n\n")
        vn = f.get("verification_notes", "")
        if vn:
            lines.append(f"**Verification:** {vn}\n\n")
        lines.append("---\n\n")

    lines += ["## Attack Timeline\n\n"]
    for e in report.get("attack_timeline", []):
        ts = e.get("timestamp", "n/a")
        if hasattr(ts, "isoformat"):
            ts = ts.isoformat()
        lines.append(f"- `{ts}` - {e.get('description', '')} *(Confidence: {e.get('confidence', '')})*\n")

    lines += ["\n## Evidence Inventory\n\n", "| File | SHA256 |\n|------|--------|\n"]
    for path in report.get("evidence_paths", []):
        name = Path(path).name
        lines.append(f"| `{name}` | computed on ingest |\n")

    lines += [
        f"\n## Self-Assessment & Limitations\n\n{report.get('self_assessment', '')}\n\n",
        "## Recommendations\n\n",
    ]
    for rec in report.get("recommendations", []):
        lines.append(f"{rec}  \n")
    lines += [
        "\n---\n\n",
        "*Report generated by SIFT-HUNTER - Self-correcting Intelligent Forensic Triage & Hunt*  \n",
        "*All findings include confidence levels and evidence citations.*\n",
    ]
    with open(output_path, "w") as f:
        f.write("".join(lines))


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
