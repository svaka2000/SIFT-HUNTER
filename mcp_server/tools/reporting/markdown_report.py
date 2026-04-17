"""
Structured Markdown report generator — produces professional IR reports.
Every section is evidence-backed with confidence levels and MITRE mappings.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Optional

from core.models import ConfidenceLevel, IncidentReport


CONFIDENCE_EMOJI = {
    ConfidenceLevel.CONFIRMED: "🔴",
    ConfidenceLevel.PROBABLE: "🟠",
    ConfidenceLevel.POSSIBLE: "🟡",
    ConfidenceLevel.UNVERIFIED: "⚪",
}

CONFIDENCE_LABEL = {
    ConfidenceLevel.CONFIRMED: "CONFIRMED",
    ConfidenceLevel.PROBABLE: "PROBABLE",
    ConfidenceLevel.POSSIBLE: "POSSIBLE",
    ConfidenceLevel.UNVERIFIED: "UNVERIFIED",
}


def generate_markdown_report(report: IncidentReport, output_path: Optional[str] = None) -> str:
    """Generate a full incident report as Markdown. Optionally write to file."""
    lines: list[str] = []

    # Title and metadata
    lines += [
        f"# {report.title}",
        "",
        f"> **Generated:** {report.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
        f"> **Report ID:** `{report.id}`  ",
        f"> **Tool:** SIFT-HUNTER v1.0.0",
        "",
        "---",
        "",
    ]

    # Executive Summary
    lines += [
        "## Executive Summary",
        "",
        report.executive_summary,
        "",
    ]

    # Confidence Summary
    cs = report.confidence_summary
    lines += [
        "## Finding Confidence Summary",
        "",
        f"| Level | Count |",
        f"|-------|-------|",
        f"| 🔴 CONFIRMED | {cs.confirmed} |",
        f"| 🟠 PROBABLE | {cs.probable} |",
        f"| 🟡 POSSIBLE | {cs.possible} |",
        f"| ⚪ UNVERIFIED | {cs.unverified} |",
        f"| **Total** | **{cs.total}** |",
        f"| Hallucinations Caught | {cs.hallucinations_caught} |",
        f"| Self-Corrections Applied | {cs.corrections_made} |",
        "",
    ]

    # Detailed Findings
    lines += ["## Detailed Findings", ""]
    for i, finding in enumerate(sorted(report.findings, key=lambda f: list(ConfidenceLevel).index(f.confidence))):
        emoji = CONFIDENCE_EMOJI[finding.confidence]
        label = CONFIDENCE_LABEL[finding.confidence]
        lines += [
            f"### {i+1}. {finding.title}",
            "",
            f"**Type:** {finding.finding_type.value}  ",
            f"**Confidence:** {emoji} {label}  ",
            f"**Agent:** {finding.agent_source}  ",
            "",
            finding.description,
            "",
        ]
        if finding.raw_evidence_excerpt:
            lines += [
                "**Evidence Excerpt:**",
                "```",
                finding.raw_evidence_excerpt[:500],
                "```",
                "",
            ]
        if finding.mitre_ttps:
            lines += ["**MITRE ATT&CK:**"]
            for ttp in finding.mitre_ttps:
                lines.append(f"- [{ttp.technique_id}]({ttp.evidence_ref or '#'}) — {ttp.technique_name} ({ttp.tactic})")
            lines.append("")
        if finding.artifact_path:
            lines += [f"**Artifact:** `{finding.artifact_path}`", ""]
        if finding.verification_notes:
            lines += [f"**Verification:** {finding.verification_notes}", ""]
        lines.append("---")
        lines.append("")

    # Attack Timeline
    if report.attack_timeline:
        lines += ["## Attack Timeline", ""]
        for event in sorted(report.attack_timeline, key=lambda e: e.timestamp):
            ts = event.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            lines.append(f"- `{ts}` — {event.description} *(Confidence: {event.confidence.value})*")
        lines.append("")

    # MITRE ATT&CK Coverage
    if report.mitre_mapping:
        lines += ["## MITRE ATT&CK Coverage", ""]
        tactic_groups: dict[str, list] = {}
        for m in report.mitre_mapping:
            tactic_groups.setdefault(m.tactic, []).append(m)
        for tactic, techniques in sorted(tactic_groups.items()):
            lines.append(f"### {tactic}")
            for t in techniques:
                lines.append(f"- **{t.technique_id}** — {t.technique_name}")
            lines.append("")

    # Evidence Inventory
    if report.evidence_items:
        lines += ["## Evidence Inventory", ""]
        lines.append("| File | Type | SHA256 | Verified |")
        lines.append("|------|------|--------|----------|")
        for ev in report.evidence_items:
            sha = ev.hash_sha256[:16] + "..." if ev.hash_sha256 else "N/A"
            lines.append(f"| `{Path(ev.path).name}` | {ev.evidence_type.value} | `{sha}` | {'✓' if ev.hash_verified else '✗'} |")
        lines.append("")

    # Self-Assessment
    if report.self_assessment:
        lines += ["## Self-Assessment & Limitations", "", report.self_assessment, ""]

    if report.limitations:
        lines += ["### Known Limitations", ""]
        for lim in report.limitations:
            lines.append(f"- {lim}")
        lines.append("")

    # Recommendations
    if report.recommendations:
        lines += ["## Recommendations", ""]
        for i, rec in enumerate(report.recommendations):
            lines.append(f"{i+1}. {rec}")
        lines.append("")

    # Footer
    lines += [
        "---",
        "",
        f"*Report generated by SIFT-HUNTER — Self-correcting Intelligent Forensic Triage & Hunt*  ",
        f"*All findings include confidence levels and evidence citations.*",
    ]

    content = "\n".join(lines)

    if output_path:
        Path(output_path).write_text(content, encoding="utf-8")

    return content
