"""
Timeline visualization — generates ASCII and Markdown timeline charts.
Used in reports and the demo video to show attacker progression.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from core.models import AttackTimelineEvent, ConfidenceLevel, IncidentReport


TACTIC_ICONS = {
    "Initial Access": "🚪",
    "Execution": "⚡",
    "Persistence": "📌",
    "Privilege Escalation": "⬆️",
    "Defense Evasion": "🎭",
    "Credential Access": "🔑",
    "Discovery": "🔍",
    "Lateral Movement": "↔️",
    "Collection": "📦",
    "Command and Control": "📡",
    "Exfiltration": "📤",
    "Impact": "💥",
}


def generate_ascii_timeline(events: list[AttackTimelineEvent]) -> str:
    """Generate an ASCII art timeline for the terminal / report."""
    if not events:
        return "No timeline events to display."

    sorted_events = sorted(events, key=lambda e: e.timestamp)
    lines: list[str] = [
        "=" * 70,
        "  ATTACK TIMELINE",
        "=" * 70,
    ]

    for event in sorted_events:
        ts = event.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        icon = TACTIC_ICONS.get(event.mitre_tactic or "", "•")
        conf_char = {
            ConfidenceLevel.CONFIRMED: "●",
            ConfidenceLevel.PROBABLE: "◉",
            ConfidenceLevel.POSSIBLE: "○",
            ConfidenceLevel.UNVERIFIED: "◌",
        }.get(event.confidence, "?")

        lines.append(f"  {ts}  {icon} [{conf_char}] {event.description[:60]}")
        if event.mitre_tactic:
            lines.append(f"  {'':>19}  └─ Tactic: {event.mitre_tactic}")

    lines.append("=" * 70)
    lines.append("● CONFIRMED  ◉ PROBABLE  ○ POSSIBLE  ◌ UNVERIFIED")
    return "\n".join(lines)


def generate_markdown_timeline(report: IncidentReport) -> str:
    """Generate a Markdown Gantt-style timeline for inclusion in reports."""
    events = sorted(report.attack_timeline, key=lambda e: e.timestamp)
    if not events:
        return "_No timeline events recorded._"

    lines: list[str] = ["```", "ATTACK TIMELINE"]
    lines.append("─" * 60)

    for event in events:
        ts = event.timestamp.strftime("%m/%d %H:%M")
        icon = TACTIC_ICONS.get(event.mitre_tactic or "", "│")
        lines.append(f"  {ts}  {icon}  {event.description[:50]}")

    lines.append("─" * 60)
    lines.append("```")
    return "\n".join(lines)
