"""
Correlation Agent — cross-references disk and memory findings to build attack narrative.
Maps findings to MITRE ATT&CK and identifies inconsistencies for the verifier.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from langchain_anthropic import ChatAnthropic
from langchain_core.messages import HumanMessage, SystemMessage

from agents.state import AnalysisState
from core.audit import get_audit_logger
from core.models import AttackTimelineEvent, ConfidenceLevel, MITREMapping
from mcp_server.config import config
from mcp_server.tools.enrichment.mitre import map_finding_to_ttps

SYSTEM_PROMPT = """You are a senior threat analyst correlating findings across disk and memory evidence.

Your job:
1. Cross-reference findings from disk analysis and memory analysis
2. Build a unified attack timeline with timestamps
3. Map the full attack chain to MITRE ATT&CK tactics and techniques
4. Flag any inconsistencies between evidence sources (these will go to the verifier)
5. Produce a coherent attack narrative

Respond ONLY with valid JSON:
{
  "attack_narrative": "Paragraph describing the full attack chain",
  "attack_timeline": [
    {
      "timestamp": "ISO8601 or null",
      "description": "What happened at this time",
      "mitre_tactic": "Initial Access|Execution|Persistence|...",
      "confidence": "CONFIRMED|PROBABLE|POSSIBLE|UNVERIFIED",
      "finding_refs": ["finding IDs that support this"]
    }
  ],
  "mitre_coverage": [
    {"technique_id": "T1059.001", "technique_name": "PowerShell", "tactic": "Execution", "finding_ref": "finding_id"}
  ],
  "inconsistencies": [
    {
      "finding_id": "id of problematic finding",
      "issue": "Description of the inconsistency or contradiction",
      "severity": "HIGH|MEDIUM|LOW"
    }
  ],
  "correlated_pairs": [
    {"disk_finding_id": "id", "memory_finding_id": "id", "correlation_description": "how they connect"}
  ],
  "confidence_upgrades": [
    {"finding_id": "id", "new_confidence": "CONFIRMED", "reason": "corroborated by memory finding X"}
  ]
}"""


def correlator_node(state: AnalysisState) -> dict[str, Any]:
    """LangGraph node: Correlation Agent."""
    audit = get_audit_logger()
    audit.log_agent_transition(
        agent="correlator",
        action="PHASE_START",
        phase="correlation",
        iteration=state["iteration_count"],
        reasoning=f"Correlating {len(state.get('findings', []))} findings",
    )

    findings = state.get("findings", [])
    if not findings:
        return {
            "correlation_complete": True,
            "current_phase": "verification",
            "iteration_count": state["iteration_count"] + 1,
            "errors": state.get("errors", []) + ["No findings to correlate"],
        }

    findings_summary = json.dumps(findings[:30], default=str)[:6000]

    timeline_events: list[dict] = []
    updated_findings = list(findings)
    inconsistencies: list[dict] = []

    try:
        llm = ChatAnthropic(
            model=config.MODEL,
            api_key=config.ANTHROPIC_API_KEY,
            max_tokens=4096,
        )
        messages = [
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(content=f"All findings to correlate:\n\n{findings_summary}"),
        ]
        response = llm.invoke(messages)
        raw_content = response.content if isinstance(response.content, str) else str(response.content)
        parsed = _parse_response(raw_content)

        # Build timeline events
        for event in parsed.get("attack_timeline", []):
            ts_raw = event.get("timestamp")
            ts = None
            if ts_raw:
                try:
                    ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
                except (ValueError, TypeError):
                    ts = datetime.utcnow()
            if ts is None:
                ts = datetime.utcnow()

            try:
                confidence = ConfidenceLevel[event.get("confidence", "POSSIBLE")]
            except KeyError:
                confidence = ConfidenceLevel.POSSIBLE

            timeline_events.append(AttackTimelineEvent(
                timestamp=ts,
                description=event.get("description", ""),
                finding_refs=event.get("finding_refs", []),
                mitre_tactic=event.get("mitre_tactic"),
                confidence=confidence,
            ).model_dump(mode="json"))

        # Apply confidence upgrades
        for upgrade in parsed.get("confidence_upgrades", []):
            fid = upgrade.get("finding_id")
            new_conf_str = upgrade.get("new_confidence")
            reason = upgrade.get("reason", "")
            for f in updated_findings:
                if f.get("id") == fid:
                    try:
                        f["confidence"] = ConfidenceLevel[new_conf_str].value
                        f["verification_notes"] = f.get("verification_notes", "") + f" | Correlated: {reason}"
                    except (KeyError, TypeError):
                        pass

        inconsistencies = parsed.get("inconsistencies", [])

        audit.log_agent_transition(
            agent="correlator",
            action="CORRELATION_COMPLETE",
            phase="correlation",
            reasoning=(
                f"Timeline: {len(timeline_events)} events, "
                f"inconsistencies: {len(inconsistencies)}, "
                f"narrative: {parsed.get('attack_narrative', '')[:100]}"
            ),
        )
    except Exception as e:
        audit.log_error("correlator", "llm_call", str(e), phase="correlation")

    return {
        "findings": updated_findings,
        "correlation_complete": True,
        "current_phase": "verification",
        "iteration_count": state["iteration_count"] + 1,
        "errors": state.get("errors", []),
        # Store timeline and inconsistencies in findings metadata for verifier
        "_timeline_events": timeline_events,
        "_inconsistencies": inconsistencies,
    }


def _parse_response(raw: str) -> dict:
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        import re
        m = re.search(r"\{.*\}", raw, re.DOTALL)
        if m:
            try:
                return json.loads(m.group())
            except json.JSONDecodeError:
                pass
    return {"attack_timeline": [], "inconsistencies": [], "confidence_upgrades": []}
