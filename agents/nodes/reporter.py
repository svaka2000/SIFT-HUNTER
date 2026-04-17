"""
Report Agent — generates the final structured incident report.
Aggregates all findings, timeline, MITRE mappings, and self-assessment.
The output is the deliverable judges evaluate.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from langchain_anthropic import ChatAnthropic
from langchain_core.messages import HumanMessage, SystemMessage

from agents.state import AnalysisState
from core.audit import get_audit_logger
from core.models import (
    AttackTimelineEvent,
    ConfidenceLevel,
    ConfidenceSummary,
    Evidence,
    Finding,
    IncidentReport,
    MITREMapping,
    ToolExecution,
)
from mcp_server.config import config
from mcp_server.tools.enrichment.mitre import map_finding_to_ttps
from mcp_server.tools.reporting.markdown_report import generate_markdown_report

SYSTEM_PROMPT = """You are generating the final incident response report.

Write a professional, honest, comprehensive report. Your output will be read by senior IR analysts.

Requirements:
1. Executive summary: 3-5 sentences covering what happened, who was affected, and impact
2. Do NOT overstate confidence — if uncertain, say so
3. Include self-assessment: what you found, what you missed, what you're uncertain about
4. Recommendations must be specific and actionable
5. Limitations must be honest: what evidence was missing, what analysis was incomplete

Respond ONLY with valid JSON:
{
  "title": "Incident Report: [descriptive title]",
  "executive_summary": "3-5 sentence summary",
  "self_assessment": "Honest paragraph about analysis completeness, gaps, and uncertainties",
  "recommendations": [
    "Specific actionable recommendation 1",
    "Specific actionable recommendation 2"
  ],
  "limitations": [
    "Specific limitation 1",
    "Specific limitation 2"
  ],
  "analyst_notes": "Any additional context for follow-on analysts"
}"""


def reporter_node(state: AnalysisState) -> dict[str, Any]:
    """LangGraph node: Report Agent."""
    audit = get_audit_logger()
    audit.log_agent_transition(
        agent="reporter",
        action="PHASE_START",
        phase="reporting",
        iteration=state["iteration_count"],
        reasoning="Generating final incident report",
    )

    findings_raw = state.get("findings", [])
    tool_executions_raw = state.get("tool_executions", [])
    corrections_raw = state.get("corrections", [])
    evidence_items_raw = state.get("evidence_items", [])

    # Deserialize objects
    findings: list[Finding] = []
    for f_dict in findings_raw:
        try:
            findings.append(Finding(**f_dict))
        except Exception:
            pass

    tool_executions: list[ToolExecution] = []
    for te_dict in tool_executions_raw:
        try:
            tool_executions.append(ToolExecution(**te_dict))
        except Exception:
            pass

    evidence_items: list[Evidence] = []
    for ev_dict in evidence_items_raw:
        try:
            evidence_items.append(Evidence(**ev_dict))
        except Exception:
            pass

    # Build confidence summary
    cs = ConfidenceSummary()
    for f in findings:
        cs.total += 1
        if f.confidence == ConfidenceLevel.CONFIRMED:
            cs.confirmed += 1
        elif f.confidence == ConfidenceLevel.PROBABLE:
            cs.probable += 1
        elif f.confidence == ConfidenceLevel.POSSIBLE:
            cs.possible += 1
        else:
            cs.unverified += 1
    cs.corrections_made = len(corrections_raw)
    cs.hallucinations_caught = len(state.get("_hallucinations", []))

    # Build MITRE coverage from all findings
    all_mitre: dict[str, MITREMapping] = {}
    for f in findings:
        for ttp in f.mitre_ttps:
            if ttp.technique_id not in all_mitre:
                all_mitre[ttp.technique_id] = ttp

    # Reconstruct timeline from correlator output
    timeline_raw = state.get("_timeline_events", [])
    timeline: list[AttackTimelineEvent] = []
    for ev_dict in timeline_raw:
        try:
            timeline.append(AttackTimelineEvent(**ev_dict))
        except Exception:
            pass

    # If no timeline from correlator, build from finding timestamps
    if not timeline:
        for f in sorted(findings, key=lambda x: x.created_at):
            timeline.append(AttackTimelineEvent(
                timestamp=f.created_at,
                description=f.title,
                finding_refs=[f.id],
                confidence=f.confidence,
                mitre_tactic=f.mitre_ttps[0].tactic if f.mitre_ttps else None,
            ))

    # LLM writes executive summary, self-assessment, recommendations
    findings_summary = json.dumps([
        {"title": f.title, "type": f.finding_type.value, "confidence": f.confidence.value,
         "description": f.description[:200]}
        for f in findings[:15]
    ], default=str)[:4000]

    report_text: dict = {}
    try:
        llm = ChatAnthropic(
            model=config.MODEL,
            api_key=config.ANTHROPIC_API_KEY,
            max_tokens=2048,
        )
        messages = [
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(content=(
                f"Findings ({len(findings)} total, "
                f"{cs.confirmed} confirmed, {cs.probable} probable, "
                f"{cs.possible} possible, {cs.unverified} unverified):\n\n"
                f"{findings_summary}\n\n"
                f"Self-corrections applied: {cs.corrections_made}\n"
                f"Hallucinations caught: {cs.hallucinations_caught}\n"
                f"Tool failures: {len(state.get('tool_failures', []))}"
            )),
        ]
        response = llm.invoke(messages)
        raw_content = response.content if isinstance(response.content, str) else str(response.content)
        report_text = _parse_response(raw_content)
    except Exception as e:
        audit.log_error("reporter", "llm_call", str(e), phase="reporting")
        report_text = {
            "title": "SIFT-HUNTER Incident Analysis Report",
            "executive_summary": f"Analysis completed with {len(findings)} findings. See detailed findings below.",
            "self_assessment": f"Analysis ran with {len(state.get('errors', []))} errors. {cs.corrections_made} self-corrections applied.",
            "recommendations": ["Conduct manual review of all PROBABLE and CONFIRMED findings."],
            "limitations": [f"LLM report generation failed: {e}"],
        }

    # Build the final IncidentReport object
    report = IncidentReport(
        title=report_text.get("title", "SIFT-HUNTER Incident Report"),
        executive_summary=report_text.get("executive_summary", ""),
        findings=findings,
        attack_timeline=timeline,
        mitre_mapping=list(all_mitre.values()),
        confidence_summary=cs,
        evidence_items=evidence_items,
        tool_executions=tool_executions,
        self_assessment=report_text.get("self_assessment", ""),
        recommendations=report_text.get("recommendations", []),
        limitations=report_text.get("limitations", []),
        analyst_notes=report_text.get("analyst_notes", ""),
    )

    # Generate Markdown report to file
    output_path = f"{config.OUTPUT_ROOT}/sift-hunter-report-{report.id[:8]}.md"
    try:
        config.ensure_output_dir()
        generate_markdown_report(report, output_path)
        audit.log_agent_transition(
            agent="reporter",
            action="REPORT_GENERATED",
            phase="reporting",
            reasoning=f"Report written to {output_path}",
        )
    except Exception as e:
        audit.log_error("reporter", "markdown_report", str(e), phase="reporting")

    return {
        "report": report.model_dump(mode="json"),
        "current_phase": "complete",
        "iteration_count": state["iteration_count"] + 1,
        "_report_path": output_path,
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
    return {}
