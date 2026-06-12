"""Report Agent - generates structured incident report from verified findings."""
from __future__ import annotations
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from sift_hunter.agents.llm import get_llm
from langchain_core.messages import HumanMessage, SystemMessage

from sift_hunter.agents.state import AnalysisState
from sift_hunter.core.audit import get_audit_logger
from sift_hunter.core.models import (
    ConfidenceLevel, ConfidenceSummary, IncidentReport, Finding, AttackTimelineEvent,
)

SYSTEM_PROMPT = """You generate the final incident report narrative sections.

Write:
1. executive_summary: 3-5 sentences. What happened, what was found, impact assessment.
2. self_assessment: What evidence was available, what we might have missed, what we're uncertain about.
3. recommendations: numbered list of concrete next steps for the IR team.

Keep it professional, accurate, and honest. Do not claim certainty where there is none.

Respond ONLY with valid JSON:
{
  "executive_summary": "...",
  "self_assessment": "...",
  "recommendations": ["1. ...", "2. ..."],
  "known_limitations": ["limitation 1", "limitation 2"]
}"""


_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_EXE_RE = re.compile(r"[A-Za-z0-9_\-]+\.exe", re.IGNORECASE)
_CONF_RANK = {"CONFIRMED": 3, "PROBABLE": 2, "POSSIBLE": 1, "UNVERIFIED": 0}


def _finding_signature(f: dict) -> tuple[str, str]:
    """Stable identity for a finding so self-correction re-runs don't duplicate it.

    Keyed on finding type + the most salient IOC (an IP, else an executable name,
    else the title). Distinct findings (e.g. a C2 connection vs a masquerade on the
    same host) keep different IOCs and are NOT merged.
    """
    text = f"{f.get('artifact_path', '')} {f.get('raw_evidence_excerpt', '')} {f.get('description', '')}"
    ip = _IP_RE.search(text)
    if ip:
        ioc = ip.group(0)
    else:
        exe = _EXE_RE.search(text)
        ioc = exe.group(0).lower() if exe else (f.get("title", "")[:40].lower())
    return (str(f.get("type", "")), ioc)


def _dedupe_findings(findings: list[dict]) -> list[dict]:
    """Collapse findings emitted more than once across self-correction loops.

    Keeps the richest copy per signature (highest confidence, then most MITRE
    mappings, then longest description) and preserves first-seen order.
    """
    best: dict[tuple[str, str], dict] = {}
    order: list[tuple[str, str]] = []

    def score(f: dict) -> tuple[int, int, int]:
        return (
            _CONF_RANK.get(f.get("confidence", "UNVERIFIED"), 0),
            len(f.get("mitre_ttps", []) or []),
            len(f.get("description", "") or ""),
        )

    for f in findings:
        sig = _finding_signature(f)
        if sig not in best:
            best[sig] = f
            order.append(sig)
        elif score(f) > score(best[sig]):
            best[sig] = f
    return [best[s] for s in order]


def reporter_node(state: AnalysisState) -> dict[str, Any]:
    """LangGraph node: Report Agent."""
    audit = get_audit_logger()
    audit.log_agent_transition(
        agent="reporter",
        action="PHASE_START",
        phase="reporting",
        iteration=state.get("iteration_count", 0),
        reasoning=f"Generating report for {len(state.get('findings', []))} findings",
    )

    findings = _dedupe_findings(state.get("findings", []))
    timeline_events = state.get("_timeline_events", [])
    corrections = state.get("corrections", [])
    hallucinations = state.get("_hallucinations", [])

    # Build confidence summary
    counts = {cl.value: 0 for cl in ConfidenceLevel}
    for f in findings:
        conf = f.get("confidence", ConfidenceLevel.UNVERIFIED.value)
        counts[conf] = counts.get(conf, 0) + 1
    conf_summary = ConfidenceSummary(
        confirmed=counts.get(ConfidenceLevel.CONFIRMED.value, 0),
        probable=counts.get(ConfidenceLevel.PROBABLE.value, 0),
        possible=counts.get(ConfidenceLevel.POSSIBLE.value, 0),
        unverified=counts.get(ConfidenceLevel.UNVERIFIED.value, 0),
        hallucinations_caught=len(hallucinations),
        self_corrections_applied=len(corrections),
    )

    # Gather MITRE coverage
    mitre_coverage: list[dict] = []
    seen_ttps: set[str] = set()
    for f in findings:
        for ttp in f.get("mitre_ttps", []):
            tid = ttp.get("technique_id", "")
            if tid and tid not in seen_ttps:
                mitre_coverage.append(ttp)
                seen_ttps.add(tid)

    # Build timeline
    timeline: list[dict] = []
    if timeline_events:
        timeline = sorted(timeline_events, key=lambda e: e.get("timestamp", ""))
    else:
        for f in findings:
            ts = f.get("timestamp") or datetime.now(timezone.utc).isoformat()
            timeline.append({
                "timestamp": ts,
                "description": f.get("title", f.get("description", "")[:60]),
                "confidence": f.get("confidence", "UNVERIFIED"),
                "finding_refs": [f.get("id", "")],
            })

    # LLM generates narrative sections
    findings_for_report = json.dumps(findings[:20], default=str)[:4000]
    try:
        llm = get_llm(max_tokens=2000)
        messages = [
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(content=(
                f"Findings ({len(findings)} total):\n{findings_for_report}\n\n"
                f"Confidence: CONFIRMED={conf_summary.confirmed} PROBABLE={conf_summary.probable} "
                f"POSSIBLE={conf_summary.possible}\n"
                f"Self-corrections applied: {conf_summary.self_corrections_applied}\n"
                f"Hallucinations caught: {conf_summary.hallucinations_caught}"
            )),
        ]
        response = llm.invoke(messages)
        raw = response.content if isinstance(response.content, str) else str(response.content)
        narrative = _parse_response(raw)
    except Exception as e:
        audit.log_error("reporter", "llm_call", str(e), phase="reporting")
        narrative = {
            "executive_summary": f"Analysis complete. {len(findings)} findings identified. See detailed findings below.",
            "self_assessment": f"LLM narrative unavailable ({e}). Structured findings are accurate.",
            "recommendations": ["Review all findings manually", "Verify evidence integrity hashes"],
            "known_limitations": ["LLM narrative generation failed"],
        }

    report = IncidentReport(
        summary=narrative.get("executive_summary", ""),
        findings=[Finding(**f) for f in findings if _is_valid_finding(f)],
        attack_timeline=[AttackTimelineEvent(**e) for e in timeline if _is_valid_event(e)],
        mitre_mapping=mitre_coverage,
        confidence_summary=conf_summary,
        self_assessment=narrative.get("self_assessment", ""),
        recommendations=narrative.get("recommendations", []),
        known_limitations=narrative.get("known_limitations", []),
        evidence_paths=state.get("evidence_paths", []),
    )

    audit.log_agent_transition(
        agent="reporter",
        action="REPORT_COMPLETE",
        phase="reporting",
        reasoning=f"Report generated: {report.id}",
    )

    return {
        "report": report.model_dump(mode="json"),
        "current_phase": "complete",
        "iteration_count": state.get("iteration_count", 0) + 1,
        "errors": state.get("errors", []),
    }


def _is_valid_finding(f: dict) -> bool:
    try:
        Finding(**f)
        return True
    except Exception:
        return False


def _is_valid_event(e: dict) -> bool:
    try:
        AttackTimelineEvent(**e)
        return True
    except Exception:
        return False


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
    return {"executive_summary": "", "self_assessment": "", "recommendations": [], "known_limitations": []}
