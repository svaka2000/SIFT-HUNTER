"""Triage Agent — initial evidence assessment and analysis planning."""
from __future__ import annotations
import json
import os
from pathlib import Path
from typing import Any

from sift_hunter.agents.llm import get_llm
from langchain_core.messages import HumanMessage, SystemMessage

from sift_hunter.agents.state import AnalysisState
from sift_hunter.core.audit import get_audit_logger
from sift_hunter.core.evidence_integrity import hash_file, detect_evidence_type, ChainOfCustody

SYSTEM_PROMPT = """You are a senior incident responder performing initial triage.

Your tasks:
1. Identify the evidence types available (disk images, memory captures, logs, exported artifacts)
2. Assess the scope: OS type, timeframe, obvious IOCs visible from filenames/paths
3. Create a prioritized analysis plan listing which tools to run and in what order
4. Note any red flags visible before deep analysis begins

Respond ONLY with valid JSON:
{
  "triage_summary": "2-3 sentence overview of what evidence we have and initial impressions",
  "os_type": "Windows|Linux|macOS|Unknown",
  "timeframe_estimate": "rough timeframe or null",
  "initial_iocs": ["any IOCs visible from filenames/paths alone"],
  "analysis_plan": [
    {"step": 1, "agent": "disk_analyst|memory_analyst", "tool": "tool_name", "priority": "HIGH|MEDIUM|LOW", "rationale": "why this first"}
  ],
  "risk_level": "CRITICAL|HIGH|MEDIUM|LOW"
}"""


def triage_node(state: AnalysisState) -> dict[str, Any]:
    """LangGraph node: Triage Agent."""
    audit = get_audit_logger()
    audit.log_agent_transition(
        agent="triage",
        action="PHASE_START",
        phase="triage",
        iteration=state.get("iteration_count", 0),
        reasoning=f"Triaging {len(state.get('evidence_paths', []))} evidence items",
    )

    evidence_paths = state.get("evidence_paths", [])
    custody = ChainOfCustody()
    hashes: dict[str, str] = {}
    types: dict[str, str] = {}

    for path in evidence_paths:
        p = Path(path)
        if p.exists():
            h = hash_file(str(p))
            hashes[path] = h
            types[path] = detect_evidence_type(str(p))
            custody.record_access(str(p))

    evidence_desc = "\n".join([
        f"- {Path(p).name} ({types.get(p, 'unknown')}) SHA256={hashes.get(p, 'n/a')}"
        for p in evidence_paths
    ])

    try:
        llm = get_llm(max_tokens=1024)
        messages = [
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(content=f"Evidence available:\n{evidence_desc}\n\nEvidence paths:\n{chr(10).join(evidence_paths)}"),
        ]
        response = llm.invoke(messages)
        raw = response.content if isinstance(response.content, str) else str(response.content)
        parsed = _parse_response(raw)
    except Exception as e:
        audit.log_error("triage", "llm_call", str(e), phase="triage")
        parsed = {
            "triage_summary": f"Triage LLM unavailable: {e}. Proceeding with all evidence.",
            "os_type": "Unknown",
            "analysis_plan": [
                {"step": 1, "agent": "disk_analyst", "tool": "mft_parser", "priority": "HIGH", "rationale": "auto"},
                {"step": 2, "agent": "memory_analyst", "tool": "volatility", "priority": "HIGH", "rationale": "auto"},
            ],
            "risk_level": "UNKNOWN",
            "initial_iocs": [],
        }

    audit.log_agent_transition(
        agent="triage",
        action="TRIAGE_COMPLETE",
        phase="triage",
        reasoning=f"Risk={parsed.get('risk_level')} OS={parsed.get('os_type')} Plan={len(parsed.get('analysis_plan', []))} steps",
    )

    return {
        "evidence_hashes": hashes,
        "evidence_types": types,
        "triage_complete": True,
        "triage_summary": parsed.get("triage_summary", ""),
        "analysis_plan": parsed.get("analysis_plan", []),
        "current_phase": "disk",
        "iteration_count": state.get("iteration_count", 0) + 1,
        "errors": state.get("errors", []),
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
    return {"triage_summary": "Parse error", "analysis_plan": [], "initial_iocs": [], "risk_level": "UNKNOWN"}
