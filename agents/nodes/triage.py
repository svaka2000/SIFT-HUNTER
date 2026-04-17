"""
Triage Agent — initial assessment and analysis planning.
Ingests evidence, establishes chain of custody, creates prioritized analysis plan.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agents.llm import get_llm
from langchain_core.messages import HumanMessage, SystemMessage

from agents.state import AnalysisState, add_tool_execution
from core.audit import get_audit_logger
from core.evidence_integrity import ingest_evidence, detect_evidence_type
from core.models import EvidenceType, ToolExecution
from mcp_server.config import config

SYSTEM_PROMPT = """You are a senior incident responder performing initial triage on digital evidence.

Your job:
1. Identify the type and quality of each evidence item
2. Hash all evidence for integrity verification
3. Perform rapid assessment: OS type, incident timeframe, any obvious IOCs
4. Create a prioritized analysis plan for disk and memory analysis

Respond ONLY with valid JSON in this exact format:
{
  "os_type": "Windows/Linux/macOS/Unknown",
  "incident_timeframe_estimate": "description or null",
  "obvious_iocs": ["list of any immediately visible IOCs"],
  "disk_evidence": ["list of paths"],
  "memory_evidence": ["list of paths"],
  "other_evidence": ["list of paths"],
  "analysis_priority": ["ordered list: what to analyze first and why"],
  "initial_hypotheses": ["list of attack scenarios to investigate"],
  "recommended_tools": ["list of tools/plugins to prioritize"]
}"""


def triage_node(state: AnalysisState) -> dict[str, Any]:
    """
    LangGraph node: Triage Agent.
    Returns partial state update.
    """
    audit = get_audit_logger()
    audit.log_agent_transition(
        agent="triage",
        action="PHASE_START",
        phase="triage",
        iteration=state["iteration_count"],
        reasoning="Beginning evidence triage and analysis planning",
    )

    # Ingest all evidence files
    evidence_items = []
    evidence_hashes = {}
    tool_executions = []
    errors = []

    # Expand any directories into individual files
    expanded_paths: list[str] = []
    for path in state["evidence_paths"]:
        p = Path(path)
        if p.is_dir():
            expanded_paths.extend(str(f) for f in sorted(p.iterdir()) if f.is_file())
        else:
            expanded_paths.append(path)

    for path in expanded_paths:
        try:
            ev = ingest_evidence(path)
            evidence_items.append(ev.model_dump(mode="json"))
            evidence_hashes[path] = ev.hash_sha256 or ""
            te = ToolExecution(
                tool_name="sha256sum",
                command=f"sha256 {path}",
                raw_output=f"{ev.hash_sha256}  {path}",
                output_hash=ev.hash_sha256[:16] if ev.hash_sha256 else "",
                exit_code=0,
                evidence_paths=[path],
            )
            tool_executions.append(te.model_dump(mode="json"))
            audit.log_tool_execution(
                agent="triage",
                tool_name="ingest_evidence",
                command=f"ingest {path}",
                output_hash=ev.hash_sha256[:16] if ev.hash_sha256 else None,
                phase="triage",
                reasoning=f"Ingested {ev.evidence_type.value}, hash={ev.hash_sha256[:16] if ev.hash_sha256 else 'N/A'}",
            )
        except Exception as e:
            errors.append(f"Failed to ingest {path}: {e}")
            audit.log_error("triage", "ingest_evidence", str(e), phase="triage")

    # Build evidence summary for LLM
    evidence_summary = "\n".join([
        f"- {Path(ev['path']).name} ({ev['evidence_type']}, {ev.get('size_bytes', 0) or 0} bytes, SHA256: {ev.get('hash_sha256', 'N/A')[:16]}...)"
        for ev in evidence_items
    ])

    # Call Claude for triage analysis
    triage_plan = {}
    try:
        llm = get_llm(max_tokens=2048)
        messages = [
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(content=f"Evidence to triage:\n{evidence_summary or 'No evidence provided'}"),
        ]
        response = llm.invoke(messages)
        raw_content = response.content if isinstance(response.content, str) else str(response.content)

        # Extract JSON from response
        try:
            triage_plan = json.loads(raw_content)
        except json.JSONDecodeError:
            import re
            json_match = re.search(r"\{.*\}", raw_content, re.DOTALL)
            if json_match:
                triage_plan = json.loads(json_match.group())
            else:
                triage_plan = {"error": "Could not parse triage response", "raw": raw_content[:500]}

        audit.log_agent_transition(
            agent="triage",
            action="TRIAGE_COMPLETE",
            phase="triage",
            reasoning=f"Plan: {json.dumps(triage_plan)[:200]}",
        )
    except Exception as e:
        errors.append(f"Triage LLM call failed: {e}")
        # Fallback: basic plan from file types
        disk_paths = [p for p in state["evidence_paths"]
                      if detect_evidence_type(p) == EvidenceType.DISK_IMAGE]
        mem_paths = [p for p in state["evidence_paths"]
                     if detect_evidence_type(p) == EvidenceType.MEMORY_CAPTURE]
        triage_plan = {
            "disk_evidence": disk_paths,
            "memory_evidence": mem_paths,
            "analysis_priority": ["disk" if disk_paths else "memory"],
            "initial_hypotheses": ["Compromise of unknown type — full analysis required"],
            "error": str(e),
        }

    return {
        "evidence_items": evidence_items,
        "evidence_hashes": evidence_hashes,
        "triage_plan": triage_plan,
        "current_phase": "disk",
        "tool_executions": state.get("tool_executions", []) + tool_executions,
        "errors": state.get("errors", []) + errors,
        "iteration_count": state["iteration_count"] + 1,
    }
