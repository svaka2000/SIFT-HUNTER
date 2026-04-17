"""Memory Forensics Agent — analyzes memory dumps using Volatility3."""
from __future__ import annotations
import json
import os
import uuid
from pathlib import Path
from typing import Any

from sift_hunter.agents.llm import get_llm
from langchain_core.messages import HumanMessage, SystemMessage

from sift_hunter.agents.state import AnalysisState
from sift_hunter.core.audit import get_audit_logger
from sift_hunter.mcp_server.tools.memory.volatility import VolatilityTool
from sift_hunter.mcp_server.tools.memory.processes import ProcessTool
from sift_hunter.mcp_server.tools.memory.network import NetworkTool

SYSTEM_PROMPT = """You are a memory forensics specialist analyzing volatile evidence.

You have been given Volatility3 plugin output or pre-exported memory artifacts. Your job:
1. Identify suspicious processes (wrong parent, wrong path, masquerading)
2. Find C2 network connections (external IPs, suspicious ports, unexpected processes)
3. Look for process injection (malfind output with PAGE_EXECUTE_READWRITE regions)
4. Identify credential dumping artifacts
5. For EVERY finding, cite the specific row/field from the tool output
6. Assign confidence based on evidence strength

Respond ONLY with valid JSON:
{
  "findings": [
    {
      "id": "mem_001",
      "type": "COMMAND_AND_CONTROL|DEFENSE_EVASION|CREDENTIAL_ACCESS|LATERAL_MOVEMENT|EXECUTION",
      "title": "Short title",
      "description": "What this finding means in the context of the incident",
      "confidence": "CONFIRMED|PROBABLE|POSSIBLE|UNVERIFIED",
      "raw_evidence_excerpt": "The exact tool output row(s) supporting this",
      "artifact_path": "process name, PID, connection string",
      "mitre_hints": "process injection, c2 beacon, credential dumping",
      "timestamp": "ISO8601 or null"
    }
  ],
  "analyst_notes": "observations about memory image quality, missing artifacts"
}"""


def memory_analyst_node(state: AnalysisState) -> dict[str, Any]:
    """LangGraph node: Memory Forensics Agent."""
    audit = get_audit_logger()
    iteration = state.get("iteration_count", 0)
    pending = state.get("pending_corrections", [])
    mem_corrections = [p for p in pending if p.get("target_agent") == "memory_analyst"]

    audit.log_agent_transition(
        agent="memory_analyst",
        action="PHASE_START",
        phase="memory",
        iteration=iteration,
        reasoning=f"Analyzing memory evidence. Corrections: {len(mem_corrections)}",
    )

    evidence_paths = state.get("evidence_paths", [])
    tool_results: dict[str, Any] = {}
    tool_executions = list(state.get("tool_executions", []))

    for path in evidence_paths:
        p = Path(path)
        ext = p.suffix.lower()
        name = p.name.lower()

        if ext in (".dmp", ".mem", ".vmem", ".raw"):
            # Real memory image — run Volatility
            vol = VolatilityTool()
            if vol.is_available():
                proc_result = ProcessTool().list_processes(path)
                net_result = NetworkTool().list_connections(path)
                tool_results["process_list"] = proc_result.get("raw", "")[:2000]
                tool_results["network_connections"] = net_result.get("raw", "")[:2000]
                for plugin, r in [("pslist", proc_result), ("netscan", net_result)]:
                    te = {"id": str(uuid.uuid4()), "tool_name": f"volatility_{plugin}",
                          "evidence_path": path, "raw_output": r.get("raw", "")[:500], "success": r.get("success", False)}
                    tool_executions.append(te)
                    audit.log_tool_call(f"volatility_{plugin}", path, r.get("raw", "")[:300], "memory_analyst")
            else:
                tool_results["note"] = "Volatility3 not installed — using pre-exported artifacts if available"

        elif ext in (".txt", ".csv", ".log"):
            # Pre-exported memory artifacts
            try:
                with open(path, "r", errors="replace") as f:
                    content = f.read(6000)
                tool_results[p.name] = content
                te = {"id": str(uuid.uuid4()), "tool_name": "memory_artifact_reader",
                      "evidence_path": path, "raw_output": content[:500], "success": True}
                tool_executions.append(te)
                audit.log_tool_call("memory_artifact_reader", path, content[:300], "memory_analyst")
            except Exception as e:
                audit.log_error("memory_analyst", "file_read", str(e), phase="memory")

    tool_summary = json.dumps(tool_results, default=str)[:5000]
    correction_context = ""
    if mem_corrections:
        correction_context = f"\n\nPENDING CORRECTIONS:\n{json.dumps(mem_corrections, indent=2)}"

    existing_findings = [f for f in state.get("findings", [])
                         if f.get("agent") != "memory_analyst" or
                         (mem_corrections and f.get("id") not in {c["finding_id"] for c in mem_corrections})]

    try:
        llm = get_llm(max_tokens=3000)
        messages = [
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(content=f"Memory tool outputs:\n{tool_summary}{correction_context}"),
        ]
        response = llm.invoke(messages)
        raw = response.content if isinstance(response.content, str) else str(response.content)
        parsed = _parse_response(raw)

        new_findings = []
        for f in parsed.get("findings", []):
            f["agent"] = "memory_analyst"
            f.setdefault("id", f"mem_{uuid.uuid4().hex[:8]}")
            f.setdefault("verified", False)
            f.setdefault("verification_notes", "")
            from sift_hunter.mcp_server.tools.enrichment.mitre_attack import map_finding_to_ttps
            f["mitre_ttps"] = map_finding_to_ttps(f)
            new_findings.append(f)
            audit.log_finding(f["id"], "memory_analyst", f.get("type", ""), f.get("confidence", ""), "memory")

    except Exception as e:
        audit.log_error("memory_analyst", "llm_call", str(e), phase="memory")
        new_findings = []

    all_findings = existing_findings + new_findings

    audit.log_agent_transition(
        agent="memory_analyst",
        action="MEMORY_ANALYSIS_COMPLETE",
        phase="memory",
        reasoning=f"Produced {len(new_findings)} findings",
    )

    return {
        "findings": all_findings,
        "tool_executions": tool_executions,
        "memory_findings_complete": True,
        "memory_raw_outputs": {k: str(v)[:300] for k, v in tool_results.items()},
        "current_phase": "correlation",
        "iteration_count": iteration + 1,
        "pending_corrections": [p for p in pending if p.get("target_agent") != "memory_analyst"],
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
    return {"findings": [], "analyst_notes": "Parse error"}
