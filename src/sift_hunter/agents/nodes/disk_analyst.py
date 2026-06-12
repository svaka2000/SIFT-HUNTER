"""Disk Forensics Agent - analyzes disk evidence using MCP tools."""
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
from sift_hunter.core.models import ConfidenceLevel, FindingType
from sift_hunter.mcp_server.tools.disk.mft import MFTTool
from sift_hunter.mcp_server.tools.disk.prefetch import PrefetchTool
from sift_hunter.mcp_server.tools.disk.registry import RegistryTool

SYSTEM_PROMPT = """You are a disk forensics specialist analyzing evidence from a potential security incident.

You have been given structured output from forensic tools. Your job:
1. Identify malicious or suspicious artifacts - persistence mechanisms, malware execution, attacker tools
2. For EVERY finding, cite the specific evidence field (column name, registry key, etc.) that supports it
3. Assign appropriate confidence: CONFIRMED (2+ independent sources), PROBABLE (1 strong source), POSSIBLE (circumstantial)
4. Never claim something is present if it's not clearly in the tool output
5. If a pending correction is provided, re-examine ONLY the flagged finding

Respond ONLY with valid JSON:
{
  "findings": [
    {
      "id": "disk_001",
      "type": "PERSISTENCE|EXECUTION|DEFENSE_EVASION|LATERAL_MOVEMENT|COLLECTION|CREDENTIAL_ACCESS",
      "title": "Short descriptive title",
      "description": "Detailed description of the finding and its significance",
      "confidence": "CONFIRMED|PROBABLE|POSSIBLE|UNVERIFIED",
      "raw_evidence_excerpt": "The specific tool output lines that support this finding",
      "artifact_path": "path/key/inode if applicable",
      "mitre_hints": "keywords like 'registry run key' or 'powershell encoded' to guide MITRE mapping",
      "timestamp": "ISO8601 if determinable from evidence"
    }
  ],
  "analyst_notes": "Any observations about evidence quality or gaps"
}"""


def disk_analyst_node(state: AnalysisState) -> dict[str, Any]:
    """LangGraph node: Disk Forensics Agent."""
    audit = get_audit_logger()
    iteration = state.get("iteration_count", 0)
    pending = state.get("pending_corrections", [])
    disk_corrections = [p for p in pending if p.get("target_agent") == "disk_analyst"]

    audit.log_agent_transition(
        agent="disk_analyst",
        action="PHASE_START",
        phase="disk",
        iteration=iteration,
        reasoning=f"Analyzing disk evidence. Corrections: {len(disk_corrections)}",
    )

    evidence_paths = state.get("evidence_paths", [])
    output_dir = os.environ.get("SIFT_OUTPUT_ROOT", "/tmp/sift-output")
    os.makedirs(output_dir, exist_ok=True)

    tool_results: dict[str, Any] = {}
    tool_executions: list[dict] = list(state.get("tool_executions", []))

    # Run available disk tools
    for path in evidence_paths:
        p = Path(path)
        ext = p.suffix.lower()
        name = p.name.lower()

        if ext == ".csv" and "mft" in name:
            tool = MFTTool()
            result = tool.find_suspicious(tool.parse_csv(path))
            tool_results["mft_suspicious"] = result
            te = {"id": str(uuid.uuid4()), "tool_name": "mft_parser", "evidence_path": path,
                  "raw_output": json.dumps(result[:10], default=str)[:1000], "success": True}
            tool_executions.append(te)
            audit.log_tool_call("mft_parser", path, json.dumps(result[:5], default=str)[:500], "disk_analyst")

        elif ext == ".csv" and "prefetch" in name:
            from sift_hunter.mcp_server.tools.output_parser import parse_ez_csv_file
            tool = PrefetchTool()
            result = tool.find_suspicious(parse_ez_csv_file(path))
            tool_results["prefetch_suspicious"] = result
            te = {"id": str(uuid.uuid4()), "tool_name": "prefetch_parser", "evidence_path": path,
                  "raw_output": json.dumps(result[:10], default=str)[:1000], "success": True}
            tool_executions.append(te)

        elif "registry" in name or "reg" in name:
            tool = RegistryTool()
            entries = []
            if ext in (".txt", ".csv"):
                try:
                    with open(path, "r", errors="replace") as f:
                        raw = f.read()
                    tool_results["registry_raw"] = raw[:3000]
                except Exception:
                    pass
            te = {"id": str(uuid.uuid4()), "tool_name": "registry_parser", "evidence_path": path,
                  "raw_output": tool_results.get("registry_raw", "")[:500], "success": True}
            tool_executions.append(te)

        elif ext in (".txt", ".log", ".csv"):
            try:
                with open(path, "r", errors="replace") as f:
                    content = f.read(8000)
                tool_results[p.name] = content
                te = {"id": str(uuid.uuid4()), "tool_name": "file_reader", "evidence_path": path,
                      "raw_output": content[:500], "success": True}
                tool_executions.append(te)
            except Exception as e:
                audit.log_error("disk_analyst", "file_read", str(e), phase="disk")

    # Summarize tool results for LLM
    tool_summary = json.dumps(tool_results, default=str)[:5000]
    correction_context = ""
    if disk_corrections:
        correction_context = f"\n\nPENDING CORRECTIONS TO RE-EXAMINE:\n{json.dumps(disk_corrections, indent=2)}"

    existing_findings = [f for f in state.get("findings", []) if f.get("agent") != "disk_analyst"]
    if disk_corrections:
        existing_findings = [f for f in state.get("findings", [])
                             if f.get("agent") != "disk_analyst" or
                             f.get("id") not in {c["finding_id"] for c in disk_corrections}]

    try:
        llm = get_llm(max_tokens=3000)
        messages = [
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(content=f"Tool outputs:\n{tool_summary}{correction_context}"),
        ]
        response = llm.invoke(messages)
        raw = response.content if isinstance(response.content, str) else str(response.content)
        parsed = _parse_response(raw)

        new_findings = []
        for f in parsed.get("findings", []):
            f["agent"] = "disk_analyst"
            f.setdefault("id", f"disk_{uuid.uuid4().hex[:8]}")
            f.setdefault("verified", False)
            f.setdefault("verification_notes", "")
            # Apply MITRE mapping
            from sift_hunter.mcp_server.tools.enrichment.mitre_attack import map_finding_to_ttps
            f["mitre_ttps"] = map_finding_to_ttps(f)
            new_findings.append(f)
            audit.log_finding(f["id"], "disk_analyst", f.get("type", ""), f.get("confidence", ""), "disk")

    except Exception as e:
        audit.log_error("disk_analyst", "llm_call", str(e), phase="disk")
        new_findings = []

    all_findings = existing_findings + new_findings

    audit.log_agent_transition(
        agent="disk_analyst",
        action="DISK_ANALYSIS_COMPLETE",
        phase="disk",
        reasoning=f"Produced {len(new_findings)} findings",
    )

    return {
        "findings": all_findings,
        "tool_executions": tool_executions,
        "disk_findings_complete": True,
        "disk_raw_outputs": {k: str(v)[:500] for k, v in tool_results.items()},
        "current_phase": "memory",
        "iteration_count": iteration + 1,
        "pending_corrections": [p for p in pending if p.get("target_agent") != "disk_analyst"],
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
