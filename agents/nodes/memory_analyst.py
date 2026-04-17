"""
Memory Forensics Agent — specialist in volatile memory analysis.
Runs Volatility3 plugins for process analysis, network connections, and credentials.
Cross-references with disk findings when available.
"""

from __future__ import annotations

import json
from typing import Any

from langchain_anthropic import ChatAnthropic
from langchain_core.messages import HumanMessage, SystemMessage

from agents.state import AnalysisState
from core.audit import get_audit_logger
from core.models import ConfidenceLevel, Finding, FindingType, MITREMapping
from mcp_server.config import config
from mcp_server.tools.memory.processes import ProcessAnalysisTool
from mcp_server.tools.memory.network import NetworkAnalysisTool
from mcp_server.tools.memory.credentials import CredentialsTool
from mcp_server.tools.memory.volatility import Volatility3Tool
from mcp_server.tools.enrichment.mitre import map_finding_to_ttps

SYSTEM_PROMPT = """You are a memory forensics specialist. You have received structured output from Volatility3 plugins.

Your job:
1. Analyze process lists for suspicious parent-child relationships and masquerading
2. Identify C2 indicators in network connections
3. Flag credential access artifacts
4. Cross-reference with any disk findings provided
5. For EVERY finding, cite the EXACT plugin output supporting it

Respond ONLY with valid JSON:
{
  "findings": [
    {
      "title": "Short finding title",
      "finding_type": "PERSISTENCE|EXECUTION|DEFENSE_EVASION|LATERAL_MOVEMENT|CREDENTIAL_ACCESS|COMMAND_AND_CONTROL|DISCOVERY|ANOMALY",
      "description": "Detailed description with forensic significance",
      "confidence": "CONFIRMED|PROBABLE|POSSIBLE|UNVERIFIED",
      "raw_evidence_excerpt": "EXACT quote from plugin output",
      "pid": null,
      "process_name": null,
      "artifact_path": null,
      "mitre_techniques": ["T1055", "T1021"],
      "tool_source": "vol3_plugin_name"
    }
  ],
  "summary": "One paragraph memory analysis summary",
  "plugins_run": ["list of Volatility3 plugins executed"],
  "cross_references": ["disk finding IDs that correlate with memory findings"]
}"""


def memory_analyst_node(state: AnalysisState) -> dict[str, Any]:
    """LangGraph node: Memory Forensics Agent."""
    audit = get_audit_logger()
    audit.log_agent_transition(
        agent="memory_analyst",
        action="PHASE_START",
        phase="memory",
        iteration=state["iteration_count"],
        reasoning="Beginning memory forensics analysis",
    )

    triage_plan = state.get("triage_plan", {})
    memory_paths = triage_plan.get("memory_evidence", [])
    corrections = state.get("pending_corrections", [])

    if not memory_paths:
        for path in state["evidence_paths"]:
            if any(ext in path.lower() for ext in [".dmp", ".mem", ".vmem", ".lime", ".raw"]):
                memory_paths.append(path)

    if not memory_paths:
        audit.log_agent_transition(
            agent="memory_analyst",
            action="NO_MEMORY_EVIDENCE",
            phase="memory",
            reasoning="No memory captures found — skipping memory analysis",
        )
        return {
            "memory_findings_complete": True,
            "current_phase": "correlation",
            "iteration_count": state["iteration_count"] + 1,
            "errors": state.get("errors", []) + ["No memory evidence provided"],
        }

    tool_outputs: dict[str, Any] = {}
    new_tool_executions: list[dict] = []
    errors: list[str] = []

    process_tool = ProcessAnalysisTool()
    network_tool = NetworkAnalysisTool()
    cred_tool = CredentialsTool()
    vol_tool = Volatility3Tool()

    for mem_path in memory_paths[:2]:
        _run_memory_tools(
            mem_path, tool_outputs, new_tool_executions, errors, audit, state,
            process_tool, network_tool, cred_tool, vol_tool,
        )

    tool_summary = _build_memory_summary(tool_outputs)

    # Include disk findings as context for cross-referencing
    disk_context = ""
    existing_findings = state.get("findings", [])
    if existing_findings:
        disk_context = f"\n\nExisting disk findings to cross-reference:\n{json.dumps(existing_findings[:5], default=str)[:2000]}"

    new_findings: list[dict] = []
    try:
        llm = ChatAnthropic(
            model=config.MODEL,
            api_key=config.ANTHROPIC_API_KEY,
            max_tokens=4096,
        )
        correction_context = ""
        if corrections:
            correction_context = f"\n\nNOTE: These findings need correction:\n{json.dumps(corrections, indent=2)}"

        messages = [
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(content=f"Memory analysis output:\n\n{tool_summary}{disk_context}{correction_context}"),
        ]
        response = llm.invoke(messages)
        raw_content = response.content if isinstance(response.content, str) else str(response.content)
        parsed = _parse_response(raw_content)
        new_findings = _build_memory_findings(parsed, new_tool_executions, "memory_analyst")

        audit.log_agent_transition(
            agent="memory_analyst",
            action="FINDINGS_PRODUCED",
            phase="memory",
            iteration=state["iteration_count"],
            reasoning=f"Produced {len(new_findings)} memory findings",
        )
    except Exception as e:
        errors.append(f"Memory analyst LLM failed: {e}")
        audit.log_error("memory_analyst", "llm_call", str(e), phase="memory")

    corrected_ids = {c.get("finding_id") for c in corrections if c.get("finding_id")}
    existing = [f for f in state.get("findings", []) if f.get("id") not in corrected_ids]

    return {
        "findings": existing + new_findings,
        "tool_executions": state.get("tool_executions", []) + new_tool_executions,
        "memory_findings_complete": True,
        "current_phase": "correlation",
        "errors": state.get("errors", []) + errors,
        "pending_corrections": [],
        "iteration_count": state["iteration_count"] + 1,
    }


def _run_memory_tools(
    mem_path: str,
    tool_outputs: dict,
    new_tes: list,
    errors: list,
    audit: Any,
    state: AnalysisState,
    process_tool: ProcessAnalysisTool,
    network_tool: NetworkAnalysisTool,
    cred_tool: CredentialsTool,
    vol_tool: Volatility3Tool,
) -> None:
    def _try(name: str, func: Any, *args: Any, **kwargs: Any) -> None:
        try:
            result = func(*args, **kwargs)
            if isinstance(result, tuple):
                te, data = result
                new_tes.append(te.model_dump(mode="json") if hasattr(te, "model_dump") else te)
                tool_outputs[name] = data
            else:
                tool_outputs[name] = result
        except Exception as e:
            errors.append(f"{name} on {mem_path}: {e}")

    _try("pslist", process_tool.list_processes, mem_path, agent="memory_analyst", phase="memory")
    _try("cmdline", process_tool.get_process_cmdlines, mem_path, agent="memory_analyst", phase="memory")
    _try("netscan", network_tool.list_connections, mem_path, agent="memory_analyst", phase="memory")
    _try("hashdump", cred_tool.extract_hashes, mem_path, agent="memory_analyst", phase="memory")

    # Run malfind for injection detection
    _try("malfind", vol_tool.run_plugin, mem_path, "windows.malfind.Malfind",
         agent="memory_analyst", phase="memory")


def _build_memory_summary(tool_outputs: dict) -> str:
    parts: list[str] = []
    for name, data in tool_outputs.items():
        if isinstance(data, list):
            serialized = json.dumps([
                item.model_dump(mode="json") if hasattr(item, "model_dump") else item
                for item in data[:20]
            ], default=str)[:3000]
        elif hasattr(data, "model_dump"):
            serialized = json.dumps(data.model_dump(mode="json"), default=str)[:3000]
        else:
            serialized = str(data)[:3000]
        parts.append(f"=== {name.upper()} ===\n{serialized}")
    return "\n\n".join(parts) if parts else "No memory tool output available."


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
    return {"findings": [], "summary": raw[:200]}


def _build_memory_findings(parsed: dict, tool_executions: list[dict], agent_source: str) -> list[dict]:
    te_ids = [te.get("id") for te in tool_executions if te.get("id")]
    findings = []
    for f in parsed.get("findings", []):
        try:
            finding_type = FindingType[f.get("finding_type", "ANOMALY")]
        except KeyError:
            finding_type = FindingType.ANOMALY
        try:
            confidence = ConfidenceLevel[f.get("confidence", "UNVERIFIED")]
        except KeyError:
            confidence = ConfidenceLevel.UNVERIFIED

        mitre_ids = f.get("mitre_techniques", [])
        mitre_ttps = []
        for mid in mitre_ids:
            techniques = map_finding_to_ttps(mid, f.get("title", ""))
            for t in techniques[:1]:
                mitre_ttps.append(MITREMapping(
                    technique_id=t.technique_id,
                    technique_name=t.technique_name,
                    tactic=t.tactic,
                    confidence=confidence,
                ))

        finding = Finding(
            finding_type=finding_type,
            title=f.get("title", "Memory Finding"),
            description=f.get("description", ""),
            confidence=confidence,
            raw_evidence_excerpt=f.get("raw_evidence_excerpt", ""),
            artifact_path=f.get("artifact_path"),
            tool_execution_refs=te_ids[:2],
            mitre_ttps=mitre_ttps,
            agent_source=agent_source,
        )
        findings.append(finding.model_dump(mode="json"))
    return findings
