"""
Disk Forensics Agent — specialist in NTFS/disk artifact analysis.
Executes MFT, Prefetch, Amcache, Registry, USN Journal, and ShellBags analysis.
Every finding cites the specific tool output that supports it.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from agents.llm import get_llm
from langchain_core.messages import HumanMessage, SystemMessage

from agents.state import AnalysisState
from core.audit import get_audit_logger
from core.models import (
    ConfidenceLevel,
    EvidenceType,
    Finding,
    FindingType,
    MITREMapping,
    ToolExecution,
)
from mcp_server.config import config
from mcp_server.tools.disk.mft import MFTTool
from mcp_server.tools.disk.prefetch import PrefetchTool
from mcp_server.tools.disk.amcache import AmcacheTool
from mcp_server.tools.disk.registry import RegistryTool
from mcp_server.tools.disk.usnjrnl import USNJournalTool
from mcp_server.tools.disk.shellbags import ShellbagTool
from mcp_server.tools.enrichment.mitre import map_finding_to_ttps

SYSTEM_PROMPT = """You are a disk forensics specialist. You have received structured output from multiple forensic tools.

Your job:
1. Analyze the tool outputs to identify attacker artifacts
2. For EVERY finding you report, cite the EXACT excerpt from tool output that supports it
3. Assign confidence levels: CONFIRMED (2+ sources), PROBABLE (1 strong source), POSSIBLE (circumstantial), UNVERIFIED
4. If a tool failed or returned no output, note it and adapt — don't invent findings
5. Focus on persistence, execution, anti-forensics, and lateral movement artifacts

Respond ONLY with valid JSON:
{
  "findings": [
    {
      "title": "Short finding title",
      "finding_type": "PERSISTENCE|EXECUTION|DEFENSE_EVASION|LATERAL_MOVEMENT|CREDENTIAL_ACCESS|DISCOVERY|ANOMALY",
      "description": "Detailed description of what was found and its significance",
      "confidence": "CONFIRMED|PROBABLE|POSSIBLE|UNVERIFIED",
      "raw_evidence_excerpt": "EXACT quote from tool output supporting this finding",
      "artifact_path": "path if applicable",
      "mitre_techniques": ["T1547.001", "T1059.001"],
      "tool_source": "Which tool produced this finding"
    }
  ],
  "summary": "One paragraph summary of disk findings",
  "artifacts_examined": ["list of artifacts analyzed"],
  "tool_failures": ["list of tools that failed or returned no output"]
}"""


def disk_analyst_node(state: AnalysisState) -> dict[str, Any]:
    """LangGraph node: Disk Forensics Agent."""
    audit = get_audit_logger()
    audit.log_agent_transition(
        agent="disk_analyst",
        action="PHASE_START",
        phase="disk",
        iteration=state["iteration_count"],
        reasoning="Beginning disk forensics analysis",
    )

    triage_plan = state.get("triage_plan", {})
    disk_paths = triage_plan.get("disk_evidence", [])
    corrections = state.get("pending_corrections", [])

    # If re-running due to corrections, log which findings need re-examination
    if corrections:
        audit.log_agent_transition(
            agent="disk_analyst",
            action="CORRECTION_RE_EXAMINE",
            phase="disk",
            iteration=state["iteration_count"],
            reasoning=f"Re-examining {len(corrections)} flagged findings",
        )

    # Expand any directories in evidence_paths
    all_evidence_files: list[str] = []
    for p in state["evidence_paths"]:
        ep = Path(p)
        if ep.is_dir():
            all_evidence_files.extend(str(f) for f in sorted(ep.iterdir()) if f.is_file())
        else:
            all_evidence_files.append(p)

    # If no disk evidence from triage, scan all evidence paths
    if not disk_paths:
        for path in all_evidence_files:
            if any(ext in path.lower() for ext in [".dd", ".img", ".e01", ".raw", ".vmdk"]):
                disk_paths.append(path)

    tool_outputs: dict[str, Any] = {}
    new_tool_executions: list[dict] = []
    errors: list[str] = []

    # Run each disk forensic tool on disk images
    for evidence_path in disk_paths[:3]:
        _run_disk_tools(evidence_path, tool_outputs, new_tool_executions, errors, audit, state)

    # Also ingest pre-exported tool output files (.csv, .txt) as direct evidence
    text_extensions = {".csv", ".txt", ".log", ".tsv", ".json"}
    for path in all_evidence_files:
        if Path(path).suffix.lower() in text_extensions and path not in disk_paths:
            try:
                content = Path(path).read_text(errors="replace")[:8000]
                tool_outputs[Path(path).name] = content
                te = ToolExecution(
                    tool_name="read_artifact",
                    command=f"cat {path}",
                    raw_output=content,
                    exit_code=0,
                    evidence_paths=[path],
                )
                new_tool_executions.append(te.model_dump(mode="json"))
            except Exception as e:
                errors.append(f"Could not read {path}: {e}")

    # Build context for LLM analysis
    tool_summary = _build_tool_summary(tool_outputs)

    # Ask Claude to analyze and produce structured findings
    new_findings: list[dict] = []
    try:
        llm = get_llm(max_tokens=4096)
        correction_context = ""
        if corrections:
            correction_context = f"\n\nNOTE: The following findings from a previous run were flagged by the verification agent and need correction:\n{json.dumps(corrections, indent=2)}\n\nPlease re-examine and provide corrected findings."

        messages = [
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(content=f"Disk forensic tool outputs:\n\n{tool_summary}{correction_context}"),
        ]
        response = llm.invoke(messages)
        raw_content = response.content if isinstance(response.content, str) else str(response.content)
        parsed = _parse_llm_response(raw_content)
        new_findings = _build_findings_from_llm(parsed, new_tool_executions, "disk_analyst")
        errors.extend(parsed.get("tool_failures", []))

        audit.log_agent_transition(
            agent="disk_analyst",
            action="FINDINGS_PRODUCED",
            phase="disk",
            iteration=state["iteration_count"],
            reasoning=f"Produced {len(new_findings)} disk findings",
        )
    except Exception as e:
        errors.append(f"Disk analyst LLM failed: {e}")
        audit.log_error("disk_analyst", "llm_call", str(e), phase="disk")

    # Merge with existing findings (remove any that are being corrected)
    corrected_ids = {c.get("finding_id") for c in corrections if c.get("finding_id")}
    existing = [f for f in state.get("findings", []) if f.get("id") not in corrected_ids]

    return {
        "findings": existing + new_findings,
        "tool_executions": state.get("tool_executions", []) + new_tool_executions,
        "disk_findings_complete": True,
        "current_phase": "memory",
        "errors": state.get("errors", []) + errors,
        "pending_corrections": [],  # Consumed
        "iteration_count": state["iteration_count"] + 1,
    }


def _run_disk_tools(
    evidence_path: str,
    tool_outputs: dict,
    new_tes: list,
    errors: list,
    audit: Any,
    state: AnalysisState,
) -> None:
    """Run all disk tools against a single evidence path. Populates tool_outputs."""

    def _try(name: str, func: Any, *args: Any, **kwargs: Any) -> None:
        try:
            result = func(*args, **kwargs)
            # Handle (ToolExecution, result) tuples
            if isinstance(result, tuple):
                te, data = result
                new_tes.append(te.model_dump(mode="json") if hasattr(te, "model_dump") else te)
                tool_outputs[name] = data
            else:
                tool_outputs[name] = result
        except Exception as e:
            errors.append(f"{name} failed on {evidence_path}: {e}")
            audit.log_error("disk_analyst", name, str(e), phase="disk")

    # MFT
    mft = MFTTool()
    _try("mft", mft.parse_mft, evidence_path, agent="disk_analyst", phase="disk")
    if "mft" in tool_outputs:
        result = tool_outputs["mft"]
        if hasattr(result, "entries"):
            suspicious = mft.find_suspicious_entries(result)
            tool_outputs["mft_suspicious"] = suspicious

    # Prefetch (check if it's a directory of .pf files)
    pf_dir = _find_prefetch_dir(evidence_path)
    if pf_dir:
        pf = PrefetchTool()
        _try("prefetch", pf.parse_prefetch, pf_dir, agent="disk_analyst", phase="disk")

    # Registry
    for hive_type in ["software", "system"]:
        hive_path = _find_registry_hive(evidence_path, hive_type)
        if hive_path:
            reg = RegistryTool()
            _try(f"registry_{hive_type}", reg.parse_registry_hive, hive_path, hive_type,
                 agent="disk_analyst", phase="disk")

    # Amcache
    amcache_path = _find_amcache(evidence_path)
    if amcache_path:
        am = AmcacheTool()
        _try("amcache", am.parse_amcache, amcache_path, agent="disk_analyst", phase="disk")

    # USN Journal
    usn_path = _find_usn(evidence_path)
    if usn_path:
        usn = USNJournalTool()
        _try("usnjrnl", usn.parse_usn_journal, usn_path, agent="disk_analyst", phase="disk")

    # Shellbags (from NTUSER.DAT)
    ntuser_path = _find_ntuser(evidence_path)
    if ntuser_path:
        sb = ShellbagTool()
        _try("shellbags", sb.parse_shellbags, ntuser_path, agent="disk_analyst", phase="disk")


def _build_tool_summary(tool_outputs: dict) -> str:
    """Serialize tool outputs into a compact string for LLM context."""
    parts: list[str] = []
    for name, data in tool_outputs.items():
        if hasattr(data, "model_dump"):
            serialized = json.dumps(data.model_dump(mode="json"), default=str)[:3000]
        elif isinstance(data, list):
            serialized = json.dumps([
                item.model_dump(mode="json") if hasattr(item, "model_dump") else item
                for item in data[:20]
            ], default=str)[:3000]
        else:
            serialized = str(data)[:3000]
        parts.append(f"=== {name.upper()} ===\n{serialized}")
    return "\n\n".join(parts) if parts else "No disk tool output available."


def _parse_llm_response(raw: str) -> dict:
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
    return {"findings": [], "summary": raw[:200], "tool_failures": []}


def _build_findings_from_llm(
    parsed: dict,
    tool_executions: list[dict],
    agent_source: str,
) -> list[dict]:
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
                ).model_dump(mode="json"))

        finding = Finding(
            finding_type=finding_type,
            title=f.get("title", "Untitled Finding"),
            description=f.get("description", ""),
            confidence=confidence,
            raw_evidence_excerpt=f.get("raw_evidence_excerpt", ""),
            artifact_path=f.get("artifact_path"),
            tool_execution_refs=te_ids[:2],
            mitre_ttps=[MITREMapping(**m) for m in mitre_ttps],
            agent_source=agent_source,
        )
        findings.append(finding.model_dump(mode="json"))
    return findings


def _find_prefetch_dir(base: str) -> str:
    """Try to find a Prefetch directory near the evidence path."""
    candidates = [
        str(Path(base).parent / "Windows" / "Prefetch"),
        str(Path(base).parent / "Prefetch"),
        base if Path(base).is_dir() else "",
    ]
    for c in candidates:
        if c and Path(c).is_dir():
            return c
    return ""


def _find_registry_hive(base: str, hive_type: str) -> str:
    candidates = [
        str(Path(base).parent / "Windows" / "System32" / "config" / hive_type.upper()),
        str(Path(base).parent / hive_type),
        base if hive_type.lower() in base.lower() else "",
    ]
    for c in candidates:
        if c and Path(c).is_file():
            return c
    return ""


def _find_amcache(base: str) -> str:
    candidates = [
        str(Path(base).parent / "Windows" / "AppCompat" / "Programs" / "Amcache.hve"),
        str(Path(base).parent / "Amcache.hve"),
        base if "amcache" in base.lower() else "",
    ]
    for c in candidates:
        if c and Path(c).is_file():
            return c
    return ""


def _find_usn(base: str) -> str:
    candidates = [
        str(Path(base).parent / "$Extend" / "$J"),
        str(Path(base).parent / "UsnJrnl"),
        base if "usn" in base.lower() or "$j" in base.lower() else "",
    ]
    for c in candidates:
        if c and Path(c).is_file():
            return c
    return ""


def _find_ntuser(base: str) -> str:
    candidates = [
        str(Path(base).parent / "NTUSER.DAT"),
        str(Path(base).parent / "Users" / "NTUSER.DAT"),
        base if "ntuser" in base.lower() else "",
    ]
    for c in candidates:
        if c and Path(c).is_file():
            return c
    return ""
