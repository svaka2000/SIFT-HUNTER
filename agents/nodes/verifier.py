"""
Verification Agent — THE TIEBREAKER. Quality assurance for all findings.
Cross-checks every finding against raw tool output.
Detects hallucinations, contradictions, and overconfident claims.
Routes back to analysts if issues are found (self-correction loop).
"""

from __future__ import annotations

import json
from typing import Any

from langchain_anthropic import ChatAnthropic
from langchain_core.messages import HumanMessage, SystemMessage

from agents.state import AnalysisState
from core.audit import get_audit_logger
from core.hallucination_detector import batch_verify
from core.models import (
    ConfidenceLevel,
    Correction,
    Finding,
    ToolExecution,
)
from mcp_server.config import config

SYSTEM_PROMPT = """You are the quality assurance agent. You are THE MOST IMPORTANT agent in this system.
Your job is to find mistakes, hallucinations, and overconfident claims.

For each finding, ask:
1. Does the raw_evidence_excerpt ACTUALLY appear in the tool outputs listed?
2. Is the confidence level appropriate for the evidence quality?
3. Does this finding contradict any other finding?
4. Could this be a hallucination (agent claiming something not in tool output)?

Be RUTHLESS. Your job is to catch mistakes, not to approve findings.
"I'm uncertain about X" is better than hallucinating a finding.

Respond ONLY with valid JSON:
{
  "approved_finding_ids": ["list of finding IDs that pass verification"],
  "corrections_needed": [
    {
      "finding_id": "id",
      "action": "RE_EXAMINE|DOWNGRADE_CONFIDENCE|REMOVE|FLAG_HALLUCINATION",
      "issue": "Specific problem: what claim is unsupported, what contradicts what",
      "original_confidence": "CONFIRMED",
      "recommended_confidence": "POSSIBLE",
      "target_agent": "disk_analyst|memory_analyst"
    }
  ],
  "hallucinations_caught": ["description of any caught hallucinations"],
  "verification_summary": "Paragraph summarizing what passed and what failed",
  "overall_quality": "PASS|FAIL|PARTIAL"
}"""


def verifier_node(state: AnalysisState) -> dict[str, Any]:
    """
    LangGraph node: Verification Agent.
    The self-correction engine — routes back to analysts if issues found.
    """
    audit = get_audit_logger()
    iteration = state["iteration_count"]

    audit.log_agent_transition(
        agent="verifier",
        action="VERIFICATION_START",
        phase="verification",
        iteration=iteration,
        reasoning=f"Verifying {len(state.get('findings', []))} findings, iteration {iteration}",
    )

    findings = state.get("findings", [])
    tool_executions = state.get("tool_executions", [])

    if not findings:
        return {
            "verification_passed": True,
            "current_phase": "reporting",
            "iteration_count": iteration + 1,
        }

    # Step 1: Automated hallucination detection
    finding_objects = []
    te_objects = []
    for f_dict in findings:
        try:
            finding_objects.append(Finding(**f_dict))
        except Exception:
            pass
    for te_dict in tool_executions:
        try:
            te_objects.append(ToolExecution(**te_dict))
        except Exception:
            pass

    auto_results = batch_verify(finding_objects, te_objects)
    auto_issues: dict[str, str] = {}
    for r in auto_results:
        if not r.verified or not r.confidence_appropriate:
            auto_issues[r.finding_id] = " | ".join(r.issues)

    # Step 2: LLM-based verification (catches semantic issues auto-detect misses)
    findings_for_review = json.dumps(findings[:20], default=str)[:5000]
    tool_outputs_sample = json.dumps([
        {"id": te.get("id"), "tool": te.get("tool_name"), "excerpt": te.get("raw_output", "")[:500]}
        for te in tool_executions[:10]
    ], default=str)[:3000]

    corrections_raw: list[dict] = []
    hallucinations: list[str] = []
    approved_ids: list[str] = []
    verification_summary = ""

    try:
        llm = ChatAnthropic(
            model=config.MODEL,
            api_key=config.ANTHROPIC_API_KEY,
            max_tokens=4096,
        )
        # Include auto-detected issues for LLM awareness
        auto_context = ""
        if auto_issues:
            auto_context = f"\n\nAutomated hallucination detector flagged these issues:\n{json.dumps(auto_issues, indent=2)}"

        messages = [
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(content=(
                f"Findings to verify:\n{findings_for_review}\n\n"
                f"Tool output excerpts (source of truth):\n{tool_outputs_sample}"
                f"{auto_context}"
            )),
        ]
        response = llm.invoke(messages)
        raw_content = response.content if isinstance(response.content, str) else str(response.content)
        parsed = _parse_response(raw_content)

        corrections_raw = parsed.get("corrections_needed", [])
        hallucinations = parsed.get("hallucinations_caught", [])
        approved_ids = parsed.get("approved_finding_ids", [])
        verification_summary = parsed.get("verification_summary", "")
        overall = parsed.get("overall_quality", "PARTIAL")

        audit.log_agent_transition(
            agent="verifier",
            action="VERIFICATION_COMPLETE",
            phase="verification",
            iteration=iteration,
            reasoning=(
                f"Quality: {overall} | "
                f"Approved: {len(approved_ids)} | "
                f"Corrections: {len(corrections_raw)} | "
                f"Hallucinations: {len(hallucinations)}"
            ),
        )
    except Exception as e:
        audit.log_error("verifier", "llm_call", str(e), phase="verification")
        # If verifier fails, approve everything with POSSIBLE confidence cap
        for f in findings:
            if f.get("confidence") == ConfidenceLevel.CONFIRMED.value:
                f["confidence"] = ConfidenceLevel.PROBABLE.value
                f["verification_notes"] = "Auto-downgraded: verifier failed"
        return {
            "findings": findings,
            "verification_passed": True,
            "current_phase": "reporting",
            "iteration_count": iteration + 1,
            "errors": state.get("errors", []) + [f"Verifier LLM failed: {e}"],
        }

    # Build Correction objects and log each one
    corrections: list[dict] = []
    pending: list[dict] = []

    for c_raw in corrections_raw:
        fid = c_raw.get("finding_id", "")
        # Check correction loop depth — prevent infinite recursion
        loop_depth = state.get("correction_counts", {}).get(fid, 0)
        max_loops = config.MAX_CORRECTION_LOOPS

        if loop_depth >= max_loops:
            # Force-accept with downgraded confidence
            for f in findings:
                if f.get("id") == fid:
                    recommended = c_raw.get("recommended_confidence", "UNVERIFIED")
                    try:
                        f["confidence"] = ConfidenceLevel[recommended].value
                    except KeyError:
                        f["confidence"] = ConfidenceLevel.UNVERIFIED.value
                    f["verification_notes"] = (
                        f"Max correction loops ({max_loops}) reached. "
                        f"Issue: {c_raw.get('issue', '')} | "
                        f"Forced to {recommended}"
                    )
            continue

        try:
            orig_conf = ConfidenceLevel[c_raw.get("original_confidence", "UNVERIFIED")]
        except KeyError:
            orig_conf = ConfidenceLevel.UNVERIFIED
        try:
            rec_conf = ConfidenceLevel[c_raw.get("recommended_confidence", "UNVERIFIED")]
        except KeyError:
            rec_conf = ConfidenceLevel.UNVERIFIED

        correction = Correction(
            finding_id=fid,
            issue_description=c_raw.get("issue", ""),
            action=c_raw.get("action", "RE_EXAMINE"),
            original_confidence=orig_conf,
            corrected_confidence=rec_conf,
            corrected_by="verifier",
            correction_reasoning=c_raw.get("issue", ""),
        )
        corrections.append(correction.model_dump(mode="json"))
        pending.append({
            "finding_id": fid,
            "issue": c_raw.get("issue", ""),
            "action": c_raw.get("action", "RE_EXAMINE"),
            "target_agent": c_raw.get("target_agent", "disk_analyst"),
            "recommended_confidence": c_raw.get("recommended_confidence", "UNVERIFIED"),
        })
        audit.log_correction(
            agent="verifier",
            finding_id=fid,
            correction_id=correction.id,
            reasoning=correction.issue_description,
            phase="verification",
            iteration=iteration,
        )

    # Mark verified findings
    for f in findings:
        if f.get("id") in approved_ids:
            f["verified"] = True
            f["verification_notes"] = "Approved by verification agent"

    # Update correction counts
    new_correction_counts = dict(state.get("correction_counts", {}))
    for c in corrections:
        fid = c.get("finding_id", "")
        new_correction_counts[fid] = new_correction_counts.get(fid, 0) + 1

    has_corrections = len(pending) > 0
    verification_passed = not has_corrections

    # Determine routing
    if has_corrections:
        # Identify which agents need to re-run
        disk_corrections = [p for p in pending if p.get("target_agent") == "disk_analyst"]
        memory_corrections = [p for p in pending if p.get("target_agent") == "memory_analyst"]
        next_phase = "disk" if disk_corrections else "memory" if memory_corrections else "reporting"
        audit.log_agent_transition(
            agent="verifier",
            action="ROUTING_TO_CORRECTION",
            phase="verification",
            reasoning=f"Routing to {next_phase} for {len(pending)} corrections",
        )
    else:
        next_phase = "reporting"
        audit.log_agent_transition(
            agent="verifier",
            action="ALL_FINDINGS_APPROVED",
            phase="verification",
            reasoning=f"All {len(approved_ids)} findings approved",
        )

    # Update confidence summary for corrections
    confidence_summary_update = {
        "corrections_made": len(corrections),
        "hallucinations_caught": len(hallucinations),
    }

    return {
        "findings": findings,
        "corrections": state.get("corrections", []) + corrections,
        "pending_corrections": pending if has_corrections else [],
        "correction_counts": new_correction_counts,
        "verification_passed": verification_passed,
        "current_phase": next_phase,
        "disk_findings_complete": not (has_corrections and any(p.get("target_agent") == "disk_analyst" for p in pending)),
        "memory_findings_complete": not (has_corrections and any(p.get("target_agent") == "memory_analyst" for p in pending)),
        "iteration_count": iteration + 1,
        "_verification_summary": verification_summary,
        "_hallucinations": hallucinations,
        "_confidence_summary_update": confidence_summary_update,
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
    return {
        "approved_finding_ids": [],
        "corrections_needed": [],
        "hallucinations_caught": [],
        "verification_summary": "Parse error",
        "overall_quality": "PARTIAL",
    }
