"""Verification Agent - self-correction engine. THE TIEBREAKER."""
from __future__ import annotations
import json
from typing import Any

from sift_hunter.agents.llm import get_llm
from langchain_core.messages import HumanMessage, SystemMessage

from sift_hunter.agents.state import AnalysisState
from sift_hunter.core.audit import get_audit_logger
from sift_hunter.core.hallucination_detector import batch_verify
from sift_hunter.core.models import ConfidenceLevel, Correction, Finding, ToolExecution

SYSTEM_PROMPT = """You are the quality assurance agent. You are THE MOST IMPORTANT agent in this system.
Find mistakes, hallucinations, and overconfident claims.

For each finding:
1. Does raw_evidence_excerpt ACTUALLY appear in the tool outputs listed?
2. Is the confidence level appropriate for the evidence quality?
3. Does this finding contradict any other finding?
4. Could this be a hallucination (agent claiming something not in tool output)?

Be RUTHLESS. Catch mistakes, not approve findings.

Respond ONLY with valid JSON:
{
  "approved_finding_ids": ["list of IDs that pass"],
  "corrections_needed": [
    {
      "finding_id": "id",
      "action": "RE_EXAMINE|DOWNGRADE_CONFIDENCE|REMOVE|FLAG_HALLUCINATION",
      "issue": "specific problem",
      "original_confidence": "CONFIRMED",
      "recommended_confidence": "POSSIBLE",
      "target_agent": "disk_analyst|memory_analyst"
    }
  ],
  "hallucinations_caught": ["description of caught hallucinations"],
  "verification_summary": "paragraph summarizing pass/fail",
  "overall_quality": "PASS|FAIL|PARTIAL"
}"""

MAX_CORRECTION_LOOPS = int(__import__("os").environ.get("SIFT_MAX_CORRECTION_LOOPS", "3"))


def verifier_node(state: AnalysisState) -> dict[str, Any]:
    """LangGraph node: Verification Agent - self-correction engine."""
    audit = get_audit_logger()
    iteration = state.get("iteration_count", 0)
    max_iterations = state.get("max_iterations", 20)

    audit.log_agent_transition(
        agent="verifier",
        action="VERIFICATION_START",
        phase="verification",
        iteration=iteration,
        reasoning=f"Verifying {len(state.get('findings', []))} findings",
    )

    findings = state.get("findings", [])
    tool_executions = state.get("tool_executions", [])

    if not findings:
        return {
            "verification_passed": True,
            "current_phase": "reporting",
            "iteration_count": iteration + 1,
        }

    # Automated hallucination detection
    finding_objects = []
    te_objects = []
    for f in findings:
        try:
            finding_objects.append(Finding(**f))
        except Exception:
            pass
    for te in tool_executions:
        try:
            te_objects.append(ToolExecution(**te))
        except Exception:
            pass

    auto_results = batch_verify(finding_objects, te_objects)
    auto_issues: dict[str, str] = {}
    for r in auto_results:
        if not r.verified or not r.confidence_appropriate:
            auto_issues[r.finding_id] = " | ".join(r.issues)

    # LLM-based verification
    findings_for_review = json.dumps(findings[:20], default=str)[:5000]
    tool_outputs_sample = json.dumps([
        {"tool": te.get("tool_name"), "excerpt": te.get("raw_output", "")[:400]}
        for te in tool_executions[:10]
    ], default=str)[:2500]

    corrections_raw: list[dict] = []
    hallucinations: list[str] = []
    approved_ids: list[str] = []

    try:
        llm = get_llm(max_tokens=3000)
        auto_context = ""
        if auto_issues:
            auto_context = f"\n\nAuto-detector issues:\n{json.dumps(auto_issues, indent=2)}"
        messages = [
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(content=(
                f"Findings:\n{findings_for_review}\n\n"
                f"Tool outputs (source of truth):\n{tool_outputs_sample}"
                f"{auto_context}"
            )),
        ]
        response = llm.invoke(messages)
        raw = response.content if isinstance(response.content, str) else str(response.content)
        parsed = _parse_response(raw)
        corrections_raw = parsed.get("corrections_needed", [])
        hallucinations = parsed.get("hallucinations_caught", [])
        approved_ids = parsed.get("approved_finding_ids", [])
        overall = parsed.get("overall_quality", "PARTIAL")

        audit.log_agent_transition(
            agent="verifier",
            action="VERIFICATION_COMPLETE",
            phase="verification",
            iteration=iteration,
            reasoning=f"Quality: {overall} | Approved: {len(approved_ids)} | Corrections: {len(corrections_raw)}",
        )
    except Exception as e:
        audit.log_error("verifier", "llm_call", str(e), phase="verification")
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

    # Build corrections with loop depth guard
    corrections: list[dict] = []
    pending: list[dict] = []
    correction_counts = dict(state.get("correction_counts", {}))

    for c_raw in corrections_raw:
        fid = c_raw.get("finding_id", "")
        loop_depth = correction_counts.get(fid, 0)
        if loop_depth >= MAX_CORRECTION_LOOPS:
            for f in findings:
                if f.get("id") == fid:
                    recommended = c_raw.get("recommended_confidence", "UNVERIFIED")
                    try:
                        f["confidence"] = ConfidenceLevel[recommended].value
                    except KeyError:
                        f["confidence"] = ConfidenceLevel.UNVERIFIED.value
                    f["verification_notes"] = (
                        f"Max correction loops ({MAX_CORRECTION_LOOPS}) reached. "
                        f"Issue: {c_raw.get('issue', '')} | Forced to {recommended}"
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
        audit.log_correction("verifier", fid, correction.id, correction.issue_description, "verification", iteration)
        correction_counts[fid] = correction_counts.get(fid, 0) + 1

    # Mark verified findings
    for f in findings:
        if f.get("id") in approved_ids:
            f["verified"] = True
            f["verification_notes"] = "Approved by verification agent"

    # Iteration cap safety valve
    if iteration >= int(max_iterations * 0.6) and pending:
        for f in findings:
            if f.get("confidence") == ConfidenceLevel.CONFIRMED.value:
                f["confidence"] = ConfidenceLevel.PROBABLE.value
            if not f.get("verified"):
                f["verified"] = True
                f["verification_notes"] = (f.get("verification_notes", "") + " [accepted at iteration cap]").strip()
        pending = []
        audit.log_agent_transition(
            agent="verifier", action="FORCED_ACCEPT", phase="verification",
            reasoning=f"Iteration cap reached ({iteration}/{max_iterations})",
        )

    has_corrections = len(pending) > 0
    verification_passed = not has_corrections

    if has_corrections:
        disk_c = [p for p in pending if p.get("target_agent") == "disk_analyst"]
        next_phase = "disk" if disk_c else "memory"
    else:
        next_phase = "reporting"

    return {
        "findings": findings,
        "corrections": state.get("corrections", []) + corrections,
        "pending_corrections": pending if has_corrections else [],
        "correction_counts": correction_counts,
        "verification_passed": verification_passed,
        "current_phase": next_phase,
        "disk_findings_complete": not (has_corrections and any(p.get("target_agent") == "disk_analyst" for p in pending)),
        "memory_findings_complete": not (has_corrections and any(p.get("target_agent") == "memory_analyst" for p in pending)),
        "iteration_count": iteration + 1,
        "_verification_summary": parsed.get("verification_summary", "") if "parsed" in dir() else "",
        "_hallucinations": hallucinations,
        "_confidence_summary_update": {
            "corrections_made": len(corrections),
            "hallucinations_caught": len(hallucinations),
        },
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
    return {
        "approved_finding_ids": [],
        "corrections_needed": [],
        "hallucinations_caught": [],
        "verification_summary": "Parse error",
        "overall_quality": "PARTIAL",
    }
