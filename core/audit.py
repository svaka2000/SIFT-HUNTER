"""
Structured JSON audit logger — every agent action, tool call, and finding is recorded.
Supports querying by finding_id to trace the full chain of evidence.
"""

from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from core.models import AuditEntry


class AuditLogger:
    """Thread-safe structured JSON audit logger."""

    def __init__(self, log_path: str = "/tmp/sift-hunter-audit.jsonl"):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._entries: list[AuditEntry] = []
        self._index: dict[str, list[str]] = {}  # finding_id -> list[entry_id]

    def _write(self, entry: AuditEntry) -> None:
        with self._lock:
            self._entries.append(entry)
            if entry.finding_id:
                self._index.setdefault(entry.finding_id, []).append(entry.id)
            with open(self.log_path, "a") as f:
                f.write(entry.model_dump_json() + "\n")

    def log_tool_execution(
        self,
        agent_or_te: Any = None,
        tool_name: Optional[str] = None,
        command: Optional[str] = None,
        output_hash: Optional[str] = None,
        reasoning: str = "",
        finding_id: Optional[str] = None,
        phase: str = "",
        iteration: int = 0,
        metadata: Optional[dict[str, Any]] = None,
        agent: Optional[str] = None,
    ) -> AuditEntry:
        # Object-form: log_tool_execution(te_object, agent="...", phase="...")
        if agent_or_te is not None and hasattr(agent_or_te, "tool_name"):
            te = agent_or_te
            entry = AuditEntry(
                agent=agent or "",
                action="TOOL_EXECUTION",
                tool_name=te.tool_name,
                command=getattr(te, "command", ""),
                output_hash=getattr(te, "output_hash", None),
                finding_id=getattr(te, "id", None),
                phase=phase,
                iteration=iteration,
                metadata=metadata or {},
            )
        else:
            entry = AuditEntry(
                agent=agent or (agent_or_te if isinstance(agent_or_te, str) else ""),
                action="TOOL_EXECUTION",
                tool_name=tool_name or "",
                command=command or "",
                output_hash=output_hash,
                finding_id=finding_id,
                reasoning=reasoning,
                phase=phase,
                iteration=iteration,
                metadata=metadata or {},
            )
        self._write(entry)
        return entry

    def log_finding(
        self,
        agent_or_finding: Any = None,
        finding_id: Optional[str] = None,
        reasoning: str = "",
        phase: str = "",
        iteration: int = 0,
        agent: Optional[str] = None,
    ) -> AuditEntry:
        # Object-form: log_finding(finding_object, agent="...", phase="...")
        if agent_or_finding is not None and hasattr(agent_or_finding, "model_dump") and not isinstance(agent_or_finding, str):
            f = agent_or_finding
            entry = AuditEntry(
                agent=agent or "",
                action="FINDING_CREATED",
                finding_id=getattr(f, "id", None),
                reasoning=getattr(f, "description", ""),
                phase=phase,
                iteration=iteration,
            )
        else:
            entry = AuditEntry(
                agent=agent or (agent_or_finding if isinstance(agent_or_finding, str) else ""),
                action="FINDING_CREATED",
                finding_id=finding_id,
                reasoning=reasoning,
                phase=phase,
                iteration=iteration,
            )
        self._write(entry)
        return entry

    def log_correction(
        self,
        agent_or_correction: Any = None,
        finding_id: Optional[str] = None,
        correction_id: Optional[str] = None,
        reasoning: str = "",
        phase: str = "",
        iteration: int = 0,
        agent: Optional[str] = None,
    ) -> AuditEntry:
        # Object-form: log_correction(correction_object, agent="...", phase="...")
        if agent_or_correction is not None and hasattr(agent_or_correction, "model_dump") and not isinstance(agent_or_correction, str):
            c = agent_or_correction
            issue = getattr(c, "issue", "") or getattr(c, "issue_description", "")
            entry = AuditEntry(
                agent=agent or "",
                action="correction",
                finding_id=getattr(c, "finding_id", None),
                correction_id=getattr(c, "id", None),
                reasoning=getattr(c, "correction_reasoning", issue),
                phase=phase,
                iteration=iteration,
                metadata={"issue": issue, "correction_action": getattr(c, "action", "")},
            )
        else:
            entry = AuditEntry(
                agent=agent or (agent_or_correction if isinstance(agent_or_correction, str) else ""),
                action="CORRECTION_APPLIED",
                finding_id=finding_id,
                correction_id=correction_id,
                reasoning=reasoning,
                phase=phase,
                iteration=iteration,
            )
        self._write(entry)
        return entry

    def log_agent_transition(
        self,
        agent: str,
        action: str,
        reasoning: str = "",
        phase: str = "",
        iteration: int = 0,
        metadata: Optional[dict[str, Any]] = None,
    ) -> AuditEntry:
        entry = AuditEntry(
            agent=agent,
            action=action,
            reasoning=reasoning,
            phase=phase,
            iteration=iteration,
            metadata=metadata or {},
        )
        self._write(entry)
        return entry

    def log_error(
        self,
        agent: str,
        tool: str,
        error: str,
        phase: str = "",
        iteration: int = 0,
    ) -> AuditEntry:
        entry = AuditEntry(
            agent=agent,
            action="ERROR",
            tool_name=tool,
            reasoning=error,
            phase=phase,
            iteration=iteration,
            metadata={"error": error},
        )
        self._write(entry)
        return entry

    def log_warning(self, message: str, agent: str = "system") -> AuditEntry:
        entry = AuditEntry(agent=agent, action="WARNING", reasoning=message)
        self._write(entry)
        return entry

    def query_by_finding(self, finding_id: str) -> list[dict[str, Any]]:
        """Return all audit entries related to a specific finding — full evidence chain."""
        entry_ids = self._index.get(finding_id, set())
        results = []
        for e in self._entries:
            if e.id in entry_ids:
                d = e.model_dump(mode="json")
                # Promote metadata keys to top-level for convenience
                d.update(e.metadata)
                results.append(d)
        return results

    def query_by_agent(self, agent_name: str) -> list[AuditEntry]:
        return [e for e in self._entries if e.agent == agent_name]

    def query_by_phase(self, phase: str) -> list[AuditEntry]:
        return [e for e in self._entries if e.phase == phase]

    def get_all(self) -> list[AuditEntry]:
        return list(self._entries)

    def export_json(self) -> list[dict[str, Any]]:
        return [e.model_dump(mode="json") for e in self._entries]

    def print_finding_chain(self, finding_id: str) -> str:
        """Human-readable evidence chain for a finding — for demo and audit commands."""
        entries = self.query_by_finding(finding_id)
        if not entries:
            return f"No audit trail found for finding {finding_id}"
        lines = [f"=== Evidence Chain for Finding {finding_id} ==="]
        for e in sorted(entries, key=lambda x: x.get("timestamp", "") if isinstance(x, dict) else x.timestamp):
            ts = e.get("timestamp", "") if isinstance(e, dict) else e.timestamp.isoformat()
            ag = e.get("agent", "") if isinstance(e, dict) else e.agent
            ac = e.get("action", "") if isinstance(e, dict) else e.action
            tn = e.get("tool_name", "") if isinstance(e, dict) else e.tool_name
            cm = e.get("command", "") if isinstance(e, dict) else e.command
            rs = e.get("reasoning", "") if isinstance(e, dict) else e.reasoning
            lines.append(
                f"[{ts}] {ag} | {ac}"
                + (f" | Tool: {tn}" if tn else "")
                + (f" | Cmd: {cm[:80]}..." if cm and len(cm) > 80 else f" | Cmd: {cm}" if cm else "")
                + (f"\n  Reasoning: {rs}" if rs else "")
            )
        return "\n".join(lines)


def hash_output(raw_output: str) -> str:
    return hashlib.sha256(raw_output.encode()).hexdigest()[:16]


# Module-level singleton — imported throughout the codebase
_default_logger: Optional[AuditLogger] = None


def get_audit_logger(log_path: Optional[str] = None) -> AuditLogger:
    global _default_logger
    if _default_logger is None:
        _default_logger = AuditLogger(log_path or "/tmp/sift-hunter-audit.jsonl")
    return _default_logger


def reset_audit_logger(log_path: Optional[str] = None) -> AuditLogger:
    global _default_logger
    _default_logger = AuditLogger(log_path or "/tmp/sift-hunter-audit.jsonl")
    return _default_logger
