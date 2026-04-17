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
        agent: str,
        tool_name: str,
        command: str,
        output_hash: Optional[str],
        reasoning: str = "",
        finding_id: Optional[str] = None,
        phase: str = "",
        iteration: int = 0,
        metadata: Optional[dict[str, Any]] = None,
    ) -> AuditEntry:
        entry = AuditEntry(
            agent=agent,
            action="TOOL_EXECUTION",
            tool_name=tool_name,
            command=command,
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
        agent: str,
        finding_id: str,
        reasoning: str = "",
        phase: str = "",
        iteration: int = 0,
    ) -> AuditEntry:
        entry = AuditEntry(
            agent=agent,
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
        agent: str,
        finding_id: str,
        correction_id: str,
        reasoning: str = "",
        phase: str = "",
        iteration: int = 0,
    ) -> AuditEntry:
        entry = AuditEntry(
            agent=agent,
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

    def query_by_finding(self, finding_id: str) -> list[AuditEntry]:
        """Return all audit entries related to a specific finding — full evidence chain."""
        entry_ids = self._index.get(finding_id, [])
        return [e for e in self._entries if e.id in entry_ids]

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
        for e in sorted(entries, key=lambda x: x.timestamp):
            lines.append(
                f"[{e.timestamp.isoformat()}] {e.agent} | {e.action}"
                + (f" | Tool: {e.tool_name}" if e.tool_name else "")
                + (f" | Cmd: {e.command[:80]}..." if e.command and len(e.command) > 80 else f" | Cmd: {e.command}" if e.command else "")
                + (f"\n  Reasoning: {e.reasoning}" if e.reasoning else "")
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
