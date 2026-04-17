"""Structured JSONL audit logger with finding chain-trace queries."""
from __future__ import annotations

import json
import threading
from datetime import datetime
from pathlib import Path
from typing import Optional

from sift_hunter.core.models import AuditEntry, Correction, Finding, ToolExecution, VerificationCheck


class AuditLogger:
    """Thread-safe structured JSONL audit logger.

    Every tool call, agent decision, finding, correction, and verification
    is recorded as a JSON line. Supports querying by finding_id to trace
    the full chain of evidence.
    """

    def __init__(self, log_path: str = "/tmp/sift-hunter-audit.jsonl") -> None:
        self._path = Path(log_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def log(self, entry: AuditEntry) -> None:
        """Write an audit entry to the JSONL file."""
        with self._lock:
            with self._path.open("a", encoding="utf-8") as f:
                f.write(entry.model_dump_json() + "\n")
                f.flush()

    def log_tool_call(
        self,
        agent: str,
        tool_execution: ToolExecution,
        phase: Optional[str] = None,
    ) -> None:
        """Convenience: log a tool execution."""
        self.log(AuditEntry(
            agent=agent,
            action="tool_call",
            tool_execution_id=tool_execution.id,
            phase=phase,
            details=f"{tool_execution.tool_name} → exit {tool_execution.exit_code} "
                    f"({tool_execution.output_size_bytes}B output)",
        ))

    def log_finding(self, agent: str, finding: Finding, phase: Optional[str] = None) -> None:
        """Convenience: log a finding being created."""
        self.log(AuditEntry(
            agent=agent,
            action="finding_created",
            finding_id=finding.id,
            phase=phase,
            details=f"[{finding.confidence.value}] {finding.title}",
        ))

    def log_verification(self, check: VerificationCheck) -> None:
        """Convenience: log a verification check."""
        self.log(AuditEntry(
            agent="verifier",
            action="verification_check",
            finding_id=check.finding_id,
            verification_id=check.id,
            phase="verification",
            details=f"{check.check_type}: {'PASS' if check.passed else 'FAIL'} — {check.details[:200]}",
        ))

    def log_correction(self, correction: Correction) -> None:
        """Convenience: log a correction being issued."""
        self.log(AuditEntry(
            agent="verifier",
            action="correction_issued",
            finding_id=correction.finding_id,
            correction_id=correction.id,
            phase="verification",
            details=f"Attempt {correction.attempt_number}/3 → {correction.target_agent}: "
                    f"{correction.issue_description[:200]}",
        ))

    def log_agent_transition(
        self,
        agent: str,
        action: str,
        phase: str,
        iteration: int = 0,
        reasoning: str = "",
    ) -> None:
        """Convenience: log an agent phase transition."""
        self.log(AuditEntry(
            agent=agent,
            action=action,
            phase=phase,
            iteration=iteration,
            details=reasoning,
        ))

    def log_error(
        self,
        agent: str,
        action: str,
        error: str,
        phase: Optional[str] = None,
    ) -> None:
        """Convenience: log an error."""
        self.log(AuditEntry(
            agent=agent,
            action="error",
            phase=phase,
            details=f"{action}: {error[:500]}",
        ))

    def get_all(self) -> list[AuditEntry]:
        """Return all audit entries."""
        entries = []
        if not self._path.exists():
            return entries
        with self._path.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entries.append(AuditEntry(**json.loads(line)))
                    except Exception:
                        pass
        return entries

    def query_finding(self, finding_id: str) -> list[AuditEntry]:
        """Return all audit entries related to a specific finding."""
        return [e for e in self.get_all() if e.finding_id == finding_id]

    def query_agent(self, agent_name: str) -> list[AuditEntry]:
        """Return all audit entries from a specific agent."""
        return [e for e in self.get_all() if e.agent == agent_name]

    def trace_chain(self, finding_id: str) -> dict:
        """Trace the full evidence chain for a finding.

        Returns: tool executions → finding creation → verifications → corrections
        """
        entries = self.query_finding(finding_id)
        return {
            "finding_id": finding_id,
            "tool_calls": [e for e in entries if e.action == "tool_call"],
            "finding_created": [e for e in entries if e.action == "finding_created"],
            "verifications": [e for e in entries if e.action == "verification_check"],
            "corrections": [e for e in entries if e.action == "correction_issued"],
            "errors": [e for e in entries if e.action == "error"],
            "chronological": sorted(entries, key=lambda e: e.timestamp),
        }

    def get_statistics(self) -> dict:
        """Return summary statistics from the audit log."""
        entries = self.get_all()
        stats: dict = {
            "total_entries": len(entries),
            "by_action": {},
            "by_agent": {},
            "findings_created": 0,
            "corrections_issued": 0,
            "tool_calls": 0,
            "errors": 0,
        }
        for e in entries:
            stats["by_action"][e.action] = stats["by_action"].get(e.action, 0) + 1
            stats["by_agent"][e.agent] = stats["by_agent"].get(e.agent, 0) + 1
            if e.action == "finding_created":
                stats["findings_created"] += 1
            elif e.action == "correction_issued":
                stats["corrections_issued"] += 1
            elif e.action == "tool_call":
                stats["tool_calls"] += 1
            elif e.action == "error":
                stats["errors"] += 1
        return stats


_default_logger: Optional[AuditLogger] = None


def get_audit_logger(path: str = "/tmp/sift-hunter-audit.jsonl") -> AuditLogger:
    """Get or create the default audit logger singleton."""
    global _default_logger
    if _default_logger is None:
        _default_logger = AuditLogger(path)
    return _default_logger


def reset_audit_logger(path: Optional[str] = None) -> AuditLogger:
    """Reset the default logger (useful in tests)."""
    global _default_logger
    _default_logger = AuditLogger(path or "/tmp/sift-hunter-audit-test.jsonl")
    return _default_logger
