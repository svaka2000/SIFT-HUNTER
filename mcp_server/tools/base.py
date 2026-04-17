"""
BaseTool — all forensic tool wrappers inherit from this.
Provides: audit logging, path validation, structured output, error handling, timing, output hashing.
"""

from __future__ import annotations

import hashlib
import subprocess
import time
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from core.audit import get_audit_logger
from core.models import ToolExecution
from mcp_server.config import config
from mcp_server.security import check_command_safety
from mcp_server.validators.path_validator import SecurityError, validate_path


class ToolError(Exception):
    """Raised when a forensic tool fails in a non-recoverable way."""
    pass


class BaseTool(ABC):
    """
    Abstract base class for all SIFT-HUNTER forensic tool wrappers.
    Subclasses implement _build_command() and _parse_output().
    """

    tool_name: str = "base"

    def __init__(self, allowed_roots: Optional[list[str]] = None):
        self._allowed_roots = allowed_roots or config.EVIDENCE_ROOTS
        self._audit = get_audit_logger()

    def run(
        self,
        evidence_path: str,
        agent: str = "system",
        phase: str = "",
        iteration: int = 0,
        extra_args: Optional[dict[str, Any]] = None,
    ) -> ToolExecution:
        """
        Execute the forensic tool against evidence_path.
        Returns a ToolExecution with structured output and full audit trail.
        """
        # 1. Validate path before touching anything
        try:
            validated = validate_path(evidence_path, self._allowed_roots)
        except SecurityError as e:
            te = ToolExecution(
                tool_name=self.tool_name,
                command=f"BLOCKED: {evidence_path}",
                raw_output="",
                exit_code=-1,
                error_message=str(e),
                evidence_paths=[evidence_path],
            )
            self._audit.log_error(agent, self.tool_name, str(e), phase, iteration)
            return te

        # 2. Build command
        cmd = self._build_command(validated, extra_args or {})

        # 3. Check command safety (second layer after validate_path)
        try:
            check_command_safety(cmd)
        except SecurityError as e:
            te = ToolExecution(
                tool_name=self.tool_name,
                command=cmd,
                raw_output="",
                exit_code=-1,
                error_message=f"Security check failed: {e}",
                evidence_paths=[validated],
            )
            self._audit.log_error(agent, self.tool_name, str(e), phase, iteration)
            return te

        # 4. Execute
        started = datetime.utcnow()
        t0 = time.monotonic()
        try:
            result = subprocess.run(
                cmd,
                shell=False,
                capture_output=True,
                text=True,
                timeout=300,
                cwd=str(Path(validated).parent) if Path(validated).is_file() else validated,
            )
            raw_output = result.stdout + result.stderr
            exit_code = result.returncode
        except subprocess.TimeoutExpired:
            raw_output = ""
            exit_code = -1
        except FileNotFoundError as e:
            raw_output = f"Tool binary not found: {e}"
            exit_code = -1
        except Exception as e:
            raw_output = f"Unexpected error: {e}"
            exit_code = -1

        duration_ms = (time.monotonic() - t0) * 1000

        # 5. Truncate if too large
        if len(raw_output) > config.MAX_OUTPUT_SIZE:
            raw_output = raw_output[: config.MAX_OUTPUT_SIZE] + "\n[TRUNCATED]"

        output_hash = hashlib.sha256(raw_output.encode()).hexdigest()[:16]

        te = ToolExecution(
            tool_name=self.tool_name,
            command=cmd if isinstance(cmd, str) else " ".join(cmd),
            raw_output=raw_output,
            output_hash=output_hash,
            exit_code=exit_code,
            error_message=raw_output[:500] if exit_code != 0 else None,
            started_at=started,
            duration_ms=duration_ms,
            evidence_paths=[validated],
        )

        self._audit.log_tool_execution(
            agent=agent,
            tool_name=self.tool_name,
            command=te.command,
            output_hash=output_hash,
            phase=phase,
            iteration=iteration,
        )

        return te

    @abstractmethod
    def _build_command(self, evidence_path: str, args: dict[str, Any]) -> list[str]:
        """Return the command as a list of strings (never a shell string)."""
        ...

    def _parse_output(self, raw: str) -> Any:
        """Optional: parse raw output into a structured result. Default returns raw string."""
        return raw

    def _run_cmd(self, cmd: list[str], cwd: Optional[str] = None) -> tuple[str, int]:
        """Low-level subprocess runner with safety check. Used by tool implementations."""
        check_command_safety(" ".join(cmd))
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=300, cwd=cwd)
            return r.stdout + r.stderr, r.returncode
        except subprocess.TimeoutExpired:
            return "TIMEOUT", -1
        except FileNotFoundError as e:
            return f"Tool not found: {e}", -1


def run_tool_safe(
    cmd: list[str],
    evidence_path: str,
    tool_name: str,
    agent: str = "system",
    phase: str = "",
    iteration: int = 0,
    allowed_roots: Optional[list[str]] = None,
) -> ToolExecution:
    """
    Functional interface for one-off tool calls that don't need a full BaseTool subclass.
    Validates path, checks command safety, executes, returns ToolExecution.
    """
    roots = allowed_roots or config.EVIDENCE_ROOTS
    audit = get_audit_logger()

    try:
        validated = validate_path(evidence_path, roots)
        check_command_safety(" ".join(cmd))
    except SecurityError as e:
        audit.log_error(agent, tool_name, str(e), phase, iteration)
        return ToolExecution(
            tool_name=tool_name,
            command=" ".join(cmd),
            raw_output="",
            exit_code=-1,
            error_message=str(e),
            evidence_paths=[evidence_path],
        )

    t0 = time.monotonic()
    started = datetime.utcnow()
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        raw = r.stdout + r.stderr
        code = r.returncode
    except Exception as e:
        raw = str(e)
        code = -1

    duration_ms = (time.monotonic() - t0) * 1000
    if len(raw) > config.MAX_OUTPUT_SIZE:
        raw = raw[: config.MAX_OUTPUT_SIZE] + "\n[TRUNCATED]"

    output_hash = hashlib.sha256(raw.encode()).hexdigest()[:16]
    te = ToolExecution(
        tool_name=tool_name,
        command=" ".join(cmd),
        raw_output=raw,
        output_hash=output_hash,
        exit_code=code,
        started_at=started,
        duration_ms=duration_ms,
        evidence_paths=[validated],
    )
    audit.log_tool_execution(agent, tool_name, te.command, output_hash, phase=phase, iteration=iteration)
    return te
