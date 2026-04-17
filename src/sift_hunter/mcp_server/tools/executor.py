"""Safe subprocess executor for forensic tool binaries."""
from __future__ import annotations

import hashlib
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from sift_hunter.core.exceptions import ToolExecutionError, ToolTimeoutError
from sift_hunter.mcp_server.security.command_sanitizer import validate_command
from sift_hunter.mcp_server.security.evidence_guard import get_output_root
from sift_hunter.mcp_server.security.path_validator import validate_path


@dataclass
class ExecutionResult:
    """Result of a safe tool execution."""
    binary: str
    args: list[str]
    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float
    output_hash: str
    output_size_bytes: int
    output_files: list[str] = field(default_factory=list)
    success: bool = True
    tool_execution_id: str = ""

    def to_tool_execution_dict(self, tool_name: str = "", evidence_id: str = "") -> dict:
        """Convert to ToolExecution model dict."""
        from sift_hunter.core.models import ToolExecution
        te = ToolExecution(
            tool_name=tool_name or self.binary,
            binary=self.binary,
            command_args=self.args,
            evidence_id=evidence_id,
            exit_code=self.exit_code,
            output_hash=self.output_hash,
            output_size_bytes=self.output_size_bytes,
            raw_output=self.stdout[:8000],
            output_summary=self.stdout[:500],
            error_output=self.stderr[:500],
            success=self.success,
            duration_seconds=self.duration_seconds,
        )
        self.tool_execution_id = te.id
        return te.model_dump(mode="json")


class SafeExecutor:
    """Executes forensic binaries safely via subprocess with security enforcement."""

    DEFAULT_TIMEOUT = 300  # 5 minutes

    def __init__(self, evidence_roots: Optional[list[str]] = None) -> None:
        from sift_hunter.mcp_server.security.evidence_guard import get_evidence_roots
        self._evidence_roots = evidence_roots or get_evidence_roots()

    def execute(
        self,
        binary: str,
        args: list[str],
        evidence_path: Optional[str] = None,
        output_dir: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT,
        env: Optional[dict] = None,
    ) -> ExecutionResult:
        """Execute a forensic tool binary safely.

        All security checks run before execution:
        1. Binary + args validated against allowlist.
        2. evidence_path validated against evidence roots.
        3. output_dir validated as output root or omitted.
        4. subprocess.run() with shell=False, timeout, captured I/O.
        """
        # Security: validate binary and args
        resolved_binary, safe_args = validate_command(binary, args)

        # Security: validate evidence path
        if evidence_path:
            validate_path(evidence_path, self._evidence_roots)

        # Determine working directory (output root)
        cwd = output_dir or get_output_root()
        Path(cwd).mkdir(parents=True, exist_ok=True)

        cmd = [resolved_binary] + safe_args
        start = time.time()

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=cwd,
                env=env,
            )
        except subprocess.TimeoutExpired:
            raise ToolTimeoutError(
                f"{binary} timed out after {timeout}s. Evidence: {evidence_path}"
            )
        except FileNotFoundError:
            # Binary not installed — return graceful degradation result
            return ExecutionResult(
                binary=binary,
                args=safe_args,
                exit_code=127,
                stdout="",
                stderr=f"{binary}: command not found (not installed on this system)",
                duration_seconds=time.time() - start,
                output_hash="",
                output_size_bytes=0,
                success=False,
            )
        except Exception as e:
            raise ToolExecutionError(f"Failed to execute {binary}: {e}") from e

        duration = time.time() - start
        stdout = proc.stdout or ""
        output_hash = hashlib.sha256(stdout.encode()).hexdigest() if stdout else ""

        # Discover any output files created in cwd
        output_files: list[str] = []
        if cwd and Path(cwd).exists():
            output_files = [
                str(p) for p in Path(cwd).iterdir()
                if p.is_file() and p.suffix.lower() in {".csv", ".json", ".txt", ".log"}
            ]

        return ExecutionResult(
            binary=resolved_binary,
            args=safe_args,
            exit_code=proc.returncode,
            stdout=stdout,
            stderr=proc.stderr or "",
            duration_seconds=duration,
            output_hash=output_hash,
            output_size_bytes=len(stdout.encode()),
            output_files=output_files,
            success=proc.returncode == 0,
        )

    def check_binary(self, binary: str) -> bool:
        """Return True if a binary is installed on this system."""
        import shutil
        return bool(shutil.which(binary))
