"""Base tool class: security enforcement, audit logging, graceful degradation."""
from __future__ import annotations

import shutil
from typing import Any, Optional

from sift_hunter.core.audit import get_audit_logger
from sift_hunter.core.exceptions import ToolNotAvailableError
from sift_hunter.mcp_server.tools.executor import ExecutionResult, SafeExecutor


class BaseTool:
    """Base class all forensic tool wrappers inherit from.

    Provides:
    - Binary availability checking
    - Safe execution via SafeExecutor
    - Audit logging of every invocation
    - Graceful degradation when binary is missing
    """

    #: Override in subclass — name used in audit trail
    tool_name: str = "base_tool"
    #: Override in subclass — actual binary name
    binary_name: str = ""
    #: Human-readable description for MCP tool registry
    description: str = "Forensic tool wrapper"

    def __init__(self, executor: Optional[SafeExecutor] = None) -> None:
        self._executor = executor or SafeExecutor()
        self._audit = get_audit_logger()
        self._available: Optional[bool] = None

    def is_available(self) -> bool:
        """Return True if the binary is installed on this system."""
        if self._available is None:
            self._available = bool(shutil.which(self.binary_name))
        return self._available

    def _execute(
        self,
        args: list[str],
        evidence_path: Optional[str] = None,
        output_dir: Optional[str] = None,
        timeout: int = 300,
    ) -> ExecutionResult:
        """Execute the binary via the safe executor with audit logging."""
        result = self._executor.execute(
            self.binary_name,
            args,
            evidence_path=evidence_path,
            output_dir=output_dir,
            timeout=timeout,
        )
        # Log execution to audit trail
        from sift_hunter.core.models import ToolExecution
        te_dict = result.to_tool_execution_dict(tool_name=self.tool_name)
        from sift_hunter.core.models import ToolExecution
        try:
            te = ToolExecution(**te_dict)
            self._audit.log_tool_call(self.tool_name, te)
        except Exception:
            pass
        return result

    def _require_binary(self) -> None:
        """Raise ToolNotAvailableError if binary is not installed."""
        if not self.is_available():
            raise ToolNotAvailableError(
                f"{self.binary_name!r} is not installed on this system. "
                "Install SIFT Workstation or the Eric Zimmerman tools."
            )

    def _parse_output(self, result: ExecutionResult) -> Any:
        """Parse tool output into structured data. Override in subclasses."""
        raise NotImplementedError
