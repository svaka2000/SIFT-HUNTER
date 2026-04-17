"""Security decorators applied to every forensic tool function."""
from __future__ import annotations

import functools
import inspect
import time
from typing import Any, Callable

from sift_hunter.mcp_server.security.command_sanitizer import sanitize_args
from sift_hunter.mcp_server.security.evidence_guard import enforce_read_only
from sift_hunter.mcp_server.security.path_validator import validate_path


def _get_path_args(func: Callable, args: tuple, kwargs: dict) -> list[str]:
    """Extract string arguments that look like file paths from a function call."""
    sig = inspect.signature(func)
    bound = sig.bind(*args, **kwargs)
    bound.apply_defaults()
    paths = []
    for name, value in bound.arguments.items():
        if isinstance(value, str) and (
            "/" in value or "\\" in value or value.endswith((".py", ".dd", ".mem", ".dmp"))
        ):
            paths.append(value)
    return paths


def read_only(func: Callable) -> Callable:
    """Decorator: ensure all path arguments are in evidence roots (read-only)."""
    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        for path in _get_path_args(func, args, kwargs):
            enforce_read_only(path, "write")  # Raises if a write is attempted
        return func(*args, **kwargs)
    return wrapper


def validated_path(allowed_roots: list[str] | None = None) -> Callable:
    """Decorator factory: validate all path arguments against allowed roots."""
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            from sift_hunter.mcp_server.security.evidence_guard import get_evidence_roots, get_output_root
            roots = allowed_roots or get_evidence_roots() + [get_output_root()]
            for path in _get_path_args(func, args, kwargs):
                if path:
                    validate_path(path, roots)
            return func(*args, **kwargs)
        return wrapper
    return decorator


def audited(tool_name: str) -> Callable:
    """Decorator factory: automatically log tool invocations to audit trail."""
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            from sift_hunter.core.audit import get_audit_logger
            from sift_hunter.core.models import ToolExecution
            audit = get_audit_logger()
            te = ToolExecution(
                tool_name=tool_name,
                binary=tool_name,
                started_at=__import__("datetime").datetime.utcnow(),
            )
            start = time.time()
            try:
                result = func(*args, **kwargs)
                te.exit_code = 0
                te.success = True
                return result
            except Exception as e:
                te.exit_code = 1
                te.success = False
                te.error_output = str(e)[:500]
                raise
            finally:
                te.duration_seconds = time.time() - start
                te.completed_at = __import__("datetime").datetime.utcnow()
                audit.log_tool_call("mcp_server", te)
        return wrapper
    return decorator


def secure_tool(tool_name: str, evidence_args: list[str] | None = None) -> Callable:
    """Combined decorator: read_only + validated_path + audited."""
    def decorator(func: Callable) -> Callable:
        wrapped = audited(tool_name)(validated_path()(read_only(func)))
        return wrapped
    return decorator
