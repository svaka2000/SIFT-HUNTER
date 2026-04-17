"""Custom exception hierarchy for SIFT-HUNTER."""
from __future__ import annotations


class SiftHunterError(Exception):
    """Base exception for all SIFT-HUNTER errors."""


class SecurityViolation(SiftHunterError):
    """A security boundary was violated."""


class PathTraversalError(SecurityViolation):
    """Attempted path traversal outside allowed roots."""


class CommandInjectionError(SecurityViolation):
    """Injection characters detected in command arguments."""


class UnauthorizedBinaryError(SecurityViolation):
    """Attempt to execute a binary not on the allowlist."""


class WriteAttemptError(SecurityViolation):
    """Attempt to write to a read-only evidence directory."""


class ToolExecutionError(SiftHunterError):
    """A forensic tool failed to execute or produce output."""


class ToolNotAvailableError(ToolExecutionError):
    """Required forensic binary is not installed."""


class ToolTimeoutError(ToolExecutionError):
    """Tool execution exceeded the timeout limit."""


class ToolOutputParseError(ToolExecutionError):
    """Failed to parse structured output from a tool."""


class EvidenceError(SiftHunterError):
    """Problem with forensic evidence."""


class EvidenceNotFoundError(EvidenceError):
    """Evidence file or directory does not exist."""


class EvidenceIntegrityError(EvidenceError):
    """Evidence hash verification failed — possible tampering."""


class EvidenceCorruptedError(EvidenceError):
    """Evidence file appears corrupted or unreadable."""


class AgentError(SiftHunterError):
    """Multi-agent orchestration error."""


class MaxIterationsError(AgentError):
    """Analysis exceeded the maximum allowed iteration count."""


class HallucinationDetectedError(AgentError):
    """Agent produced a claim not supported by tool output."""


class OrchestrationError(AgentError):
    """LangGraph workflow encountered an unrecoverable error."""
