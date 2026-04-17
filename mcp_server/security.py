"""
Architectural security guardrails for the MCP server.
EVERY tool function must pass through these before execution.
This is NOT prompt-based — it's enforced in Python. Judges WILL attempt bypasses.

Blocked: rm, dd, shred, wget, curl, nc, ssh, mkfs, fdisk, chmod, chown, mount, kill, ...
Allowed: read-only forensic binaries under strict path validation.
"""

from __future__ import annotations

import functools
import re
import shlex
from typing import Any, Callable, Optional, TypeVar

from mcp_server.validators.path_validator import SecurityError, validate_path

F = TypeVar("F", bound=Callable[..., Any])

# ── Blocked command prefixes and substrings ──────────────────────────────────
BLOCKED_COMMANDS: frozenset[str] = frozenset([
    # Destructive filesystem ops
    "rm", "rmdir", "del", "shred", "dd", "mkfs", "fdisk", "format",
    "wipefs", "wipe", "srm", "secure-delete",
    # Network exfiltration
    "wget", "curl", "nc", "netcat", "ncat", "socat",
    "ssh", "scp", "sftp", "ftp", "rsync", "rcp",
    # Privilege / execution
    "sudo", "su", "chmod", "chown", "chgrp",
    "mount", "umount", "fusermount",
    # Process control
    "kill", "pkill", "killall", "reboot", "shutdown", "halt", "poweroff",
    # Shell spawns
    "bash", "sh", "zsh", "fish", "tcsh", "csh", "cmd", "powershell",
    "python", "python3", "perl", "ruby", "node", "lua",
    # Write tools
    "tee", "cp", "mv", "install", "ln",
    # Package managers (prevent dependency injection)
    "apt", "apt-get", "yum", "dnf", "pip", "pip3", "npm", "cargo",
])

# Allowed forensic read-only binaries — explicit allowlist (safer than blocklist)
ALLOWED_BINARIES: frozenset[str] = frozenset([
    "log2timeline.py", "log2timeline", "psort.py", "psort",
    "pinfo.py", "pinfo",
    "vol", "vol.py", "vol3",
    "regripper", "rip.pl",
    "strings", "file", "xxd", "hexdump",
    "sha256sum", "md5sum", "sha1sum",
    "stat", "ls", "find", "cat", "head", "tail", "grep", "awk", "sort",
    "python3",  # Allowed ONLY for running specific forensic scripts, not arbitrary
])

# Mono-flag patterns that indicate write/destroy operations
_DANGEROUS_FLAG_PATTERNS: list[re.Pattern] = [
    re.compile(r"--delete"),
    re.compile(r"--remove"),
    re.compile(r"--overwrite"),
    re.compile(r"-[rR]*r[rRf]*"),  # rm -r / -rf / -Rf style (must contain 'r')
    re.compile(r">\s*/"),    # redirect to filesystem root
    re.compile(r"2>/dev/null.*&&"),  # piped destruction with silenced errors
]


def check_command_safety(command: str) -> None:
    """
    Raise SecurityError if the command contains any blocked binary or dangerous pattern.
    Called before every subprocess invocation.
    """
    try:
        tokens = shlex.split(command)
    except ValueError:
        raise SecurityError(f"Cannot parse command (shell injection attempt?): {command!r}")

    if not tokens:
        raise SecurityError("Empty command rejected.")

    binary = tokens[0].split("/")[-1].lower()  # strip path prefix

    # Check exact match AND prefix match (catches mkfs.ext4, mkfs.btrfs, etc.)
    if binary in BLOCKED_COMMANDS or any(binary.startswith(b + ".") for b in BLOCKED_COMMANDS):
        raise SecurityError(f"Command '{binary}' is permanently blocked (destructive/network tool).")

    # Block shell metacharacters BEFORE flag pattern checks — these are always injections
    for dangerous_char in [";", "&&", "||", "`", "$("]:
        if dangerous_char in command:
            raise SecurityError(
                f"Shell metacharacter {dangerous_char!r} detected — command chaining blocked."
            )

    # Check every token for destructive flag patterns
    full_lower = command.lower()
    for pattern in _DANGEROUS_FLAG_PATTERNS:
        if pattern.search(full_lower):
            raise SecurityError(f"Dangerous flag/pattern detected in command: {command!r}")


def read_only(func: F) -> F:
    """
    Decorator that marks a tool as read-only.
    Checks command safety before execution.
    Provides defense-in-depth against prompt injection.
    """
    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        # If the function accepts a 'command' kwarg, validate it
        if "command" in kwargs:
            check_command_safety(kwargs["command"])
        return func(*args, **kwargs)
    return wrapper  # type: ignore[return-value]


def validated_path(allowed_roots_attr: str = "_allowed_roots"):
    """
    Decorator factory that validates all path arguments before passing to the function.
    Tools must have self._allowed_roots set (done in BaseTool.__init__).
    """
    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(self: Any, *args: Any, **kwargs: Any) -> Any:
            roots = getattr(self, allowed_roots_attr, [])
            # Validate any kwarg that looks like a path
            path_keys = {k for k in kwargs if "path" in k.lower() or "file" in k.lower() or "dir" in k.lower()}
            for key in path_keys:
                if isinstance(kwargs[key], str) and kwargs[key]:
                    kwargs[key] = validate_path(kwargs[key], roots)
            return func(self, *args, **kwargs)
        return wrapper  # type: ignore[return-value]
    return decorator
