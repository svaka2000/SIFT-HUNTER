"""Command sanitization: allowlist enforcement and injection prevention."""
from __future__ import annotations

import shutil
from pathlib import Path

from sift_hunter.core.exceptions import (
    CommandInjectionError,
    UnauthorizedBinaryError,
)
from sift_hunter.mcp_server.security.allowlist import (
    ALLOWED_BINARIES,
    BLOCKED_BINARIES,
    INJECTION_CHARS,
    VOLATILITY_PLUGIN_RE,
)


def _extract_basename(binary: str) -> str:
    """Extract just the binary name from a potentially path-prefixed string."""
    return Path(binary).name


def sanitize_args(args: list[str]) -> list[str]:
    """Check each argument for injection characters.

    Raises CommandInjectionError if any injection character is found.
    Returns the args list unchanged if clean.
    """
    for arg in args:
        for char in INJECTION_CHARS:
            if char in arg:
                raise CommandInjectionError(
                    f"Shell injection character {char!r} detected in argument: {arg!r}"
                )
    return list(args)


def validate_command(
    binary: str,
    args: list[str],
) -> tuple[str, list[str]]:
    """Validate a binary + args against the security allowlist.

    Steps:
      1. Check binary is NOT in the blocklist.
      2. Check binary IS in the allowlist.
      3. Resolve binary to full path via shutil.which().
      4. Validate each flag against the binary's allowed flags.
      5. Sanitize all arguments for injection characters.

    Returns (resolved_binary_path, sanitized_args).
    Raises SecurityViolation subclass on any failure.
    """
    basename = _extract_basename(binary).lower()
    # Case-insensitive lookup by normalizing
    binary_lower_map = {k.lower(): k for k in ALLOWED_BINARIES}
    blocked_lower = {b.lower() for b in BLOCKED_BINARIES}

    # 1. Block check (catches path-prefixed variants like /usr/bin/rm)
    if basename in blocked_lower:
        raise UnauthorizedBinaryError(
            f"Binary {basename!r} is explicitly blocked (destruction/exfiltration risk)"
        )

    # 2. Allowlist check
    if basename not in binary_lower_map:
        raise UnauthorizedBinaryError(
            f"Binary {basename!r} is not on the allowlist. "
            f"Allowed tools: {sorted(ALLOWED_BINARIES)}"
        )

    canonical = binary_lower_map[basename]
    allowed_flags = ALLOWED_BINARIES[canonical]

    # 3. Resolve to full path
    resolved = shutil.which(canonical) or shutil.which(basename)
    if not resolved:
        # Binary not installed — return a placeholder path for graceful degradation
        resolved = f"/usr/bin/{canonical}"

    # 4. Validate flags — only check tokens that look like flags (start with -)
    #    Positional args (file paths, plugin names) are allowed through
    for arg in args:
        if arg.startswith("-"):
            if allowed_flags and arg not in allowed_flags:
                raise UnauthorizedBinaryError(
                    f"Flag {arg!r} is not allowed for {canonical!r}. "
                    f"Allowed flags: {sorted(allowed_flags)}"
                )
        elif VOLATILITY_PLUGIN_RE.match(arg) and "." in arg:
            # Volatility plugin name — allowed
            pass

    # 5. Injection check on all args
    sanitized = sanitize_args(args)

    return resolved, sanitized
