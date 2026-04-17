"""Path traversal prevention — resolves symlinks and enforces evidence root boundaries."""
from __future__ import annotations

import os
import re
from pathlib import Path

from sift_hunter.core.exceptions import PathTraversalError


# Paths always blocked regardless of allowed_roots
_ALWAYS_BLOCKED_PREFIXES: tuple[str, ...] = (
    "/dev/", "/proc/", "/sys/", "/run/", "/boot/",
)

# URL/percent-encoding patterns
_PCT_ENCODE = re.compile(r"%[0-9a-fA-F]{2}")
_DOUBLE_PCT = re.compile(r"%25[0-9a-fA-F]{2}")


def validate_path(
    path: str,
    allowed_roots: list[str],
    must_exist: bool = False,
) -> Path:
    """Validate a path against allowed roots.

    Resolves symlinks, blocks traversal, enforces root boundaries.
    Returns the resolved absolute Path if safe.
    Raises PathTraversalError if any check fails.
    """
    if not path or not path.strip():
        raise PathTraversalError("Empty path")

    # Block null bytes
    if "\x00" in path:
        raise PathTraversalError("Null byte in path")

    # Block URL-encoded traversal sequences
    decoded = path
    if _DOUBLE_PCT.search(decoded):
        raise PathTraversalError(f"Double-encoded sequence in path: {path}")
    if _PCT_ENCODE.search(decoded):
        # Decode and re-check
        try:
            import urllib.parse
            decoded = urllib.parse.unquote(path)
        except Exception:
            raise PathTraversalError(f"Malformed URL encoding in path: {path}")

    # Block explicit ".." components in the ORIGINAL string (before resolution)
    for raw in (path, decoded):
        parts = raw.replace("\\", "/").split("/")
        if ".." in parts:
            raise PathTraversalError(f"Path traversal component '..' detected: {raw}")

    # Resolve to absolute, following symlinks
    try:
        resolved = Path(os.path.realpath(decoded))
    except Exception as e:
        raise PathTraversalError(f"Cannot resolve path {path!r}: {e}")

    # Block device/proc/sys files
    resolved_str = str(resolved)
    for prefix in _ALWAYS_BLOCKED_PREFIXES:
        if resolved_str.startswith(prefix):
            raise PathTraversalError(f"Access to {prefix}* is blocked: {resolved_str}")

    # Block root itself
    if resolved_str in ("/", ""):
        raise PathTraversalError("Access to filesystem root is blocked")

    # Check against allowed roots
    if allowed_roots:
        allowed = False
        for root in allowed_roots:
            try:
                root_resolved = str(Path(os.path.realpath(root)))
                if resolved_str.startswith(root_resolved.rstrip("/") + "/") or resolved_str == root_resolved:
                    allowed = True
                    break
            except Exception:
                continue
        if not allowed:
            raise PathTraversalError(
                f"Path {resolved_str!r} is outside allowed roots: {allowed_roots}"
            )

    if must_exist and not resolved.exists():
        raise PathTraversalError(f"Path does not exist: {resolved_str}")

    return resolved


def sanitize_filename(name: str) -> str:
    """Sanitize a filename, removing traversal and special characters."""
    safe = name.replace("..", "_").replace("/", "_").replace("\\", "_")
    safe = re.sub(r"[^\w.\-]", "_", safe)
    if safe.startswith("-"):
        safe = "_" + safe[1:]
    return safe or "_"
