"""Read-only enforcement for evidence directories."""
from __future__ import annotations

import os
from pathlib import Path

from sift_hunter.core.exceptions import PathTraversalError, WriteAttemptError


def get_evidence_roots() -> list[str]:
    """Return configured evidence root directories."""
    raw = os.environ.get("SIFT_EVIDENCE_ROOTS", "/cases:/mnt/evidence:/tmp/sift-evidence")
    return [r.strip() for r in raw.split(":") if r.strip()]


def get_output_root() -> str:
    """Return configured output directory (writes allowed here)."""
    return os.environ.get("SIFT_OUTPUT_ROOT", "/tmp/sift-output")


def is_evidence_path(path: str) -> bool:
    """Return True if path is under an evidence root."""
    try:
        resolved = str(Path(os.path.realpath(path)))
        for root in get_evidence_roots():
            root_r = str(Path(os.path.realpath(root)))
            if resolved.startswith(root_r.rstrip("/") + "/") or resolved == root_r:
                return True
    except Exception:
        pass
    return False


def is_output_path(path: str) -> bool:
    """Return True if path is under the output root."""
    try:
        resolved = str(Path(os.path.realpath(path)))
        out_root = str(Path(os.path.realpath(get_output_root())))
        return resolved.startswith(out_root.rstrip("/") + "/") or resolved == out_root
    except Exception:
        return False


def enforce_read_only(path: str, operation: str) -> None:
    """Raise WriteAttemptError if a write operation targets an evidence directory.

    Write operations allowed only under the output root.
    """
    write_ops = {"write", "create", "delete", "modify", "truncate", "rename", "move"}
    if operation.lower() not in write_ops:
        return  # Read operation - no enforcement needed

    if is_evidence_path(path):
        raise WriteAttemptError(
            f"Write operation '{operation}' to evidence path {path!r} is blocked. "
            "Evidence directories are read-only."
        )

    if not is_output_path(path):
        raise PathTraversalError(
            f"Write operation '{operation}' to {path!r} is outside the output root "
            f"({get_output_root()!r}). Only writes to the output root are allowed."
        )
