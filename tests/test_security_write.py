"""Write-prevention tests for evidence directories — 6 cases."""
from __future__ import annotations

import os
import pytest

from sift_hunter.core.exceptions import PathTraversalError, WriteAttemptError
from sift_hunter.mcp_server.security.evidence_guard import enforce_read_only


pytestmark = pytest.mark.unit


def test_write_to_evidence_dir(tmp_path):
    """Write to evidence dir raises WriteAttemptError."""
    evidence = tmp_path / "evidence"
    evidence.mkdir(exist_ok=True)
    os.environ["SIFT_EVIDENCE_ROOTS"] = str(evidence)
    target = str(evidence / "file.dd")
    with pytest.raises(WriteAttemptError):
        enforce_read_only(target, "write")


def test_create_in_evidence_dir(tmp_path):
    """Create in evidence dir raises WriteAttemptError."""
    evidence = tmp_path / "evidence"
    evidence.mkdir(exist_ok=True)
    os.environ["SIFT_EVIDENCE_ROOTS"] = str(evidence)
    with pytest.raises(WriteAttemptError):
        enforce_read_only(str(evidence / "new.txt"), "create")


def test_delete_from_evidence_dir(tmp_path):
    """Delete from evidence dir raises WriteAttemptError."""
    evidence = tmp_path / "evidence"
    evidence.mkdir(exist_ok=True)
    os.environ["SIFT_EVIDENCE_ROOTS"] = str(evidence)
    with pytest.raises(WriteAttemptError):
        enforce_read_only(str(evidence / "evidence.dd"), "delete")


def test_modify_evidence_file(tmp_path):
    """Modify evidence file raises WriteAttemptError."""
    evidence = tmp_path / "evidence"
    evidence.mkdir(exist_ok=True)
    os.environ["SIFT_EVIDENCE_ROOTS"] = str(evidence)
    with pytest.raises(WriteAttemptError):
        enforce_read_only(str(evidence / "registry.hive"), "modify")


def test_write_to_output_dir_allowed(tmp_path):
    """Write to output directory is allowed (no exception)."""
    out = tmp_path / "output"
    out.mkdir(exist_ok=True)
    os.environ["SIFT_OUTPUT_ROOT"] = str(out)
    # Should not raise
    enforce_read_only(str(out / "report.md"), "write")


def test_read_from_evidence_allowed(tmp_path):
    """Read from evidence dir is always allowed."""
    evidence = tmp_path / "evidence"
    evidence.mkdir(exist_ok=True)
    os.environ["SIFT_EVIDENCE_ROOTS"] = str(evidence)
    # Should not raise for read operations
    enforce_read_only(str(evidence / "disk.dd"), "read")
