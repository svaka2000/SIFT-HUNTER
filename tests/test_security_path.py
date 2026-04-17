"""Path traversal security tests — 16 cases."""
from __future__ import annotations

import os
import pytest
from pathlib import Path

from sift_hunter.core.exceptions import PathTraversalError
from sift_hunter.mcp_server.security.path_validator import validate_path, sanitize_filename


pytestmark = pytest.mark.unit


def test_valid_evidence_path(tmp_path):
    """A path under the allowed root is returned resolved."""
    root = str(tmp_path)
    f = tmp_path / "evidence.dd"
    f.write_bytes(b"data")
    result = validate_path(str(f), [root])
    assert result == f.resolve()


def test_path_traversal_dotdot(tmp_path):
    """../../etc/passwd blocked."""
    with pytest.raises(PathTraversalError):
        validate_path(f"{tmp_path}/../../etc/passwd", [str(tmp_path)])


def test_path_traversal_dotdot_in_middle(tmp_path):
    """Traversal in the middle of a path blocked."""
    with pytest.raises(PathTraversalError):
        validate_path(f"{tmp_path}/sub/../../../etc/passwd", [str(tmp_path)])


def test_path_traversal_encoded(tmp_path):
    """%2e%2e%2f traversal blocked."""
    with pytest.raises(PathTraversalError):
        validate_path(f"{tmp_path}/%2e%2e%2fetc%2fpasswd", [str(tmp_path)])


def test_path_traversal_double_encoded(tmp_path):
    """%252e%252e%252f double-encoded traversal blocked."""
    with pytest.raises(PathTraversalError):
        validate_path(f"{tmp_path}/%252e%252e%252fetc", [str(tmp_path)])


def test_path_traversal_null_byte(tmp_path):
    """Null byte in path blocked."""
    with pytest.raises(PathTraversalError):
        validate_path(f"{tmp_path}/evidence.dd\x00.txt", [str(tmp_path)])


def test_path_device_file():
    """/dev/sda blocked."""
    with pytest.raises(PathTraversalError):
        validate_path("/dev/sda", ["/dev"])


def test_path_proc_file():
    """/proc/self/environ blocked."""
    with pytest.raises(PathTraversalError):
        validate_path("/proc/self/environ", ["/proc"])


def test_path_sys_file():
    """/sys/class/net blocked."""
    with pytest.raises(PathTraversalError):
        validate_path("/sys/class/net", ["/sys"])


def test_path_empty():
    """Empty path raises PathTraversalError."""
    with pytest.raises(PathTraversalError):
        validate_path("", ["/cases"])


def test_path_root():
    """Filesystem root / blocked."""
    with pytest.raises(PathTraversalError):
        validate_path("/", ["/cases"])


def test_path_home_not_in_roots(tmp_path):
    """/home/user blocked when not in allowed roots."""
    with pytest.raises(PathTraversalError):
        validate_path("/home/user/secret.txt", [str(tmp_path)])


def test_path_outside_roots(tmp_path):
    """A path outside all allowed roots is blocked."""
    other = tmp_path.parent / "other"
    other.mkdir(exist_ok=True)
    with pytest.raises(PathTraversalError):
        validate_path(str(other / "file.txt"), [str(tmp_path)])


def test_valid_output_path(tmp_path):
    """Output root path resolves without error when included in roots."""
    out = tmp_path / "output"
    out.mkdir(exist_ok=True)
    result = validate_path(str(out), [str(tmp_path)])
    assert result is not None


def test_path_backslash_traversal(tmp_path):
    r"""Windows-style backslash traversal blocked."""
    with pytest.raises(PathTraversalError):
        validate_path(str(tmp_path) + r"\..\etc\passwd", [str(tmp_path)])


def test_sanitize_filename_removes_traversal():
    """sanitize_filename strips .. and special chars."""
    result = sanitize_filename("../../etc/passwd")
    assert ".." not in result
    assert "/" not in result


def test_sanitize_filename_strips_leading_dash():
    """sanitize_filename removes leading dash (flag injection)."""
    result = sanitize_filename("-rf")
    assert not result.startswith("-")
