"""Destructive and unauthorized binary blocking tests — 17 cases."""
from __future__ import annotations

import pytest

from sift_hunter.core.exceptions import UnauthorizedBinaryError
from sift_hunter.mcp_server.security.command_sanitizer import validate_command


pytestmark = pytest.mark.unit


@pytest.mark.parametrize("binary", [
    "rm", "rmdir", "shred", "wipe", "srm",
    "dd", "mkfs", "fdisk", "parted",
    "chmod", "chown", "chgrp",
    "kill", "pkill",
    "wget", "curl", "nc", "ssh", "scp",
    "bash", "sh", "zsh",
    "python", "sudo",
])
def test_blocked_binary(binary):
    """Blocked binary raises UnauthorizedBinaryError."""
    with pytest.raises(UnauthorizedBinaryError):
        validate_command(binary, [])


def test_block_full_path_rm():
    """/usr/bin/rm still blocked (basename extracted)."""
    with pytest.raises(UnauthorizedBinaryError):
        validate_command("/usr/bin/rm", ["-rf", "/"])


def test_block_case_upper():
    """RM (uppercase) blocked."""
    with pytest.raises(UnauthorizedBinaryError):
        validate_command("RM", [])


def test_block_case_mixed():
    """Rm (mixed case) blocked."""
    with pytest.raises(UnauthorizedBinaryError):
        validate_command("Rm", [])


def test_allow_MFTECmd():
    """MFTECmd with valid flags is allowed."""
    try:
        binary, args = validate_command("MFTECmd", ["-f", "/cases/test.dd", "--csv", "/tmp/out/"])
        assert "MFTECmd" in binary or binary.endswith("MFTECmd")
    except UnauthorizedBinaryError:
        pytest.fail("MFTECmd should be allowed")


def test_allow_vol():
    """vol with valid flags is allowed."""
    try:
        validate_command("vol", ["-f", "/cases/memory.dmp"])
    except UnauthorizedBinaryError:
        pytest.fail("vol should be allowed")


def test_allow_sha256sum():
    """sha256sum with no flags is allowed."""
    try:
        validate_command("sha256sum", ["/cases/evidence.dd"])
    except UnauthorizedBinaryError:
        pytest.fail("sha256sum should be allowed")


def test_unknown_binary_blocked():
    """An unlisted binary is blocked."""
    with pytest.raises(UnauthorizedBinaryError):
        validate_command("totally_custom_tool", ["--flag"])


def test_block_mkfs_variant():
    """mkfs blocked as a listed blocked binary."""
    with pytest.raises(UnauthorizedBinaryError):
        validate_command("mkfs", [])
