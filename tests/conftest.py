"""Shared fixtures for SIFT-HUNTER tests."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def set_evidence_roots(tmp_path):
    """Set evidence roots and output root to temp directories for all tests."""
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    os.environ["SIFT_EVIDENCE_ROOTS"] = str(evidence_dir)
    os.environ["SIFT_OUTPUT_ROOT"] = str(output_dir)
    yield evidence_dir, output_dir
    # Cleanup handled by tmp_path fixture


@pytest.fixture
def evidence_file(tmp_path):
    """Create a sample evidence file in the evidence directory."""
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir(exist_ok=True)
    f = evidence_dir / "test.dd"
    f.write_bytes(b"FAKE DISK IMAGE CONTENT" * 100)
    return str(f)


@pytest.fixture
def output_dir(tmp_path):
    """Return the output directory path as a string."""
    d = tmp_path / "output"
    d.mkdir(exist_ok=True)
    return str(d)


@pytest.fixture
def evidence_root(tmp_path):
    """Return the evidence root directory path as a string."""
    d = tmp_path / "evidence"
    d.mkdir(exist_ok=True)
    return str(d)
