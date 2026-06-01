"""Tests for evidence integrity — SHA256 hashing, type detection, chain of custody.

Covers src/sift_hunter/core/evidence_integrity.py against the shipped package API.
(Replaces coverage previously provided by the removed pre-src/ test_accuracy.py.)
"""
from __future__ import annotations

import json

import pytest

from sift_hunter.core.evidence_integrity import (
    ChainOfCustody,
    detect_evidence_type,
    hash_file,
    hash_string,
    verify_hash,
)
from sift_hunter.core.exceptions import EvidenceNotFoundError
from sift_hunter.core.models import EvidenceType


class TestHashing:
    def test_hash_file_is_sha256_hex(self, tmp_path):
        f = tmp_path / "evidence.dd"
        f.write_bytes(b"A" * 4096)
        h = hash_file(str(f))
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_hash_file_is_deterministic(self, tmp_path):
        f = tmp_path / "evidence.dd"
        f.write_bytes(b"forensic bytes")
        assert hash_file(str(f)) == hash_file(str(f))

    def test_hash_file_missing_raises(self, tmp_path):
        with pytest.raises(EvidenceNotFoundError):
            hash_file(str(tmp_path / "does_not_exist.dd"))

    def test_hash_string_known_vector(self):
        # SHA256("") is well-known
        assert hash_string("") == (
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )

    def test_verify_hash_roundtrip(self, tmp_path):
        f = tmp_path / "mem.dmp"
        f.write_bytes(b"PAGEDUMP" + b"\x00" * 1024)
        h = hash_file(str(f))
        assert verify_hash(str(f), h) is True
        assert verify_hash(str(f), h.upper()) is True  # case-insensitive

    def test_verify_hash_detects_tampering(self, tmp_path):
        f = tmp_path / "disk.dd"
        f.write_bytes(b"original")
        original = hash_file(str(f))
        f.write_bytes(b"tampered")
        assert verify_hash(str(f), original) is False

    def test_verify_hash_missing_file_is_false(self, tmp_path):
        assert verify_hash(str(tmp_path / "nope.dd"), "0" * 64) is False


class TestEvidenceTypeDetection:
    @pytest.mark.parametrize(
        "name,expected",
        [
            ("case001.dd", EvidenceType.DISK_IMAGE),
            ("image.e01", EvidenceType.DISK_IMAGE),
            ("memory.dmp", EvidenceType.MEMORY_CAPTURE),
            ("capture.vmem", EvidenceType.MEMORY_CAPTURE),
            ("NTUSER.DAT", EvidenceType.REGISTRY_HIVE),
            ("amcache_export.csv", EvidenceType.AMCACHE),
            ("prefetch.pf", EvidenceType.PREFETCH),
            ("findings.json", EvidenceType.ARTIFACT_EXPORT),
            ("mystery.bin", EvidenceType.UNKNOWN),
        ],
    )
    def test_detect(self, name, expected):
        assert detect_evidence_type(name) == expected


class TestChainOfCustody:
    def test_register_returns_hashed_item(self, tmp_path):
        f = tmp_path / "case.dd"
        f.write_bytes(b"\x00" * 2048)
        coc = ChainOfCustody()
        item = coc.register(str(f))
        assert len(item.hash_sha256) == 64
        assert item.hash_verified is True
        assert item.evidence_type == EvidenceType.DISK_IMAGE
        assert item.size_bytes == 2048

    def test_register_missing_raises(self, tmp_path):
        coc = ChainOfCustody()
        with pytest.raises(EvidenceNotFoundError):
            coc.register(str(tmp_path / "ghost.dd"))

    def test_verify_all_passes_when_untampered(self, tmp_path):
        f = tmp_path / "mem.dmp"
        f.write_bytes(b"DUMP" * 100)
        coc = ChainOfCustody()
        coc.register(str(f))
        results = coc.verify_all()
        assert results == [(str(f), True)]

    def test_verify_all_detects_tampering(self, tmp_path):
        f = tmp_path / "mem.dmp"
        f.write_bytes(b"DUMP" * 100)
        coc = ChainOfCustody()
        coc.register(str(f))
        f.write_bytes(b"EVIL" * 100)  # tamper after registration
        results = coc.verify_all()
        assert results == [(str(f), False)]

    def test_access_log_records_registration_and_access(self, tmp_path):
        f = tmp_path / "case.dd"
        f.write_bytes(b"\x00" * 16)
        coc = ChainOfCustody()
        coc.register(str(f))
        coc.record_access(str(f))
        assert len(coc.access_log(str(f))) == 2

    def test_to_json_is_serializable_and_contains_item(self, tmp_path):
        f = tmp_path / "case.dd"
        f.write_bytes(b"\x00" * 16)
        coc = ChainOfCustody()
        coc.register(str(f))
        payload = json.loads(coc.to_json())
        assert "items" in payload and len(payload["items"]) == 1
        assert payload["items"][0]["path"] == str(f)
