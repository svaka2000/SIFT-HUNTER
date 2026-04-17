"""SHA256 hashing and chain-of-custody tracking for forensic evidence."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from sift_hunter.core.exceptions import EvidenceIntegrityError, EvidenceNotFoundError
from sift_hunter.core.models import EvidenceItem, EvidenceType


def hash_file(path: str) -> str:
    """Compute SHA256 hash of a file. Reads in 64KB chunks for large files."""
    p = Path(path)
    if not p.exists():
        raise EvidenceNotFoundError(f"Evidence not found: {path}")
    sha256 = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def hash_string(data: str) -> str:
    """Compute SHA256 hash of a string."""
    return hashlib.sha256(data.encode()).hexdigest()


def verify_hash(path: str, expected: str) -> bool:
    """Verify a file's SHA256 hash against an expected value."""
    try:
        actual = hash_file(path)
        return actual.lower() == expected.lower()
    except Exception:
        return False


def detect_evidence_type(path: str) -> EvidenceType:
    """Infer evidence type from file extension and name."""
    p = Path(path)
    ext = p.suffix.lower()
    name = p.name.lower()
    if ext in {".dd", ".img", ".e01", ".vmdk", ".vhd", ".raw"} or "disk" in name:
        return EvidenceType.DISK_IMAGE
    if ext in {".dmp", ".mem", ".vmem", ".lime"} or "memory" in name or "mem" in name:
        return EvidenceType.MEMORY_CAPTURE
    if "ntuser" in name or "usrclass" in name or ext == ".dat":
        return EvidenceType.REGISTRY_HIVE
    if "$mft" in name or "mft" in name:
        return EvidenceType.MFT
    if ext == ".pf" or "prefetch" in name:
        return EvidenceType.PREFETCH
    if "amcache" in name:
        return EvidenceType.AMCACHE
    if "usnjrnl" in name or "$j" in name:
        return EvidenceType.USN_JOURNAL
    if ext == ".evtx" or "eventlog" in name:
        return EvidenceType.EVENT_LOG
    if "shellbag" in name:
        return EvidenceType.SHELLBAGS
    if ext in {".csv", ".txt", ".log", ".json", ".tsv"}:
        return EvidenceType.ARTIFACT_EXPORT
    return EvidenceType.UNKNOWN


class ChainOfCustody:
    """Tracks every access to evidence files with SHA256 verification."""

    def __init__(self) -> None:
        self._items: dict[str, EvidenceItem] = {}
        self._access_log: dict[str, list[datetime]] = {}

    def register(self, path: str) -> EvidenceItem:
        """Hash and register an evidence file. Returns EvidenceItem."""
        p = Path(path)
        if not p.exists():
            raise EvidenceNotFoundError(f"Evidence not found: {path}")
        try:
            h = hash_file(path)
        except Exception:
            h = ""
        item = EvidenceItem(
            path=path,
            evidence_type=detect_evidence_type(path),
            hash_sha256=h,
            hash_verified=bool(h),
            size_bytes=p.stat().st_size if p.is_file() else 0,
        )
        self._items[path] = item
        self._access_log.setdefault(path, []).append(datetime.utcnow())
        return item

    def verify_all(self) -> list[tuple[str, bool]]:
        """Re-hash all registered items and compare. Returns (path, ok) pairs."""
        results = []
        for path, item in self._items.items():
            if item.hash_sha256:
                ok = verify_hash(path, item.hash_sha256)
                if not ok:
                    item.hash_verified = False
                results.append((path, ok))
            else:
                results.append((path, False))
        return results

    def record_access(self, path: str) -> None:
        """Record that evidence at path was accessed."""
        self._access_log.setdefault(path, []).append(datetime.utcnow())

    def get_item(self, path: str) -> Optional[EvidenceItem]:
        """Get the registered EvidenceItem for a path."""
        return self._items.get(path)

    def access_log(self, path: str) -> list[datetime]:
        """Return timestamps of all accesses to this evidence."""
        return self._access_log.get(path, [])

    @property
    def items(self) -> list[EvidenceItem]:
        """All registered evidence items."""
        return list(self._items.values())

    def to_json(self) -> str:
        """Serialize chain of custody to JSON string."""
        return json.dumps(
            {
                "items": [i.model_dump(mode="json") for i in self._items.values()],
                "access_log": {
                    p: [t.isoformat() for t in times]
                    for p, times in self._access_log.items()
                },
            },
            indent=2,
        )
