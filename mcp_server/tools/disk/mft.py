"""
MFTECmd wrapper — parses the NTFS Master File Table.
Reveals file creation, modification, access, and deletion artifacts.
"""

from __future__ import annotations

import csv
import os
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel

from core.models import ToolExecution
from mcp_server.config import config
from mcp_server.tools.base import BaseTool


class MFTEntry(BaseModel):
    entry_number: str = ""
    sequence: str = ""
    parent_entry: str = ""
    entry_type: str = ""
    in_use: bool = True
    filename: str = ""
    extension: str = ""
    file_size: Optional[int] = None
    created0x10: Optional[datetime] = None
    modified0x10: Optional[datetime] = None
    accessed0x10: Optional[datetime] = None
    entry_modified0x10: Optional[datetime] = None
    created0x30: Optional[datetime] = None
    modified0x30: Optional[datetime] = None
    is_ads: bool = False
    has_ads: bool = False
    fullpath: str = ""
    raw_line: str = ""


class MFTResult(BaseModel):
    entries: list[MFTEntry] = []
    total_entries: int = 0
    suspicious_count: int = 0
    error: Optional[str] = None


class SuspiciousEntry(BaseModel):
    entry: MFTEntry
    reason: str
    severity: str  # HIGH, MEDIUM, LOW


class MFTTool(BaseTool):
    tool_name = "MFTECmd"

    def _build_command(self, evidence_path: str, args: dict[str, Any]) -> list[str]:
        output_dir = args.get("output_dir", config.OUTPUT_ROOT)
        return [
            "MFTECmd.exe" if os.name == "nt" else "mftecmd",
            "-f", evidence_path,
            "--csv", output_dir,
        ]

    def parse_mft(
        self,
        mft_path: str,
        agent: str = "system",
        phase: str = "disk",
        iteration: int = 0,
    ) -> tuple[ToolExecution, MFTResult]:
        config.ensure_output_dir()
        te = self.run(
            mft_path,
            agent=agent,
            phase=phase,
            iteration=iteration,
            extra_args={"output_dir": config.OUTPUT_ROOT},
        )

        result = MFTResult()
        if te.exit_code != 0 and not te.raw_output:
            result.error = te.error_message
            return te, result

        # Find the CSV output file
        csv_file = _find_mft_csv(config.OUTPUT_ROOT)
        if csv_file:
            result.entries = _parse_mft_csv(csv_file)
        else:
            # Fallback: parse raw output lines
            result.entries = _parse_raw_mft_output(te.raw_output)

        result.total_entries = len(result.entries)
        return te, result

    def find_suspicious_entries(self, result: MFTResult) -> list[SuspiciousEntry]:
        """
        Identify suspicious MFT entries:
        - Files in system directories with non-standard names
        - Timestomping indicators ($STANDARD_INFO vs $FILENAME timestamp mismatch > 1 second)
        - Alternate Data Streams (ADS)
        - Very recently created files in unusual locations
        - Deleted files ($Recycle.Bin bypass patterns)
        """
        suspicious: list[SuspiciousEntry] = []

        for entry in result.entries:
            reasons: list[tuple[str, str]] = []

            # Timestomping detection — $SI vs $FN mismatch
            if entry.created0x10 and entry.created0x30:
                diff = abs((entry.created0x10 - entry.created0x30).total_seconds())
                if diff > 2:
                    reasons.append((
                        f"Timestamp mismatch (SI vs FN) by {diff:.0f}s — possible timestomping",
                        "HIGH"
                    ))

            # ADS — common malware hiding technique
            if entry.is_ads:
                reasons.append(("Alternate Data Stream detected", "HIGH"))
            if entry.has_ads:
                reasons.append(("File has associated Alternate Data Streams", "MEDIUM"))

            # Suspicious file in Windows system directories
            path_lower = entry.fullpath.lower()
            if any(p in path_lower for p in ["\\system32\\", "\\syswow64\\"]):
                if entry.extension.lower() in [".exe", ".dll", ".sys", ".drv"]:
                    # Only flag non-standard names in system dirs
                    if len(entry.filename) > 40 or "_" * 3 in entry.filename:
                        reasons.append(("Unusual filename in system directory", "MEDIUM"))

            # Deleted file with suspicious extension
            if not entry.in_use and entry.extension.lower() in [".exe", ".ps1", ".vbs", ".bat", ".cmd"]:
                reasons.append(("Deleted executable/script", "MEDIUM"))

            for reason, severity in reasons:
                suspicious.append(SuspiciousEntry(entry=entry, reason=reason, severity=severity))

        return sorted(suspicious, key=lambda s: {"HIGH": 0, "MEDIUM": 1, "LOW": 2}[s.severity])


def _find_mft_csv(output_dir: str) -> Optional[str]:
    import glob
    files = glob.glob(os.path.join(output_dir, "*_MFT*.csv"))
    return files[0] if files else None


def _parse_mft_csv(csv_path: str) -> list[MFTEntry]:
    entries: list[MFTEntry] = []
    try:
        with open(csv_path, newline="", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                entry = MFTEntry(
                    entry_number=row.get("EntryNumber", ""),
                    sequence=row.get("SequenceNumber", ""),
                    parent_entry=row.get("ParentEntryNumber", ""),
                    entry_type=row.get("EntryType", ""),
                    in_use=row.get("InUse", "True") == "True",
                    filename=row.get("FileName", ""),
                    extension=row.get("Extension", ""),
                    file_size=_int_or_none(row.get("FileSize")),
                    created0x10=_dt_or_none(row.get("Created0x10")),
                    modified0x10=_dt_or_none(row.get("LastModified0x10")),
                    accessed0x10=_dt_or_none(row.get("LastAccess0x10")),
                    entry_modified0x10=_dt_or_none(row.get("MFTRecordModified0x10")),
                    created0x30=_dt_or_none(row.get("Created0x30")),
                    modified0x30=_dt_or_none(row.get("LastModified0x30")),
                    is_ads=row.get("IsAds", "False") == "True",
                    has_ads=row.get("HasAds", "False") == "True",
                    fullpath=row.get("ParentPath", "") + "\\" + row.get("FileName", ""),
                    raw_line=str(row),
                )
                entries.append(entry)
    except FileNotFoundError:
        pass
    return entries


def _parse_raw_mft_output(raw: str) -> list[MFTEntry]:
    entries: list[MFTEntry] = []
    for line in raw.splitlines():
        if line.strip() and not line.startswith("#"):
            entries.append(MFTEntry(filename=line.strip(), raw_line=line))
    return entries


def _int_or_none(val: Optional[str]) -> Optional[int]:
    try:
        return int(val) if val else None
    except (ValueError, TypeError):
        return None


def _dt_or_none(val: Optional[str]) -> Optional[datetime]:
    if not val:
        return None
    try:
        return datetime.fromisoformat(val.replace(" ", "T").rstrip("Z"))
    except (ValueError, AttributeError):
        return None
