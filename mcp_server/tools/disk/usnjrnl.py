"""
USN Journal parser — tracks file system changes including file deletions.
Critical for proving files were created, modified, and deleted during an incident.
"""

from __future__ import annotations

import csv
import glob
import os
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel

from core.models import ToolExecution
from mcp_server.config import config
from mcp_server.tools.base import BaseTool


class USNRecord(BaseModel):
    timestamp: Optional[datetime] = None
    filename: str = ""
    fullpath: str = ""
    reason: str = ""
    file_attributes: str = ""
    entry_number: str = ""
    parent_entry: str = ""
    raw_line: str = ""


class DeletionEvent(BaseModel):
    timestamp: Optional[datetime]
    filename: str
    fullpath: str
    suspected_attacker_action: str = ""


class USNResult(BaseModel):
    records: list[USNRecord] = []
    total_records: int = 0
    error: Optional[str] = None


# USN reason codes that indicate deletion/overwrite
DELETION_REASONS = {
    "FILE_DELETE", "RENAME_OLD_NAME", "HARD_LINK_CHANGE",
    "OBJECT_ID_CHANGE", "STREAM_CHANGE",
}

SUSPICIOUS_DELETION_PATTERNS = [
    ".exe", ".dll", ".sys", ".ps1", ".vbs", ".bat", ".cmd",
    ".lnk", ".log", ".evtx",
]


class USNJournalTool(BaseTool):
    tool_name = "MFTECmd-USN"

    def _build_command(self, evidence_path: str, args: dict[str, Any]) -> list[str]:
        output_dir = args.get("output_dir", config.OUTPUT_ROOT)
        return [
            "MFTECmd.exe" if os.name == "nt" else "mftecmd",
            "-f", evidence_path,
            "--csv", output_dir,
            "--usn",
        ]

    def parse_usn_journal(
        self,
        usn_path: str,
        agent: str = "system",
        phase: str = "disk",
        iteration: int = 0,
    ) -> tuple[ToolExecution, USNResult]:
        config.ensure_output_dir()
        te = self.run(
            usn_path,
            agent=agent,
            phase=phase,
            iteration=iteration,
            extra_args={"output_dir": config.OUTPUT_ROOT},
        )
        result = USNResult()
        if te.exit_code != 0 and not te.raw_output:
            result.error = te.error_message
            return te, result

        csv_file = _find_usn_csv(config.OUTPUT_ROOT)
        if csv_file:
            result.records = _parse_usn_csv(csv_file)
        else:
            result.records = _parse_raw_usn(te.raw_output)

        result.total_records = len(result.records)
        return te, result

    def find_file_deletions(self, result: USNResult) -> list[DeletionEvent]:
        """Find file deletion events, especially for executables and logs."""
        deletions: list[DeletionEvent] = []
        for record in result.records:
            reason_upper = record.reason.upper()
            if any(r in reason_upper for r in DELETION_REASONS):
                ext = os.path.splitext(record.filename)[1].lower()
                action = ""
                if ".evtx" in record.filename.lower() or ".log" in record.filename.lower():
                    action = "Log/Event file deletion — possible anti-forensics (T1070.001)"
                elif ext in SUSPICIOUS_DELETION_PATTERNS:
                    action = f"Executable/script deletion — evidence removal (T1070)"
                else:
                    action = f"File deletion: {record.reason}"

                deletions.append(DeletionEvent(
                    timestamp=record.timestamp,
                    filename=record.filename,
                    fullpath=record.fullpath,
                    suspected_attacker_action=action,
                ))
        return sorted(deletions, key=lambda d: d.timestamp or datetime.min)


def _find_usn_csv(output_dir: str) -> Optional[str]:
    files = glob.glob(os.path.join(output_dir, "*UsnJrnl*.csv"))
    if not files:
        files = glob.glob(os.path.join(output_dir, "*J*.csv"))
    return files[0] if files else None


def _parse_usn_csv(csv_path: str) -> list[USNRecord]:
    records: list[USNRecord] = []
    try:
        with open(csv_path, newline="", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                records.append(USNRecord(
                    timestamp=_dt_or_none(row.get("Timestamp", row.get("UpdateTimestamp", ""))),
                    filename=row.get("Name", row.get("FileName", "")),
                    fullpath=row.get("ParentPath", "") + "\\" + row.get("Name", ""),
                    reason=row.get("Reason", row.get("UpdateReasons", "")),
                    file_attributes=row.get("FileAttributes", ""),
                    entry_number=row.get("EntryNumber", ""),
                    parent_entry=row.get("ParentEntryNumber", ""),
                    raw_line=str(row),
                ))
    except FileNotFoundError:
        pass
    return records


def _parse_raw_usn(raw: str) -> list[USNRecord]:
    records: list[USNRecord] = []
    for line in raw.splitlines():
        if line.strip():
            records.append(USNRecord(filename=line.strip(), raw_line=line))
    return records


def _dt_or_none(val: Optional[str]) -> Optional[datetime]:
    if not val:
        return None
    try:
        return datetime.fromisoformat(val.replace(" ", "T").rstrip("Z"))
    except (ValueError, AttributeError):
        return None
