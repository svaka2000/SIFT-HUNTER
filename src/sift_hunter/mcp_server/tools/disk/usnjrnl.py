"""USN Journal analysis — wraps MFTECmd in USN mode."""
from __future__ import annotations
from pathlib import Path
from typing import Any

from sift_hunter.mcp_server.tools.base import BaseTool
from sift_hunter.mcp_server.tools.output_parser import parse_ez_csv_file

DELETION_REASONS = {"0x80000200", "0x00000200", "DELETE", "FILE_DELETE"}


class USNJournalTool(BaseTool):
    tool_name = "usn_journal_parser"
    binary_name = "MFTECmd"
    description = "Parse NTFS USN Journal ($UsnJrnl) to recover file creation, modification and deletion events"

    def analyze(self, usn_path: str, output_dir: str) -> dict[str, Any]:
        src = Path(usn_path)
        out = Path(output_dir)
        result = self._execute(
            args=["-f", str(src), "--csv", str(out), "--csvf", "usnjrnl.csv"],
            evidence_path=src,
            output_dir=out,
        )
        entries = []
        if result.success and (out / "usnjrnl.csv").exists():
            entries = parse_ez_csv_file(str(out / "usnjrnl.csv"))
        return {"entries": entries, "raw": result.stdout[:1000], "tool": "MFTECmd_USN", "source": str(src)}

    def find_deletions(self, entries: list[dict]) -> list[dict]:
        deletions = []
        for e in entries:
            reason = (e.get("Reason") or e.get("UpdateReasons") or "").upper()
            if any(d in reason for d in DELETION_REASONS):
                name = e.get("FileName") or e.get("Name") or ""
                deletions.append({
                    "type": "FILE_DELETION",
                    "filename": name,
                    "timestamp": e.get("UpdateTimestamp") or e.get("TimeStamp") or "",
                    "reason": reason,
                    "entry": e,
                })
        return deletions

    def find_suspicious_renames(self, entries: list[dict]) -> list[dict]:
        renames = []
        for e in entries:
            reason = (e.get("Reason") or "").upper()
            if "RENAME" in reason:
                name = e.get("FileName") or ""
                renames.append({"type": "FILE_RENAME", "filename": name, "reason": reason, "entry": e})
        return renames
