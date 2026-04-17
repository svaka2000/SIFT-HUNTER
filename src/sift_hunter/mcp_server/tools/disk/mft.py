"""MFT parser wrapper around MFTECmd with timestomping detection."""
from __future__ import annotations

import csv
import io
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from sift_hunter.mcp_server.tools.base import BaseTool
from sift_hunter.mcp_server.tools.executor import SafeExecutor
from sift_hunter.mcp_server.tools.output_parser import parse_ez_csv


@dataclass
class MFTEntry:
    """A single MFT entry."""
    entry_number: str = ""
    file_name: str = ""
    parent_path: str = ""
    file_size: str = ""
    created_si: str = ""   # $STANDARD_INFORMATION
    created_fn: str = ""   # $FILE_NAME
    modified_si: str = ""
    modified_fn: str = ""
    in_use: str = ""
    is_directory: bool = False
    raw: dict = field(default_factory=dict)


@dataclass
class MFTResult:
    """Results of MFT parsing."""
    entries: list[MFTEntry] = field(default_factory=list)
    total_entries: int = 0
    suspicious_count: int = 0
    tool_available: bool = True
    raw_output: str = ""
    error: str = ""


class MFTTool(BaseTool):
    """Wrapper around MFTECmd for MFT parsing and timestomping detection."""

    tool_name = "mft_parser"
    binary_name = "MFTECmd"
    description = "Parse MFT and detect timestomping (SI vs FN timestamp comparison)"

    def analyze(self, mft_path: str, output_dir: str = "/tmp/sift-output") -> dict:
        """Parse MFT file. Returns dict with entries and suspicious findings."""
        if not self.is_available():
            return self._analyze_text_fallback(mft_path)

        Path(output_dir).mkdir(parents=True, exist_ok=True)
        result = self._execute(
            ["-f", mft_path, "--csv", output_dir, "--csvf", "mft_output.csv", "-q"],
            evidence_path=mft_path,
            output_dir=output_dir,
        )

        if not result.success:
            return {"error": result.stderr, "tool_available": True, "entries": []}

        # Parse the CSV output
        csv_path = Path(output_dir) / "mft_output.csv"
        entries = self.parse_csv(str(csv_path))
        suspicious = self.find_suspicious(entries)
        return {
            "total_entries": len(entries),
            "suspicious": suspicious,
            "tool_available": True,
            "raw_output": result.stdout[:2000],
        }

    def parse_csv(self, csv_path: str) -> list[dict]:
        """Parse MFTECmd CSV output into list of entry dicts."""
        rows = parse_ez_csv(Path(csv_path).read_text(errors="replace") if Path(csv_path).exists() else "")
        return rows

    def parse_mft(self, mft_path: str, agent: str = "", phase: str = "") -> tuple:
        """Parse MFT. Returns (ToolExecution, list[dict]) for agent compatibility."""
        result = self._execute(["-f", mft_path, "-q"], evidence_path=mft_path)
        from sift_hunter.core.models import ToolExecution
        te = ToolExecution(
            tool_name=self.tool_name, binary=self.binary_name,
            raw_output=result.stdout[:8000], output_summary=result.stdout[:500],
            exit_code=result.exit_code, success=result.success,
            duration_seconds=result.duration_seconds,
        )
        return te, result.stdout

    def find_suspicious_entries(self, data: object) -> list[dict]:
        """Wrapper for legacy calling convention."""
        if isinstance(data, str):
            rows = parse_ez_csv(data)
        elif isinstance(data, list):
            rows = data
        else:
            rows = []
        return self.find_suspicious(rows)

    def find_suspicious(self, entries: list[dict]) -> list[dict]:
        """Detect timestomping (SI != FN) and suspicious file locations."""
        suspicious = []
        for e in entries:
            flags = []
            # Timestomping: $STANDARD_INFORMATION differs from $FILE_NAME
            si_created = e.get("Created0x10", "")
            fn_created = e.get("Created0x30", "")
            if si_created and fn_created and si_created != fn_created:
                flags.append(f"TIMESTOMPING: SI={si_created} FN={fn_created}")

            # Suspicious path
            path = e.get("ParentPath", "") + "\\" + e.get("FileName", "")
            for sus in ["\\Temp\\", "\\AppData\\", "\\Downloads\\", "$Recycle"]:
                if sus.lower() in path.lower():
                    flags.append(f"SUSPICIOUS_LOCATION: {path}")
                    break

            if flags:
                entry = dict(e)
                entry["_flags"] = flags
                suspicious.append(entry)
        return suspicious

    def _analyze_text_fallback(self, mft_path: str) -> dict:
        """Fallback: read pre-exported MFT CSV text file."""
        p = Path(mft_path)
        if p.exists() and p.suffix.lower() == ".csv":
            rows = parse_ez_csv(p.read_text(errors="replace"))
            suspicious = self.find_suspicious(rows)
            return {"total_entries": len(rows), "suspicious": suspicious,
                    "tool_available": False, "raw_output": p.read_text(errors="replace")[:2000]}
        return {"error": "MFTECmd not available and no CSV export found",
                "tool_available": False, "entries": []}

    def list_processes(self, path: str, agent: str = "", phase: str = "") -> tuple:
        """Stub for interface compatibility."""
        return self._execute(["-f", path], evidence_path=path), []
