"""
ShellBags parser (SBECmd wrapper) — tracks folder navigation history.
Reveals attacker reconnaissance: which directories they browsed, when, and from where.
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


class ShellbagEntry(BaseModel):
    path: str = ""
    slot_modified: Optional[datetime] = None
    first_interacted: Optional[datetime] = None
    last_interacted: Optional[datetime] = None
    extension: str = ""
    absolute_path: str = ""
    notes: str = ""
    raw_line: str = ""


class ShellbagTool(BaseTool):
    tool_name = "SBECmd"

    def _build_command(self, evidence_path: str, args: dict[str, Any]) -> list[str]:
        output_dir = args.get("output_dir", config.OUTPUT_ROOT)
        return [
            "SBECmd.exe" if os.name == "nt" else "sbecmd",
            "-d", evidence_path,
            "--csv", output_dir,
            "-q",
        ]

    def parse_shellbags(
        self,
        hive_path: str,
        agent: str = "system",
        phase: str = "disk",
        iteration: int = 0,
    ) -> tuple[ToolExecution, list[ShellbagEntry]]:
        config.ensure_output_dir()
        te = self.run(
            hive_path,
            agent=agent,
            phase=phase,
            iteration=iteration,
            extra_args={"output_dir": config.OUTPUT_ROOT},
        )

        csv_file = _find_shellbag_csv(config.OUTPUT_ROOT)
        if csv_file:
            entries = _parse_shellbag_csv(csv_file)
        else:
            entries = _parse_raw_shellbag(te.raw_output)

        return te, entries

    def find_suspicious_navigation(self, entries: list[ShellbagEntry]) -> list[ShellbagEntry]:
        """Find navigation to unusual locations — network shares, temp dirs, USB devices."""
        suspicious: list[ShellbagEntry] = []
        for entry in entries:
            path_lower = entry.path.lower() + entry.absolute_path.lower()
            if any([
                "\\\\" in entry.path,  # Network share access
                "usb" in path_lower,
                "\\temp\\" in path_lower,
                "\\$recycle" in path_lower,
                ":\\users\\public\\" in path_lower,
                "ftp:" in path_lower,
                "http:" in path_lower,
            ]):
                suspicious.append(entry)
        return suspicious


def _find_shellbag_csv(output_dir: str) -> Optional[str]:
    files = glob.glob(os.path.join(output_dir, "*SBECmd*.csv"))
    if not files:
        files = glob.glob(os.path.join(output_dir, "*Shellbag*.csv"))
    return files[0] if files else None


def _parse_shellbag_csv(csv_path: str) -> list[ShellbagEntry]:
    entries: list[ShellbagEntry] = []
    try:
        with open(csv_path, newline="", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                entries.append(ShellbagEntry(
                    path=row.get("AbsolutePath", row.get("Value", "")),
                    slot_modified=_dt_or_none(row.get("SlotModifiedOn", "")),
                    first_interacted=_dt_or_none(row.get("FirstInteracted", "")),
                    last_interacted=_dt_or_none(row.get("LastInteracted", "")),
                    absolute_path=row.get("AbsolutePath", ""),
                    notes=row.get("Notes", ""),
                    raw_line=str(row),
                ))
    except FileNotFoundError:
        pass
    return entries


def _parse_raw_shellbag(raw: str) -> list[ShellbagEntry]:
    entries: list[ShellbagEntry] = []
    for line in raw.splitlines():
        if line.strip():
            entries.append(ShellbagEntry(path=line.strip(), raw_line=line))
    return entries


def _dt_or_none(val: Optional[str]) -> Optional[datetime]:
    if not val:
        return None
    try:
        return datetime.fromisoformat(val.replace(" ", "T").rstrip("Z"))
    except (ValueError, AttributeError):
        return None
