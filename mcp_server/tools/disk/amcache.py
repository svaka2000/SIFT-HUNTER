"""
AmcacheParser wrapper — parses the Windows Amcache.hve registry hive.
Reveals program installation, first execution, and SHA1 hashes for threat intel lookups.
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


class InstalledProgram(BaseModel):
    program_name: str = ""
    version: str = ""
    publisher: str = ""
    install_date: Optional[datetime] = None
    path: str = ""
    sha1: str = ""
    file_id: str = ""
    is_os_component: bool = False
    raw_line: str = ""


class AmcacheResult(BaseModel):
    programs: list[InstalledProgram] = []
    total_count: int = 0
    error: Optional[str] = None


class AmcacheTool(BaseTool):
    tool_name = "AmcacheParser"

    def _build_command(self, evidence_path: str, args: dict[str, Any]) -> list[str]:
        output_dir = args.get("output_dir", config.OUTPUT_ROOT)
        return [
            "AmcacheParser.exe" if os.name == "nt" else "amcacheparser",
            "-f", evidence_path,
            "--csv", output_dir,
            "-i", "on",
        ]

    def parse_amcache(
        self,
        amcache_path: str,
        agent: str = "system",
        phase: str = "disk",
        iteration: int = 0,
    ) -> tuple[ToolExecution, AmcacheResult]:
        config.ensure_output_dir()
        te = self.run(
            amcache_path,
            agent=agent,
            phase=phase,
            iteration=iteration,
            extra_args={"output_dir": config.OUTPUT_ROOT},
        )
        result = AmcacheResult()
        if te.exit_code != 0 and not te.raw_output:
            result.error = te.error_message
            return te, result

        csv_file = _find_amcache_csv(config.OUTPUT_ROOT)
        if csv_file:
            result.programs = _parse_amcache_csv(csv_file)
        else:
            result.programs = _parse_raw_amcache(te.raw_output)

        result.total_count = len(result.programs)
        return te, result

    def find_recently_installed(
        self,
        result: AmcacheResult,
        days: int = 30,
    ) -> list[InstalledProgram]:
        """Return programs installed within the last N days — useful for finding dropper artifacts."""
        from datetime import timezone
        cutoff = datetime.utcnow()
        recent: list[InstalledProgram] = []
        for prog in result.programs:
            if prog.install_date:
                # Handle both timezone-aware and naive datetimes
                install = prog.install_date
                if install.tzinfo:
                    install = install.replace(tzinfo=None)
                if (cutoff - install).days <= days:
                    recent.append(prog)
        return sorted(recent, key=lambda p: p.install_date or datetime.min, reverse=True)

    def get_hashes_for_lookup(self, result: AmcacheResult) -> list[str]:
        """Return all SHA1 hashes from Amcache entries — feed to VirusTotal."""
        return [p.sha1 for p in result.programs if p.sha1 and not p.is_os_component]


def _find_amcache_csv(output_dir: str) -> Optional[str]:
    files = glob.glob(os.path.join(output_dir, "*Amcache*Entries*.csv"))
    if not files:
        files = glob.glob(os.path.join(output_dir, "*Amcache*.csv"))
    return files[0] if files else None


def _parse_amcache_csv(csv_path: str) -> list[InstalledProgram]:
    programs: list[InstalledProgram] = []
    try:
        with open(csv_path, newline="", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                programs.append(InstalledProgram(
                    program_name=row.get("Name", row.get("ApplicationName", "")),
                    version=row.get("Version", ""),
                    publisher=row.get("Publisher", ""),
                    install_date=_dt_or_none(row.get("InstallDate", row.get("FileKeyLastWriteTimestamp", ""))),
                    path=row.get("UninstallString", row.get("FullPath", "")),
                    sha1=row.get("SHA1", row.get("Hash", "")),
                    file_id=row.get("FileId", ""),
                    is_os_component=row.get("IsOsComponent", "False") == "True",
                    raw_line=str(row),
                ))
    except FileNotFoundError:
        pass
    return programs


def _parse_raw_amcache(raw: str) -> list[InstalledProgram]:
    programs: list[InstalledProgram] = []
    for line in raw.splitlines():
        if line.strip() and ":" in line:
            programs.append(InstalledProgram(program_name=line.strip(), raw_line=line))
    return programs


def _dt_or_none(val: Optional[str]) -> Optional[datetime]:
    if not val:
        return None
    try:
        return datetime.fromisoformat(val.replace(" ", "T").rstrip("Z"))
    except (ValueError, AttributeError):
        return None
