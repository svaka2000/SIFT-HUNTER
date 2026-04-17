"""
PECmd wrapper — parses Windows Prefetch files.
Reveals program execution history with timestamps and file references.
Critical for proving execution of malware even after deletion.
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


class PrefetchEntry(BaseModel):
    executable: str = ""
    hash_value: str = ""
    run_count: int = 0
    last_run: Optional[datetime] = None
    previous_runs: list[datetime] = []
    volume_serial: str = ""
    volume_created: Optional[datetime] = None
    referenced_files: list[str] = []
    referenced_directories: list[str] = []
    raw_line: str = ""


class ExecutionTimeline(BaseModel):
    events: list[dict] = []
    suspicious_executables: list[str] = []
    total_entries: int = 0


class PrefetchTool(BaseTool):
    tool_name = "PECmd"

    def _build_command(self, evidence_path: str, args: dict[str, Any]) -> list[str]:
        output_dir = args.get("output_dir", config.OUTPUT_ROOT)
        return [
            "PECmd.exe" if os.name == "nt" else "pecmd",
            "-d", evidence_path,
            "--csv", output_dir,
            "-q",
        ]

    def parse_prefetch(
        self,
        prefetch_dir: str,
        agent: str = "system",
        phase: str = "disk",
        iteration: int = 0,
    ) -> tuple[ToolExecution, list[PrefetchEntry]]:
        config.ensure_output_dir()
        te = self.run(
            prefetch_dir,
            agent=agent,
            phase=phase,
            iteration=iteration,
            extra_args={"output_dir": config.OUTPUT_ROOT},
        )

        csv_file = _find_prefetch_csv(config.OUTPUT_ROOT)
        if csv_file:
            entries = _parse_prefetch_csv(csv_file)
        else:
            entries = _parse_raw_prefetch(te.raw_output)

        return te, entries

    def find_execution_artifacts(
        self,
        entries: list[PrefetchEntry],
        suspicious_extensions: Optional[list[str]] = None,
    ) -> ExecutionTimeline:
        if suspicious_extensions is None:
            suspicious_extensions = [".exe", ".ps1", ".vbs", ".bat", ".cmd", ".scr", ".pif"]

        suspicious_exes: list[str] = []
        events: list[dict] = []

        for entry in entries:
            exe_lower = entry.executable.lower()

            # Flag executables in suspicious locations (temp dirs, user profile, etc.)
            is_suspicious = any([
                "\\temp\\" in exe_lower,
                "\\tmp\\" in exe_lower,
                "\\appdata\\roaming\\" in exe_lower,
                "\\appdata\\local\\temp\\" in exe_lower,
                "\\users\\public\\" in exe_lower,
                "\\recycle\\" in exe_lower,
                "\\downloads\\" in exe_lower,
                # Common LOLBins abused by attackers
                exe_lower.endswith("wscript.exe") and "\\system32\\" not in exe_lower,
                exe_lower.endswith("cscript.exe") and "\\system32\\" not in exe_lower,
                exe_lower.endswith("mshta.exe"),
                exe_lower.endswith("regsvr32.exe") and any(
                    r in exe_lower for r in entry.referenced_files
                    if r.endswith(".dll") and "\\temp\\" in r.lower()
                ),
            ])

            if is_suspicious:
                suspicious_exes.append(entry.executable)

            if entry.last_run:
                events.append({
                    "timestamp": entry.last_run.isoformat(),
                    "executable": entry.executable,
                    "run_count": entry.run_count,
                    "suspicious": is_suspicious,
                })

        events.sort(key=lambda e: e["timestamp"])
        return ExecutionTimeline(
            events=events,
            suspicious_executables=suspicious_exes,
            total_entries=len(entries),
        )


def _find_prefetch_csv(output_dir: str) -> Optional[str]:
    files = glob.glob(os.path.join(output_dir, "*PECmd*.csv"))
    return files[0] if files else None


def _parse_prefetch_csv(csv_path: str) -> list[PrefetchEntry]:
    entries: list[PrefetchEntry] = []
    try:
        with open(csv_path, newline="", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                prev_runs: list[datetime] = []
                for i in range(2, 9):
                    key = f"LastRun{i}"
                    val = row.get(key, "")
                    if val:
                        dt = _dt_or_none(val)
                        if dt:
                            prev_runs.append(dt)

                entries.append(PrefetchEntry(
                    executable=row.get("ExecutableName", ""),
                    hash_value=row.get("Hash", ""),
                    run_count=int(row.get("RunCount", 0) or 0),
                    last_run=_dt_or_none(row.get("LastRun", "")),
                    previous_runs=prev_runs,
                    volume_serial=row.get("VolumeSerialNumbers", ""),
                    referenced_files=row.get("Directories", "").split(",") if row.get("Directories") else [],
                    raw_line=str(row),
                ))
    except FileNotFoundError:
        pass
    return entries


def _parse_raw_prefetch(raw: str) -> list[PrefetchEntry]:
    entries: list[PrefetchEntry] = []
    current: Optional[dict] = None
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("Executable:"):
            if current:
                entries.append(PrefetchEntry(**current))
            current = {"executable": line.split(":", 1)[1].strip()}
        elif current and line.startswith("Run count:"):
            current["run_count"] = int(line.split(":", 1)[1].strip() or 0)
        elif current and line.startswith("Last run:"):
            current["last_run"] = _dt_or_none(line.split(":", 1)[1].strip())
    if current:
        entries.append(PrefetchEntry(**current))
    return entries


def _dt_or_none(val: Optional[str]) -> Optional[datetime]:
    if not val:
        return None
    try:
        return datetime.fromisoformat(val.replace(" ", "T").rstrip("Z"))
    except (ValueError, AttributeError):
        return None
