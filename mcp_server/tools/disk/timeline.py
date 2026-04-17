"""
Plaso/log2timeline wrapper — generates super-timelines from disk images.
Returns structured TimelineResult with filtered events.
"""

from __future__ import annotations

import csv
import io
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel

from core.models import ToolExecution
from mcp_server.config import config
from mcp_server.tools.base import BaseTool, run_tool_safe


class TimelineEvent(BaseModel):
    timestamp: Optional[datetime]
    source: str = ""
    source_long: str = ""
    message: str = ""
    filename: str = ""
    event_type: str = ""
    raw_line: str = ""


class TimelineResult(BaseModel):
    events: list[TimelineEvent] = []
    total_events: int = 0
    storage_file: str = ""
    error: Optional[str] = None


class FilteredTimeline(BaseModel):
    events: list[TimelineEvent] = []
    filter_applied: str = ""
    total_matched: int = 0


class TimelineTool(BaseTool):
    tool_name = "log2timeline"

    def _build_command(self, evidence_path: str, args: dict[str, Any]) -> list[str]:
        output_file = args.get("output_file", os.path.join(config.OUTPUT_ROOT, "timeline.plaso"))
        return [
            "log2timeline.py",
            "--storage-file", output_file,
            "--parsers", "win_registry,winevtx,pe,prefetch,lnk,winreg,usnjrnl,filestat",
            "--no-dependencies-check",
            evidence_path,
        ]

    def create_timeline(
        self,
        image_path: str,
        agent: str = "system",
        phase: str = "disk",
        iteration: int = 0,
    ) -> tuple[ToolExecution, TimelineResult]:
        config.ensure_output_dir()
        output_plaso = os.path.join(config.OUTPUT_ROOT, "timeline.plaso")
        output_csv = os.path.join(config.OUTPUT_ROOT, "timeline.csv")

        # Step 1: Create plaso storage file
        te = self.run(
            image_path,
            agent=agent,
            phase=phase,
            iteration=iteration,
            extra_args={"output_file": output_plaso},
        )

        if te.exit_code != 0:
            return te, TimelineResult(error=te.error_message)

        # Step 2: Export to L2T CSV with psort
        psort_cmd = [
            "psort.py",
            "-o", "l2tcsv",
            "-w", output_csv,
            output_plaso,
        ]
        try:
            from mcp_server.security import check_command_safety
            check_command_safety(" ".join(psort_cmd))
            import subprocess
            r = subprocess.run(psort_cmd, capture_output=True, text=True, timeout=300)
            csv_output = r.stdout + r.stderr
        except Exception as e:
            return te, TimelineResult(storage_file=output_plaso, error=str(e))

        result = TimelineResult(storage_file=output_plaso)
        result.events = _parse_l2tcsv(output_csv)
        result.total_events = len(result.events)
        return te, result

    def filter_timeline(
        self,
        csv_path: str,
        keyword: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
    ) -> FilteredTimeline:
        events = _parse_l2tcsv(csv_path)
        filtered = events

        if keyword:
            filtered = [e for e in filtered if keyword.lower() in e.message.lower() or keyword.lower() in e.filename.lower()]

        if start_time:
            try:
                st = datetime.fromisoformat(start_time)
                filtered = [e for e in filtered if e.timestamp and e.timestamp >= st]
            except ValueError:
                pass

        if end_time:
            try:
                et = datetime.fromisoformat(end_time)
                filtered = [e for e in filtered if e.timestamp and e.timestamp <= et]
            except ValueError:
                pass

        return FilteredTimeline(
            events=filtered[:5000],  # Cap at 5000 for context safety
            filter_applied=f"keyword={keyword}, start={start_time}, end={end_time}",
            total_matched=len(filtered),
        )


def _parse_l2tcsv(csv_path: str) -> list[TimelineEvent]:
    """Parse L2T CSV format into TimelineEvent objects."""
    events: list[TimelineEvent] = []
    try:
        with open(csv_path, newline="", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                ts = None
                try:
                    ts_str = row.get("datetime", row.get("date", ""))
                    if ts_str:
                        ts = datetime.fromisoformat(ts_str.replace(" ", "T"))
                except (ValueError, KeyError):
                    pass
                events.append(TimelineEvent(
                    timestamp=ts,
                    source=row.get("type", ""),
                    source_long=row.get("sourcetype", ""),
                    message=row.get("message", row.get("desc", "")),
                    filename=row.get("filename", row.get("source", "")),
                    event_type=row.get("MACB", ""),
                    raw_line=str(row),
                ))
    except FileNotFoundError:
        pass
    return events
