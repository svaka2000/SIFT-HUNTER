"""Prefetch analysis tool - wraps PECmd from Eric Zimmerman's tools."""
from __future__ import annotations
import re
from pathlib import Path
from typing import Any

from sift_hunter.mcp_server.tools.base import BaseTool
from sift_hunter.mcp_server.tools.output_parser import parse_ez_csv_file


class PrefetchTool(BaseTool):
    tool_name = "prefetch_parser"
    binary_name = "PECmd"
    description = "Parse Windows Prefetch files to recover execution history"

    def analyze(self, prefetch_dir: str, output_dir: str) -> dict[str, Any]:
        prefetch_path = Path(prefetch_dir)
        out_path = Path(output_dir)
        result = self._execute(
            args=["-d", str(prefetch_path), "--csv", str(out_path), "--csvf", "prefetch.csv"],
            evidence_path=prefetch_path,
            output_dir=out_path,
        )
        if not result.success:
            return self._analyze_text_fallback(prefetch_path)
        csv_file = out_path / "prefetch.csv"
        entries = parse_ez_csv_file(str(csv_file)) if csv_file.exists() else []
        return {"entries": entries, "raw": result.stdout[:2000], "tool": "PECmd", "source": str(prefetch_path)}

    def find_suspicious(self, entries: list[dict]) -> list[dict]:
        flags: list[dict] = []
        for e in entries:
            name = e.get("ExecutableName", "") or e.get("SourceFilename", "")
            run_count = e.get("RunCount", 0)
            try:
                run_count = int(run_count)
            except (ValueError, TypeError):
                run_count = 0
            issues = []
            name_lower = name.lower()
            if any(s in name_lower for s in ["temp", "appdata\\local\\temp", "tmp", "downloads"]):
                issues.append(f"EXECUTION_FROM_TEMP: {name}")
            if re.search(r"svchost|lsass|csrss|winlogon", name_lower):
                if not name_lower.startswith("c:\\windows\\system32"):
                    issues.append(f"PROCESS_MASQUERADING: {name}")
            if run_count > 100:
                issues.append(f"HIGH_EXECUTION_COUNT: {run_count}")
            if issues:
                flags.append({"executable": name, "issues": issues, "entry": e})
        return flags

    def _analyze_text_fallback(self, prefetch_dir: Path) -> dict[str, Any]:
        entries = []
        if prefetch_dir.is_file():
            entries.append({"SourceFilename": str(prefetch_dir), "note": "single file mode"})
        return {"entries": entries, "raw": "", "tool": "PECmd_fallback", "source": str(prefetch_dir)}
