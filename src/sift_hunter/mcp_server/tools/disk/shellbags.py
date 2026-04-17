"""ShellBags analysis — wraps SBECmd."""
from __future__ import annotations
from pathlib import Path
from typing import Any

from sift_hunter.mcp_server.tools.base import BaseTool
from sift_hunter.mcp_server.tools.output_parser import parse_ez_csv_file


class ShellBagsTool(BaseTool):
    tool_name = "shellbags_parser"
    binary_name = "SBECmd"
    description = "Parse Windows ShellBags to recover folder navigation history"

    def analyze(self, hive_path: str, output_dir: str) -> dict[str, Any]:
        src = Path(hive_path)
        out = Path(output_dir)
        result = self._execute(
            args=["-d", str(src), "--csv", str(out), "--csvf", "shellbags.csv"],
            evidence_path=src,
            output_dir=out,
        )
        entries = []
        if result.success and (out / "shellbags.csv").exists():
            entries = parse_ez_csv_file(str(out / "shellbags.csv"))
        return {"entries": entries, "raw": result.stdout[:1000], "tool": "SBECmd", "source": str(src)}

    def find_external_access(self, entries: list[dict]) -> list[dict]:
        findings = []
        for e in entries:
            path = (e.get("AbsolutePath") or e.get("Value") or "").upper()
            if any(d in path for d in [r"USB", r"REMOVABLE", r"E:\\", r"F:\\"]):
                findings.append({"type": "EXTERNAL_DRIVE_ACCESS", "path": path, "entry": e})
            if "\\\\NETWORK\\" in path or path.startswith("\\\\"):
                findings.append({"type": "NETWORK_PATH_ACCESS", "path": path, "entry": e})
        return findings
