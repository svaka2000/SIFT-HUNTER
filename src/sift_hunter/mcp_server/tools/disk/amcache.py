"""Amcache analysis tool - wraps AmcacheParser / RECmd."""
from __future__ import annotations
from pathlib import Path
from typing import Any

from sift_hunter.mcp_server.tools.base import BaseTool
from sift_hunter.mcp_server.tools.output_parser import parse_ez_csv_file


class AmcacheTool(BaseTool):
    tool_name = "amcache_parser"
    binary_name = "AmcacheParser"
    description = "Parse Amcache.hve to recover file execution and installation history"

    def analyze(self, amcache_path: str, output_dir: str) -> dict[str, Any]:
        src = Path(amcache_path)
        out = Path(output_dir)
        result = self._execute(
            args=["-f", str(src), "--csv", str(out), "--csvf", "amcache.csv"],
            evidence_path=src,
            output_dir=out,
        )
        if not result.success:
            return {"entries": [], "raw": result.stderr[:500], "tool": "AmcacheParser_unavailable", "source": str(src)}
        entries = parse_ez_csv_file(str(out / "amcache.csv")) if (out / "amcache.csv").exists() else []
        return {"entries": entries, "raw": result.stdout[:1000], "tool": "AmcacheParser", "source": str(src)}

    def find_suspicious(self, entries: list[dict]) -> list[dict]:
        flags = []
        for e in entries:
            path = (e.get("FullPath") or e.get("FilePath") or "").lower()
            name = (e.get("Name") or e.get("FileName") or "").lower()
            issues = []
            if any(s in path for s in ["\\temp\\", "\\tmp\\", "\\appdata\\local\\temp"]):
                issues.append(f"EXECUTED_FROM_TEMP: {path}")
            sha256 = e.get("SHA256") or e.get("Hash") or ""
            if sha256:
                issues.append(f"HASH_AVAILABLE_FOR_VT: {sha256}")
            if issues:
                flags.append({"path": path, "name": name, "issues": issues, "entry": e})
        return flags
