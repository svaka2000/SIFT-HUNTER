"""Sleuth Kit wrappers — fls, icat, mmls for disk image analysis."""
from __future__ import annotations
from pathlib import Path
from typing import Any
import re

from sift_hunter.mcp_server.tools.base import BaseTool
from sift_hunter.mcp_server.tools.output_parser import parse_sleuthkit_fls


class SleuthKitTool(BaseTool):
    tool_name = "sleuthkit"
    binary_name = "fls"
    description = "Sleuth Kit tools (fls/mmls/icat) for disk image analysis and file recovery"

    def list_files(self, image_path: str, inode: str = "", recursive: bool = True) -> dict[str, Any]:
        src = Path(image_path)
        args = ["-r", "-l"] if recursive else ["-l"]
        if inode:
            args += [str(src), inode]
        else:
            args.append(str(src))
        result = self._execute(args=args, evidence_path=src, output_dir=None)
        entries = parse_sleuthkit_fls(result.stdout) if result.success else []
        return {"entries": entries, "raw": result.stdout[:3000], "tool": "fls"}

    def list_partitions(self, image_path: str) -> dict[str, Any]:
        src = Path(image_path)
        result = self._execute(
            args=[str(src)],
            evidence_path=src,
            output_dir=None,
        )
        partitions = []
        if result.success:
            for line in result.stdout.splitlines():
                m = re.match(r"\s*(\d+):\s+(\d+)\s+(\d+)\s+(\d+)\s+(.*)", line)
                if m:
                    partitions.append({
                        "slot": m.group(1),
                        "start": m.group(2),
                        "end": m.group(3),
                        "length": m.group(4),
                        "description": m.group(5).strip(),
                    })
        return {"partitions": partitions, "raw": result.stdout[:2000], "tool": "mmls"}

    def extract_file(self, image_path: str, inode: str, output_path: str) -> dict[str, Any]:
        src = Path(image_path)
        out = Path(output_path)
        result = self._execute(
            args=[str(src), inode],
            evidence_path=src,
            output_dir=out.parent,
        )
        return {
            "success": result.success,
            "output_path": str(out) if result.success else None,
            "raw": result.stdout[:500],
            "tool": "icat",
        }

    def find_deleted_files(self, entries: list[dict]) -> list[dict]:
        return [e for e in entries if e.get("deleted") or e.get("name", "").startswith("*")]
