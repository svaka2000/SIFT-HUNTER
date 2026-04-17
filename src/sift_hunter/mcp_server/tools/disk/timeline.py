"""Timeline generation — wraps log2timeline/plaso (psort)."""
from __future__ import annotations
from pathlib import Path
from typing import Any
import csv
import io

from sift_hunter.mcp_server.tools.base import BaseTool


class TimelineTool(BaseTool):
    tool_name = "timeline_generator"
    binary_name = "log2timeline.py"
    description = "Generate super-timeline from disk image using log2timeline/plaso"

    def create_timeline(self, image_path: str, output_dir: str) -> dict[str, Any]:
        src = Path(image_path)
        out = Path(output_dir)
        plaso_out = out / "timeline.plaso"
        result = self._execute(
            args=[str(plaso_out), str(src)],
            evidence_path=src,
            output_dir=out,
        )
        if not result.success:
            return {"status": "failed", "error": result.stderr[:500], "plaso_file": None}
        return {"status": "created", "plaso_file": str(plaso_out), "raw": result.stdout[:500]}

    def filter_timeline(self, plaso_path: str, output_dir: str, output_format: str = "l2tcsv") -> dict[str, Any]:
        src = Path(plaso_path)
        out = Path(output_dir)
        csv_out = out / "timeline.csv"
        result = self._execute(
            args=["-o", output_format, str(src), str(csv_out)],
            evidence_path=src,
            output_dir=out,
        )
        entries = []
        if result.success and csv_out.exists():
            try:
                with open(csv_out, newline="", encoding="utf-8", errors="replace") as f:
                    reader = csv.DictReader(f)
                    entries = [row for i, row in enumerate(reader) if i < 5000]
            except Exception:
                pass
        return {"entries": entries, "csv_file": str(csv_out), "tool": "psort"}

    def _require_binary(self) -> bool:
        """log2timeline.py availability check."""
        import shutil
        return shutil.which("log2timeline.py") is not None or shutil.which("log2timeline") is not None
