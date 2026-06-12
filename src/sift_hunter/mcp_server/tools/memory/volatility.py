"""Volatility3 base wrapper - runs arbitrary plugins and returns structured output."""
from __future__ import annotations
import shutil
from pathlib import Path
from typing import Any

from sift_hunter.mcp_server.tools.base import BaseTool
from sift_hunter.mcp_server.tools.output_parser import parse_volatility_text, parse_volatility_json


_VOL_BINARIES = ["vol3", "vol", "volatility3", "volatility"]


class VolatilityTool(BaseTool):
    tool_name = "volatility"
    binary_name = "vol3"
    description = "Volatility3 memory analysis framework - run any plugin against a memory image"

    def _find_vol_binary(self) -> str | None:
        for b in _VOL_BINARIES:
            p = shutil.which(b)
            if p:
                return b
        return None

    def is_available(self) -> bool:
        return self._find_vol_binary() is not None

    def run_plugin(self, memory_image: str, plugin: str, extra_args: list[str] | None = None) -> dict[str, Any]:
        binary = self._find_vol_binary() or "vol3"
        src = Path(memory_image)
        args = ["-f", str(src), plugin]
        if extra_args:
            args += extra_args
        result = self._execute(args=args, evidence_path=src, output_dir=None)
        if not result.success:
            return {"rows": [], "raw": result.stderr[:1000], "plugin": plugin, "success": False}
        rows = parse_volatility_text(result.stdout)
        return {"rows": rows, "raw": result.stdout[:3000], "plugin": plugin, "success": True}

    def run_plugin_json(self, memory_image: str, plugin: str) -> dict[str, Any]:
        src = Path(memory_image)
        args = ["-f", str(src), "-r", "json", plugin]
        result = self._execute(args=args, evidence_path=src, output_dir=None)
        rows = parse_volatility_json(result.stdout) if result.success else []
        return {"rows": rows, "raw": result.stdout[:3000], "plugin": plugin, "success": result.success}

    def list_plugins(self, memory_image: str) -> list[str]:
        src = Path(memory_image)
        result = self._execute(args=["-f", str(src), "--help"], evidence_path=src, output_dir=None)
        plugins = []
        for line in result.stdout.splitlines():
            stripped = line.strip()
            if "." in stripped and stripped[0].isupper():
                plugins.append(stripped.split()[0])
        return plugins
