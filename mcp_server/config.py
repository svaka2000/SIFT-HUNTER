"""
SIFT-HUNTER MCP Server configuration.
All tunable parameters live here — no hardcoded paths elsewhere.
"""

from __future__ import annotations

import os
from pathlib import Path


class ServerConfig:
    # Evidence directories the server is allowed to read from
    EVIDENCE_ROOTS: list[str] = os.environ.get(
        "SIFT_EVIDENCE_ROOTS", "/cases:/mnt/evidence:/tmp/sift-evidence"
    ).split(":")

    # Maximum raw output size returned per tool call (bytes) — prevents OOM
    MAX_OUTPUT_SIZE: int = int(os.environ.get("SIFT_MAX_OUTPUT_SIZE", str(10 * 1024 * 1024)))

    # Output/staging directory for intermediate files (timeline CSVs, etc.)
    OUTPUT_ROOT: str = os.environ.get("SIFT_OUTPUT_ROOT", "/tmp/sift-output")

    # Audit log location
    AUDIT_LOG_PATH: str = os.environ.get("SIFT_AUDIT_LOG", "/tmp/sift-hunter-audit.jsonl")

    # Optional threat intel API keys
    VT_API_KEY: str = os.environ.get("VT_API_KEY", "")
    ABUSEIPDB_API_KEY: str = os.environ.get("ABUSEIPDB_API_KEY", "")

    # LLM provider: "anthropic" or "groq"
    LLM_PROVIDER: str = os.environ.get("SIFT_LLM_PROVIDER", "groq" if os.environ.get("GROQ_API_KEY") else "anthropic")

    # Anthropic API key (optional if using Groq)
    ANTHROPIC_API_KEY: str = os.environ.get("ANTHROPIC_API_KEY", "")

    # Groq API key
    GROQ_API_KEY: str = os.environ.get("GROQ_API_KEY", "")

    # Model to use — auto-selects based on provider
    MODEL: str = os.environ.get(
        "SIFT_MODEL",
        "llama-3.3-70b-versatile" if os.environ.get("GROQ_API_KEY") else "claude-opus-4-7-20250514"
    )

    # Max LangGraph iterations before forcing reporter
    MAX_ITERATIONS: int = int(os.environ.get("SIFT_MAX_ITERATIONS", "50"))

    # Max self-correction loops per finding before forcing accept
    MAX_CORRECTION_LOOPS: int = int(os.environ.get("SIFT_MAX_CORRECTION_LOOPS", "3"))

    # MITRE ATT&CK STIX bundle cache
    MITRE_CACHE_PATH: str = os.environ.get(
        "SIFT_MITRE_CACHE", str(Path.home() / ".sift-hunter" / "mitre-attack.json")
    )

    # Server host/port for stdio vs TCP mode
    SERVER_HOST: str = os.environ.get("SIFT_HOST", "0.0.0.0")
    SERVER_PORT: int = int(os.environ.get("SIFT_PORT", "8765"))

    @classmethod
    def ensure_output_dir(cls) -> None:
        Path(cls.OUTPUT_ROOT).mkdir(parents=True, exist_ok=True)

    @classmethod
    def validate(cls) -> list[str]:
        """Return list of configuration warnings (not errors — degrade gracefully)."""
        warnings: list[str] = []
        if not cls.ANTHROPIC_API_KEY and not cls.GROQ_API_KEY:
            warnings.append("No LLM API key set (ANTHROPIC_API_KEY or GROQ_API_KEY) — agent calls will fail.")
        if not cls.VT_API_KEY:
            warnings.append("VT_API_KEY not set — VirusTotal enrichment disabled.")
        if not cls.ABUSEIPDB_API_KEY:
            warnings.append("ABUSEIPDB_API_KEY not set — AbuseIPDB enrichment disabled.")
        for root in cls.EVIDENCE_ROOTS:
            if not Path(root).exists():
                warnings.append(f"Evidence root does not exist: {root}")
        return warnings


config = ServerConfig()

# Module-level alias for convenient import
MAX_CORRECTION_LOOPS: int = config.MAX_CORRECTION_LOOPS
