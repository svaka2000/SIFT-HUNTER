"""Global configuration for SIFT-HUNTER."""
from __future__ import annotations

import os


class Config:
    """Central configuration loaded from environment variables."""

    # LLM provider - auto-detect based on available keys
    GROQ_API_KEY: str = os.environ.get("GROQ_API_KEY", "")
    ANTHROPIC_API_KEY: str = os.environ.get("ANTHROPIC_API_KEY", "")
    LLM_PROVIDER: str = os.environ.get(
        "SIFT_LLM_PROVIDER",
        "groq" if os.environ.get("GROQ_API_KEY") else "anthropic",
    )

    # Default model - auto-select based on provider
    MODEL: str = os.environ.get(
        "SIFT_MODEL",
        "llama-3.1-8b-instant" if os.environ.get("GROQ_API_KEY") else "claude-sonnet-4-20250514",
    )

    # Evidence roots - directories the agent is allowed to read
    EVIDENCE_ROOTS: list[str] = [
        r.strip()
        for r in os.environ.get(
            "SIFT_EVIDENCE_ROOTS", "/cases:/mnt/evidence:/tmp/sift-evidence"
        ).split(":")
        if r.strip()
    ]

    # Output directory for reports and timelines
    OUTPUT_ROOT: str = os.environ.get("SIFT_OUTPUT_ROOT", "/tmp/sift-output")

    # Audit log path
    AUDIT_LOG_PATH: str = os.environ.get("SIFT_AUDIT_LOG", "/tmp/sift-hunter-audit.jsonl")

    # Analysis limits
    MAX_ITERATIONS: int = int(os.environ.get("SIFT_MAX_ITERATIONS", "20"))
    MAX_CORRECTION_LOOPS: int = int(os.environ.get("SIFT_MAX_CORRECTION_LOOPS", "3"))

    # Optional enrichment API keys
    VT_API_KEY: str = os.environ.get("VT_API_KEY", "")
    ABUSEIPDB_API_KEY: str = os.environ.get("ABUSEIPDB_API_KEY", "")

    def validate(self) -> list[str]:
        """Return list of warnings about missing configuration."""
        warnings = []
        if not self.GROQ_API_KEY and not self.ANTHROPIC_API_KEY:
            warnings.append(
                "No LLM API key configured. Set GROQ_API_KEY or ANTHROPIC_API_KEY."
            )
        if not self.VT_API_KEY:
            warnings.append("VT_API_KEY not set - VirusTotal enrichment disabled.")
        return warnings


config = Config()
