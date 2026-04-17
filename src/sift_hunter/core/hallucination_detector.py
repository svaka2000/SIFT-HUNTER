"""Cross-check agent claims against raw tool output to detect hallucinations."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from sift_hunter.core.models import ConfidenceLevel, Finding, ToolExecution


# Regex patterns for common forensic entities
_FILE_PATH = re.compile(r'[A-Za-z]:\\(?:[^\\\s<>:"/|?*\x00-\x1f]+\\)*[^\\\s<>:"/|?*\x00-\x1f]*')
_UNIX_PATH = re.compile(r'/(?:[^\s<>:"\'|?*\x00-\x1f]+/)*[^\s<>:"\'|?*\x00-\x1f]*')
_IPV4 = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_MD5 = re.compile(r'\b[0-9a-fA-F]{32}\b')
_SHA1 = re.compile(r'\b[0-9a-fA-F]{40}\b')
_SHA256 = re.compile(r'\b[0-9a-fA-F]{64}\b')
_EXE = re.compile(r'\b[\w\-\.]+\.exe\b', re.IGNORECASE)
_REG_KEY = re.compile(r'HK(?:LM|CU|CR|U|CC)\\[^\s"\']+', re.IGNORECASE)
_TIMESTAMP = re.compile(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}')


@dataclass
class HallucinationCheckResult:
    """Result of checking a finding for hallucinated claims."""
    finding_id: str
    verified_claims: list[str] = field(default_factory=list)
    potential_hallucinations: list[str] = field(default_factory=list)
    uncertain_claims: list[str] = field(default_factory=list)
    overall_verdict: str = "clean"   # "clean" | "suspicious" | "hallucination_detected"
    issues: list[str] = field(default_factory=list)
    confidence_appropriate: bool = True
    details: str = ""

    @property
    def verified(self) -> bool:
        return self.overall_verdict != "hallucination_detected"


def _extract_entities(text: str) -> dict[str, list[str]]:
    """Extract named forensic entities from a text string."""
    return {
        "file_paths": list(set(_FILE_PATH.findall(text))),
        "unix_paths": list(set(_UNIX_PATH.findall(text))),
        "ip_addresses": list(set(_IPV4.findall(text))),
        "md5_hashes": list(set(_MD5.findall(text))),
        "sha1_hashes": list(set(_SHA1.findall(text))),
        "sha256_hashes": list(set(_SHA256.findall(text))),
        "exe_names": list(set(_EXE.findall(text))),
        "registry_keys": list(set(_REG_KEY.findall(text))),
        "timestamps": list(set(_TIMESTAMP.findall(text))),
    }


def _build_tool_corpus(tool_executions: list[ToolExecution]) -> str:
    """Concatenate all tool output for searching."""
    parts = []
    for te in tool_executions:
        if te.raw_output:
            parts.append(te.raw_output[:8000])
        if te.output_summary:
            parts.append(te.output_summary)
    return "\n".join(parts).lower()


def verify_finding(
    finding: Finding,
    tool_executions: list[ToolExecution],
) -> HallucinationCheckResult:
    """Check a finding's claims against raw tool output.

    Extracts key entities (file paths, process names, IPs, hashes) from the
    finding description and raw evidence excerpts, then searches all tool
    output to verify they actually appear.
    """
    result = HallucinationCheckResult(finding_id=finding.id)

    # Empty evidence excerpt is always a problem
    excerpt = (finding.raw_evidence_excerpt or "").strip()
    if not excerpt and not finding.raw_evidence_excerpts:
        result.overall_verdict = "suspicious"
        result.issues = ["NO_EVIDENCE_EXCERPT: finding has no raw evidence excerpt"]
        result.details = "Finding has no raw evidence excerpt to verify"
        return result

    # Build corpus of all tool output
    corpus = _build_tool_corpus(tool_executions)
    if not corpus:
        # No tool output at all — can't verify anything
        result.overall_verdict = "suspicious"
        result.details = "No tool output available to verify claims against"
        # CONFIRMED with no tool output is always inappropriate
        if finding.confidence == ConfidenceLevel.CONFIRMED:
            result.confidence_appropriate = False
            result.issues = ["CONFIRMED confidence with no supporting tool output"]
        return result

    # Text to check: description + all evidence excerpts
    claim_text = finding.description + " " + " ".join(finding.raw_evidence_excerpts)
    entities = _extract_entities(claim_text)

    hallucinated: list[str] = []
    verified: list[str] = []

    # Check each entity type
    for entity in entities.get("exe_names", []):
        if entity.lower() in corpus:
            verified.append(entity)
        else:
            hallucinated.append(f"exe not in tool output: {entity}")

    for path in entities.get("file_paths", []):
        # Check last component only (paths vary between agents)
        tail = path.replace("\\", "/").split("/")[-1].lower()
        if tail and tail in corpus:
            verified.append(path)
        elif tail:
            result.uncertain_claims.append(f"file path not confirmed: {path}")

    for ip in entities.get("ip_addresses", []):
        if ip in corpus:
            verified.append(ip)
        else:
            hallucinated.append(f"IP not in tool output: {ip}")

    for h in entities.get("sha256_hashes", []) + entities.get("sha1_hashes", []) + entities.get("md5_hashes", []):
        if h.lower() in corpus:
            verified.append(h)
        else:
            result.uncertain_claims.append(f"hash not confirmed: {h[:16]}...")

    for reg in entities.get("registry_keys", []):
        tail = reg.split("\\")[-1].lower()
        if tail and len(tail) > 3 and tail in corpus:
            verified.append(reg)

    result.verified_claims = verified
    result.potential_hallucinations = hallucinated

    if hallucinated:
        result.overall_verdict = "hallucination_detected"
        result.issues = hallucinated
        result.details = f"Claims not found in tool output: {'; '.join(hallucinated[:3])}"
    elif result.uncertain_claims:
        result.overall_verdict = "suspicious"
        result.details = f"Uncertain claims: {'; '.join(result.uncertain_claims[:3])}"
    else:
        result.overall_verdict = "clean"
        result.details = f"All {len(verified)} verified entities found in tool output"

    return result


def batch_verify(
    findings: list[Finding],
    tool_executions: list[ToolExecution],
) -> list[HallucinationCheckResult]:
    """Verify a batch of findings against tool output."""
    return [verify_finding(f, tool_executions) for f in findings]
