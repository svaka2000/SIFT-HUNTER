"""Tests for offline MITRE ATT&CK enrichment mapping.

Covers src/sift_hunter/mcp_server/tools/enrichment/mitre_attack.py against the
shipped package API. (Replaces coverage previously provided by the removed
pre-src/ test_tools.py, which imported the renamed `enrichment.mitre` module.)
"""
from __future__ import annotations

from sift_hunter.mcp_server.tools.enrichment.mitre_attack import (
    TTPMatch,
    map_finding_to_ttps,
    map_to_ttps,
)


class TestMapToTTPs:
    def test_powershell_maps_to_t1059_001(self):
        ids = [m.technique_id for m in map_to_ttps("powershell -EncodedCommand ZQBjAGgAbw==")]
        assert "T1059.001" in ids

    def test_run_key_maps_to_persistence(self):
        ids = [m.technique_id for m in map_to_ttps(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -> evil.exe"
        )]
        assert "T1547.001" in ids

    def test_metasploit_c2_maps_to_t1071(self):
        ids = [m.technique_id for m in map_to_ttps(
            "established connection to 198.51.100.44:4444 — metasploit beacon"
        )]
        assert "T1071" in ids

    def test_mshta_maps_to_t1218_005(self):
        ids = [m.technique_id for m in map_to_ttps("mshta.exe ran a malicious .hta")]
        assert "T1218.005" in ids

    def test_benign_text_maps_to_nothing(self):
        assert map_to_ttps("the quick brown fox jumped over the lazy dog") == []

    def test_results_are_ttpmatch_and_sorted_by_confidence(self):
        matches = map_to_ttps(
            "powershell invoke-expression; mshta.exe; currentversion\\run; metasploit 4444"
        )
        assert all(isinstance(m, TTPMatch) for m in matches)
        confidences = [m.confidence for m in matches]
        assert confidences == sorted(confidences, reverse=True)
        assert all(m.technique_id.startswith("T") for m in matches)

    def test_deduplicates_same_technique(self):
        # both "powershell" and "invoke-expression" map to T1059.001
        matches = map_to_ttps("powershell and invoke-expression and iex")
        t1059 = [m for m in matches if m.technique_id == "T1059.001"]
        assert len(t1059) == 1


class TestMapFindingToTTPs:
    def test_reads_description_and_returns_dicts(self):
        result = map_finding_to_ttps(
            {"description": "powershell invoke-expression executed", "title": "", "raw_evidence_excerpt": ""}
        )
        assert isinstance(result, list)
        ids = [r["technique_id"] for r in result]
        assert "T1059.001" in ids
        assert {"technique_id", "technique_name", "tactic", "confidence"} <= set(result[0])

    def test_caps_at_five(self):
        text = (
            "powershell mshta regsvr32 rundll32 schtasks run key new-service "
            "mimikatz metasploit 4444 nmap rdp psexec ransomware exfil"
        )
        result = map_finding_to_ttps({"description": text})
        assert len(result) <= 5

    def test_empty_finding_returns_empty(self):
        assert map_finding_to_ttps({}) == []
