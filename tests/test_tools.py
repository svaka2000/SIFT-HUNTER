"""
Unit tests for individual forensic tool wrappers.
Tests structured output parsing and graceful failure handling.
"""

import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime

from core.audit import reset_audit_logger
from mcp_server.tools.disk.mft import MFTTool, MFTEntry, MFTResult, _dt_or_none
from mcp_server.tools.disk.prefetch import PrefetchTool, PrefetchEntry
from mcp_server.tools.disk.registry import RegistryTool, RegistryValue, PERSISTENCE_KEYS
from mcp_server.tools.disk.usnjrnl import USNJournalTool, USNRecord, USNResult
from mcp_server.tools.memory.network import NetworkAnalysisTool, NetworkConnection
from mcp_server.tools.memory.processes import ProcessAnalysisTool, Process
from mcp_server.tools.enrichment.mitre import map_finding_to_ttps


@pytest.fixture(autouse=True)
def reset_audit():
    reset_audit_logger("/tmp/test-audit.jsonl")


class TestMFTTool:
    def test_find_suspicious_timestomped_entry(self):
        tool = MFTTool()
        result = MFTResult()
        result.entries = [
            MFTEntry(
                filename="evil.exe",
                fullpath="C:\\Windows\\System32\\evil.exe",
                in_use=True,
                created0x10=datetime(2024, 1, 1, 12, 0, 0),
                created0x30=datetime(2020, 1, 1, 12, 0, 0),  # 4 years difference = timestomping
                extension=".exe",
            )
        ]
        suspicious = tool.find_suspicious_entries(result)
        assert len(suspicious) > 0
        assert any("timestomp" in s.reason.lower() or "mismatch" in s.reason.lower() for s in suspicious)

    def test_find_ads_entry(self):
        tool = MFTTool()
        result = MFTResult()
        result.entries = [
            MFTEntry(
                filename="normal.txt",
                is_ads=True,
                fullpath="C:\\Users\\user\\normal.txt",
            )
        ]
        suspicious = tool.find_suspicious_entries(result)
        assert len(suspicious) > 0
        assert any("Alternate Data Stream" in s.reason for s in suspicious)

    def test_no_suspicious_normal_entry(self):
        tool = MFTTool()
        result = MFTResult()
        ts = datetime(2024, 1, 1, 12, 0, 0)
        result.entries = [
            MFTEntry(
                filename="notepad.exe",
                fullpath="C:\\Windows\\System32\\notepad.exe",
                in_use=True,
                created0x10=ts,
                created0x30=ts,  # Same timestamp = no timestomping
            )
        ]
        suspicious = tool.find_suspicious_entries(result)
        # notepad.exe in System32 with matching timestamps should not be flagged
        assert len([s for s in suspicious if "timestomp" in s.reason.lower()]) == 0

    def test_dt_or_none_valid(self):
        dt = _dt_or_none("2024-01-15 10:30:00")
        assert dt is not None
        assert dt.year == 2024

    def test_dt_or_none_invalid(self):
        assert _dt_or_none("") is None
        assert _dt_or_none("not-a-date") is None
        assert _dt_or_none(None) is None


class TestRegistryTool:
    def test_find_run_key_persistence(self):
        tool = RegistryTool()
        from mcp_server.tools.disk.registry import RegistryResult
        result = RegistryResult(
            hive_type="software",
            values=[
                RegistryValue(
                    key_path="SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                    value_name="EvilMalware",
                    value_data="C:\\Users\\Public\\evil.exe",
                )
            ],
        )
        persistence = tool.find_persistence_keys(result)
        assert len(persistence) > 0
        assert persistence[0].mitre_technique == "T1547.001"
        assert persistence[0].severity == "HIGH"

    def test_no_false_positive_for_empty_run_key(self):
        tool = RegistryTool()
        from mcp_server.tools.disk.registry import RegistryResult
        result = RegistryResult(
            hive_type="software",
            values=[
                RegistryValue(
                    key_path="SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                    value_name="",
                    value_data="",  # Empty value — skip
                )
            ],
        )
        persistence = tool.find_persistence_keys(result)
        assert len(persistence) == 0


class TestNetworkTool:
    def test_find_known_c2_port(self):
        tool = NetworkAnalysisTool()
        connections = [
            NetworkConnection(
                pid=1234,
                process_name="powershell.exe",
                local_addr="192.168.1.100",
                local_port=12345,
                foreign_addr="10.0.0.1",
                foreign_port=4444,  # Metasploit default
                state="ESTABLISHED",
            )
        ]
        suspicious = tool.find_suspicious_connections(connections)
        assert len(suspicious) > 0
        assert any("4444" in s.reason or "C2" in s.ioc_type for s in suspicious)

    def test_unexpected_powershell_http(self):
        tool = NetworkAnalysisTool()
        connections = [
            NetworkConnection(
                pid=5678,
                process_name="powershell.exe",
                local_addr="10.0.0.1",
                local_port=50000,
                foreign_addr="192.168.1.1",
                foreign_port=80,
                state="ESTABLISHED",
            )
        ]
        suspicious = tool.find_suspicious_connections(connections)
        assert len(suspicious) > 0

    def test_clean_connection_not_flagged(self):
        tool = NetworkAnalysisTool()
        connections = [
            NetworkConnection(
                pid=4,
                process_name="svchost.exe",
                local_addr="10.0.0.1",
                local_port=50001,
                foreign_addr="8.8.8.8",
                foreign_port=53,  # DNS from svchost is normal
                state="ESTABLISHED",
            )
        ]
        suspicious = tool.find_suspicious_connections(connections)
        # DNS from svchost should not be flagged
        assert not any(s.severity == "HIGH" for s in suspicious)


class TestProcessTool:
    def test_suspicious_word_spawning_cmd(self):
        tool = ProcessAnalysisTool()
        processes = [
            Process(pid=100, ppid=0, name="winword.exe"),
            Process(pid=200, ppid=100, name="cmd.exe"),
        ]
        suspicious = tool.find_suspicious_processes(processes)
        assert len(suspicious) > 0
        assert any("T1059" in s.mitre_technique for s in suspicious)

    def test_lolbin_flagged(self):
        tool = ProcessAnalysisTool()
        processes = [
            Process(pid=300, ppid=0, name="mshta.exe"),
        ]
        suspicious = tool.find_suspicious_processes(processes)
        assert len(suspicious) > 0
        assert any("T1218" in s.mitre_technique for s in suspicious)

    def test_encoded_powershell_cmdline(self):
        tool = ProcessAnalysisTool()
        processes = [
            Process(
                pid=400,
                ppid=0,
                name="powershell.exe",
                cmdline="powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
            )
        ]
        suspicious = tool.find_suspicious_processes(processes)
        assert len(suspicious) > 0
        assert any("T1059.001" in s.mitre_technique for s in suspicious)


class TestMITREMapping:
    def test_powershell_maps_to_t1059(self):
        techniques = map_finding_to_ttps(
            "PowerShell execution with encoded command -enc detected",
            "Obfuscated PowerShell"
        )
        assert any(t.technique_id == "T1059.001" for t in techniques)

    def test_persistence_run_key_maps_correctly(self):
        techniques = map_finding_to_ttps(
            "Registry Run key persistence mechanism found",
            "Run Key Persistence"
        )
        assert any("T1547" in t.technique_id for t in techniques)

    def test_empty_description_no_crash(self):
        techniques = map_finding_to_ttps("")
        assert isinstance(techniques, list)

    def test_explicit_technique_id_extracted(self):
        techniques = map_finding_to_ttps("Attacker used T1055 process injection technique")
        assert any("T1055" in t.technique_id for t in techniques)
