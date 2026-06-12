"""Tests for memory forensics tool wrappers."""
import pytest
from sift_hunter.mcp_server.tools.memory.processes import ProcessTool
from sift_hunter.mcp_server.tools.memory.network import NetworkTool
from sift_hunter.mcp_server.tools.memory.malware import MalwareTool
from sift_hunter.mcp_server.tools.memory.credentials import CredentialsTool
from sift_hunter.mcp_server.tools.memory.volatility import VolatilityTool


class TestProcessTool:
    def test_find_suspicious_wrong_parent(self):
        tool = ProcessTool()
        processes = [{"ImageFileName": "lsass.exe", "Parent": "explorer.exe", "Path": "C:\\Windows\\System32\\lsass.exe"}]
        flags = tool.find_suspicious(processes)
        assert len(flags) > 0
        assert any("UNEXPECTED_PARENT" in i for f in flags for i in f["issues"])

    def test_find_suspicious_wrong_path(self):
        tool = ProcessTool()
        processes = [{"ImageFileName": "lsass.exe", "Parent": "wininit.exe", "Path": "C:\\Temp\\lsass.exe"}]
        flags = tool.find_suspicious(processes)
        assert any("WRONG_PATH" in i for f in flags for i in f["issues"])

    def test_masquerade_detection(self):
        tool = ProcessTool()
        processes = [{"ImageFileName": "svchost_helper.exe", "Parent": "services.exe", "Path": "C:\\Temp\\svchost_helper.exe"}]
        flags = tool.find_suspicious(processes)
        assert len(flags) > 0

    def test_clean_process_not_flagged(self):
        tool = ProcessTool()
        processes = [{"ImageFileName": "notepad.exe", "Parent": "explorer.exe", "Path": "C:\\Windows\\System32\\notepad.exe"}]
        flags = tool.find_suspicious(processes)
        assert len(flags) == 0

    def test_is_available_returns_bool(self):
        tool = ProcessTool()
        assert isinstance(tool.is_available(), bool)


class TestNetworkTool:
    def test_find_c2_port(self):
        tool = NetworkTool()
        connections = [{
            "ForeignAddr": "8.8.8.8",  # Google DNS - clearly external, C2 on 4444 is suspicious
            "ForeignPort": "4444",
            "Owner": "svchost_helper.exe",
            "State": "ESTABLISHED",
        }]
        flags = tool.find_suspicious(connections)
        assert len(flags) > 0
        assert any("C2_PORT" in i for f in flags for i in f["issues"])

    def test_external_established_flagged(self):
        tool = NetworkTool()
        connections = [{
            "ForeignAddr": "8.8.8.8",
            "ForeignPort": "443",
            "Owner": "chrome.exe",
            "State": "ESTABLISHED",
        }]
        flags = tool.find_suspicious(connections)
        assert any("EXTERNAL_ESTABLISHED" in i for f in flags for i in f["issues"])

    def test_suspicious_process_network(self):
        tool = NetworkTool()
        # PowerShell with ESTABLISHED state always flagged regardless of IP
        connections = [{
            "ForeignAddr": "1.1.1.1",  # Cloudflare DNS - clearly external
            "ForeignPort": "80",
            "Owner": "powershell.exe",
            "State": "ESTABLISHED",
        }]
        flags = tool.find_suspicious(connections)
        assert any("SUSPICIOUS_PROCESS_NETWORK" in i for f in flags for i in f["issues"])

    def test_private_ip_not_flagged_as_external(self):
        tool = NetworkTool()
        connections = [{
            "ForeignAddr": "192.168.1.100",
            "ForeignPort": "445",
            "Owner": "system",
            "State": "ESTABLISHED",
        }]
        flags = tool.find_suspicious(connections)
        # Private IP - should not flag as external C2
        external_flags = [f for f in flags if any("EXTERNAL_ESTABLISHED" in i for i in f["issues"])]
        assert len(external_flags) == 0

    def test_local_connection_ignored(self):
        tool = NetworkTool()
        connections = [{"ForeignAddr": "0.0.0.0", "ForeignPort": "0", "Owner": "system", "State": "LISTENING"}]
        flags = tool.find_suspicious(connections)
        assert len(flags) == 0


class TestMalwareTool:
    def test_find_injected_mz_header(self):
        tool = MalwareTool()
        rows = [{
            "Process": "explorer.exe",
            "PID": "1234",
            "Protection": "PAGE_EXECUTE_READWRITE",
            "Hexdump": "4d5a 9000 0300 0000...",
        }]
        flags = tool.find_suspicious_injections(rows)
        assert len(flags) > 0
        issues = flags[0]["issues"]
        assert any("EXECUTABLE_WRITABLE" in i or "INJECTED_PE" in i for i in issues)

    def test_find_rwx_region(self):
        tool = MalwareTool()
        rows = [{"Process": "svchost.exe", "PID": "888", "Protection": "PAGE_EXECUTE_READWRITE", "Hexdump": "nop nop nop"}]
        flags = tool.find_suspicious_injections(rows)
        assert any("EXECUTABLE_WRITABLE_REGION" in i for f in flags for i in f["issues"])

    def test_clean_region_not_flagged(self):
        tool = MalwareTool()
        rows = [{"Process": "notepad.exe", "PID": "42", "Protection": "PAGE_READONLY", "Hexdump": "..."}]
        flags = tool.find_suspicious_injections(rows)
        assert len(flags) == 0


class TestCredentialsTool:
    def test_parse_hashes(self):
        tool = CredentialsTool()
        rows = [
            {"User": "Administrator", "NT": "aabbccdd11223344aabbccdd11223344", "LM": ""},
            {"User": "Guest", "NT": "31d6cfe0d16ae931b73c59d7e0c089c0", "LM": ""},
        ]
        hashes = tool.parse_hashes(rows)
        assert len(hashes) == 2
        guest = next(h for h in hashes if h["username"] == "Guest")
        assert guest.get("note") == "blank_password"

    def test_find_privileged_accounts(self):
        tool = CredentialsTool()
        rows = [
            {"User": "Administrator", "NT": "aabb", "LM": ""},
            {"User": "jdoe", "NT": "ccdd", "LM": ""},
        ]
        privileged = tool.find_privileged_accounts(rows)
        assert len(privileged) == 1
        assert privileged[0]["username"] == "administrator"


class TestVolatilityTool:
    def test_is_available_returns_bool(self):
        vol = VolatilityTool()
        assert isinstance(vol.is_available(), bool)
