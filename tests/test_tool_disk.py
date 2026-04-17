"""Tests for disk forensics tool wrappers."""
import csv
import os
import tempfile
from pathlib import Path
import pytest

from sift_hunter.mcp_server.tools.disk.mft import MFTTool
from sift_hunter.mcp_server.tools.disk.prefetch import PrefetchTool
from sift_hunter.mcp_server.tools.disk.registry import RegistryTool
from sift_hunter.mcp_server.tools.disk.usnjrnl import USNJournalTool
from sift_hunter.mcp_server.tools.disk.shellbags import ShellBagsTool
from sift_hunter.mcp_server.tools.disk.sleuthkit import SleuthKitTool


@pytest.fixture
def mft_csv(tmp_path):
    csv_file = tmp_path / "mft.csv"
    with open(csv_file, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "EntryNumber", "FileName", "Created0x10", "Created0x30",
            "LastModified0x10", "LastModified0x30", "FileSize", "ParentPath", "InUse"
        ])
        writer.writeheader()
        writer.writerow({
            "EntryNumber": "1234",
            "FileName": "svchost_helper.exe",
            "Created0x10": "2024-01-15 14:00:00",
            "Created0x30": "2024-01-13 08:00:00",  # different — timestomping
            "LastModified0x10": "2024-01-15 14:23:00",
            "LastModified0x30": "2024-01-15 14:23:00",
            "FileSize": "45056",
            "ParentPath": "C:\\Users\\victim\\AppData\\Local\\Temp",
            "InUse": "True",
        })
    return str(csv_file)


class TestMFTTool:
    def test_parse_csv(self, mft_csv):
        tool = MFTTool()
        entries = tool.parse_csv(mft_csv)
        assert len(entries) == 1
        assert entries[0]["FileName"] == "svchost_helper.exe"

    def test_find_suspicious_timestomping(self, mft_csv):
        tool = MFTTool()
        entries = tool.parse_csv(mft_csv)
        suspicious = tool.find_suspicious(entries)
        assert len(suspicious) > 0
        flags = suspicious[0].get("_flags") or suspicious[0].get("issues") or []
        assert any("TIMESTOMP" in f for f in flags)

    def test_find_suspicious_temp_path(self, mft_csv):
        tool = MFTTool()
        entries = tool.parse_csv(mft_csv)
        suspicious = tool.find_suspicious(entries)
        flags = suspicious[0].get("_flags") or suspicious[0].get("issues") or []
        assert any("TEMP" in f.upper() or "SUSPICIOUS" in f.upper() for f in flags)

    def test_binary_not_required_for_csv_analysis(self, mft_csv):
        tool = MFTTool()
        # parse_csv works without binary
        entries = tool.parse_csv(mft_csv)
        assert len(entries) >= 1

    def test_is_available_returns_bool(self):
        tool = MFTTool()
        assert isinstance(tool.is_available(), bool)


class TestPrefetchTool:
    def test_find_suspicious_temp_path(self):
        tool = PrefetchTool()
        entries = [{"ExecutableName": "C:\\Temp\\evil.exe", "RunCount": "3"}]
        flags = tool.find_suspicious(entries)
        assert len(flags) > 0
        assert any("TEMP" in i.upper() for f in flags for i in f["issues"])

    def test_find_suspicious_high_count(self):
        tool = PrefetchTool()
        entries = [{"ExecutableName": "C:\\Windows\\normal.exe", "RunCount": "150"}]
        flags = tool.find_suspicious(entries)
        assert any("HIGH_EXECUTION_COUNT" in i for f in flags for i in f["issues"])

    def test_clean_entry_not_flagged(self):
        tool = PrefetchTool()
        entries = [{"ExecutableName": "C:\\Windows\\System32\\notepad.exe", "RunCount": "5"}]
        flags = tool.find_suspicious(entries)
        assert len(flags) == 0


class TestRegistryTool:
    def test_find_persistence_run_key(self):
        tool = RegistryTool()
        entries = [{
            "KeyPath": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "ValueName": "WindowsHelper",
            "ValueData": r"C:\Temp\evil.exe",
        }]
        findings = tool.find_persistence(entries)
        assert len(findings) > 0
        assert findings[0]["type"] == "PERSISTENCE_KEY"

    def test_find_user_activity(self):
        tool = RegistryTool()
        entries = [
            {"KeyPath": r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs", "ValueName": "secret.docx"},
            {"KeyPath": r"HKCU\Software\Microsoft\Windows\Shell\BagMRU", "ValueName": "..."},
        ]
        activities = tool.find_user_activity(entries)
        assert len(activities) >= 1

    def test_no_false_positives_for_benign_keys(self):
        tool = RegistryTool()
        entries = [{"KeyPath": r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ValueName": "ProductName", "ValueData": "Windows 10"}]
        findings = tool.find_persistence(entries)
        assert len(findings) == 0


class TestUSNJournalTool:
    def test_find_deletions(self):
        tool = USNJournalTool()
        entries = [
            {"FileName": "malware.exe", "Reason": "FILE_DELETE|DATA_EXTEND", "UpdateTimestamp": "2024-01-15"},
            {"FileName": "normal.txt", "Reason": "DATA_EXTEND", "UpdateTimestamp": "2024-01-14"},
        ]
        deletions = tool.find_deletions(entries)
        assert len(deletions) == 1
        assert deletions[0]["filename"] == "malware.exe"

    def test_find_renames(self):
        tool = USNJournalTool()
        entries = [{"FileName": "doc.docx.encrypted", "Reason": "RENAME_NEW_NAME|DATA_EXTEND"}]
        renames = tool.find_suspicious_renames(entries)
        assert len(renames) == 1


class TestShellBagsTool:
    def test_find_external_access_usb(self):
        tool = ShellBagsTool()
        entries = [{"AbsolutePath": "USB:\\SECRET_DOCS\\confidential.pdf"}]
        findings = tool.find_external_access(entries)
        assert any(f["type"] == "EXTERNAL_DRIVE_ACCESS" for f in findings)

    def test_find_network_path(self):
        tool = ShellBagsTool()
        entries = [{"AbsolutePath": "\\\\fileserver\\share\\data"}]
        findings = tool.find_external_access(entries)
        assert any(f["type"] == "NETWORK_PATH_ACCESS" for f in findings)


class TestSleuthKitTool:
    def test_find_deleted_files(self):
        tool = SleuthKitTool()
        entries = [
            {"name": "normal.txt", "deleted": False},
            {"name": "* malware.exe", "deleted": True},
        ]
        deleted = tool.find_deleted_files(entries)
        assert len(deleted) == 1
