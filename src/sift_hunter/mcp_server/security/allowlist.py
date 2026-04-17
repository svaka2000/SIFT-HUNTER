"""Allowlist and blocklist definitions for forensic binary authorization."""
from __future__ import annotations

# ── ALLOWLISTED BINARIES ────────────────────────────────────────────────────
# ONLY these binaries may be executed. Every other binary is blocked.
# Values are the set of allowed flags for that binary.
ALLOWED_BINARIES: dict[str, set[str]] = {
    # Eric Zimmerman tools (disk forensics)
    "MFTECmd": {"-f", "--csv", "--csvf", "--json", "--jsonf", "-d", "--de",
                "--fl", "--dt", "--mp", "-q", "--body", "--bodyf"},
    "PECmd": {"-f", "-d", "--csv", "--csvf", "--json", "--jsonf", "-q", "--all"},
    "AmcacheParser": {"-f", "--csv", "--csvf", "-i", "-q"},
    "RECmd": {"-f", "--csv", "--csvf", "--bn", "--nl", "-d", "--sa", "--sk", "-q"},
    "SBECmd": {"-f", "-d", "--csv", "--csvf", "-q"},
    "LECmd": {"-f", "-d", "--csv", "--csvf", "-q"},
    "JLECmd": {"-f", "-d", "--csv", "--csvf", "-q"},
    "EvtxECmd": {"-f", "-d", "--csv", "--csvf", "--json", "--jsonf", "-q"},

    # Plaso timeline generation
    "log2timeline.py": {"--storage-file", "--parsers", "--status_view",
                        "-z", "--hashers", "--logfile", "-q"},
    "psort.py": {"-o", "-w", "--analysis_plugins", "-z", "-q"},
    "pinfo.py": {"--storage-file", "-v", "-q"},

    # Volatility 3 (memory forensics)
    "vol": {"-f", "-r", "-p", "--plugin-dirs", "-o", "--single-location",
            "--clear-cache", "-q"},
    "vol3": {"-f", "-r", "-p", "--plugin-dirs", "-o", "--single-location", "-q"},
    "volatility3": {"-f", "-r", "-p", "--plugin-dirs", "-o", "--single-location", "-q"},
    "volatility": {"-f", "-r", "-p", "--plugin-dirs", "-o", "--single-location", "-q"},
    "python3": {"-m"},  # Only allowed for: python3 -m volatility3 ...

    # RegRipper
    "rip.pl": {"-r", "-p", "-a", "-l"},
    "perl": set(),  # Only for rip.pl

    # Sleuth Kit read-only tools
    "fls": {"-r", "-m", "-o", "-f", "-l", "-p", "-d"},
    "icat": {"-o", "-r", "-s"},
    "mmls": {"-t", "-r", "-a", "-B"},
    "img_stat": {"-t", "-i"},
    "fsstat": {"-o", "-f", "-t"},
    "tsk_recover": {"-o", "-e", "-a", "-d"},
    "mactime": {"-b", "-d", "-z"},
    "blkstat": {"-o", "-f"},
    "blkls": {"-o", "-f", "-A"},
    "ils": {"-o", "-f", "-a"},

    # Hashing utilities (read-only)
    "sha256sum": set(),
    "sha1sum": set(),
    "md5sum": set(),
    "shasum": {"-a"},

    # Basic read-only analysis utilities
    "file": {"-b", "-i", "-k"},
    "strings": {"-a", "-n", "-e", "-o", "-t"},
    "xxd": {"-l", "-s", "-g", "-c"},
    "hexdump": {"-C", "-n", "-s", "-v"},
    "stat": set(),
    "ls": {"-la", "-lh", "-l", "-a", "-h", "-R"},
}

# ── BLOCKED BINARIES ────────────────────────────────────────────────────────
# Explicitly blocked even if somehow not caught by the allowlist check.
BLOCKED_BINARIES: frozenset[str] = frozenset({
    # Destructive file operations
    "rm", "rmdir", "del", "erase", "shred", "wipe", "srm", "secure-delete",
    "truncate", "fallocate",
    # Disk/partition destruction
    "dd", "mkfs", "mke2fs", "mkntfs", "fdisk", "parted", "gdisk", "sgdisk",
    "mkswap", "format", "diskutil",
    # Network exfiltration
    "wget", "curl", "nc", "ncat", "netcat", "socat",
    "ssh", "scp", "sftp", "ftp", "tftp", "rsync", "rcp",
    "telnet", "nmap", "masscan", "zmap",
    # Permission/ownership modification
    "chmod", "chown", "chgrp", "setfacl", "chattr",
    # Process termination
    "kill", "pkill", "killall", "skill",
    # Package/dependency management
    "apt", "apt-get", "dpkg", "rpm", "yum", "dnf", "zypper",
    "pip", "pip3", "pip2", "conda", "npm", "yarn", "gem", "cargo",
    # Shells and interpreters
    "bash", "sh", "zsh", "dash", "fish", "csh", "ksh", "tcsh",
    "python", "python2", "python3.9", "python3.10", "ruby", "node", "nodejs",
    "perl5", "php", "lua",
    # Mount operations (evidence integrity)
    "mount", "umount", "fusermount", "losetup",
    # System modification
    "systemctl", "service", "init", "reboot", "shutdown", "halt", "poweroff",
    "useradd", "userdel", "usermod", "groupadd", "groupdel",
    "passwd", "su", "sudo", "doas", "pkexec",
    # Compilation and downloaders
    "gcc", "g++", "cc", "clang", "make", "cmake", "ninja",
    "git", "svn", "hg", "bzr",
    # Write-capable archivers
    "tar", "zip", "gzip", "bzip2", "7z", "rar",
    # Screen/session management
    "screen", "tmux", "nohup",
})

# ── INJECTION CHARACTERS ────────────────────────────────────────────────────
INJECTION_CHARS: frozenset[str] = frozenset({
    ";", "|", "&", "`", "$", "(", ")", "{", "}",
    "<", ">", "!", "\n", "\r", "\x00", "\t",
})

# ── VOLATILITY PLUGIN PATTERN ───────────────────────────────────────────────
# Positional args like "windows.pslist.PsList" are allowed as-is (dots + alnum)
import re as _re
VOLATILITY_PLUGIN_RE = _re.compile(r'^[a-zA-Z][a-zA-Z0-9_.]+$')
