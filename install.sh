#!/usr/bin/env bash
# SIFT-HUNTER Installer — One-command setup on SIFT Workstation or Ubuntu 22.04+
# Usage: curl -fsSL https://raw.githubusercontent.com/your-org/sift-hunter/main/install.sh | bash
#   or:  bash install.sh [--dev] [--no-deps-check]

set -euo pipefail

RESET="\033[0m"
BOLD="\033[1m"
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
CYAN="\033[36m"

INSTALL_DIR="${HOME}/.local/share/sift-hunter"
VENV_DIR="${INSTALL_DIR}/venv"
DEV_MODE=false
SKIP_DEPS_CHECK=false
REPO_URL="https://github.com/your-org/sift-hunter.git"

info()    { echo -e "${CYAN}[INFO]${RESET} $*"; }
success() { echo -e "${GREEN}[OK]${RESET}   $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET} $*"; }
error()   { echo -e "${RED}[ERROR]${RESET} $*" >&2; }
die()     { error "$*"; exit 1; }

# ─── Parse args ─────────────────────────────────────────────────────────────
for arg in "$@"; do
    case $arg in
        --dev)            DEV_MODE=true ;;
        --no-deps-check)  SKIP_DEPS_CHECK=true ;;
        --help|-h)
            echo "Usage: install.sh [--dev] [--no-deps-check]"
            echo "  --dev            Install in editable mode (for development)"
            echo "  --no-deps-check  Skip SIFT tool availability checks"
            exit 0
            ;;
        *) warn "Unknown argument: $arg" ;;
    esac
done

# ─── Banner ──────────────────────────────────────────────────────────────────
echo -e "${BOLD}"
cat << 'EOF'
  ███████╗██╗███████╗████████╗      ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
  ██╔════╝██║██╔════╝╚══██╔══╝      ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
  ███████╗██║█████╗     ██║   █████╗███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
  ╚════██║██║██╔══╝     ██║   ╚════╝██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
  ███████║██║██║        ██║         ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
  ╚══════╝╚═╝╚═╝        ╚═╝         ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
EOF
echo -e "${RESET}"
echo -e "${BOLD}  Self-correcting Intelligent Forensic Triage & Hunt — Unified Network of Expert Responders${RESET}"
echo ""

# ─── Prerequisites ───────────────────────────────────────────────────────────
info "Checking prerequisites..."

# Python 3.11+
if ! command -v python3 &>/dev/null; then
    die "Python 3 not found. Install Python 3.11+ and retry."
fi

PYTHON_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PYTHON_MAJOR=$(echo "$PYTHON_VER" | cut -d. -f1)
PYTHON_MINOR=$(echo "$PYTHON_VER" | cut -d. -f2)

if [[ "$PYTHON_MAJOR" -lt 3 ]] || { [[ "$PYTHON_MAJOR" -eq 3 ]] && [[ "$PYTHON_MINOR" -lt 11 ]]; }; then
    die "Python 3.11+ required. Found $PYTHON_VER. Install a newer Python version."
fi
success "Python $PYTHON_VER"

# pip
if ! python3 -m pip --version &>/dev/null; then
    die "pip not found. Run: python3 -m ensurepip --upgrade"
fi
success "pip available"

# git (for cloning if needed)
if ! command -v git &>/dev/null; then
    warn "git not found — install from git if you need to clone the repo"
fi

# ANTHROPIC_API_KEY
if [[ -z "${ANTHROPIC_API_KEY:-}" ]]; then
    warn "ANTHROPIC_API_KEY not set. Add it to your shell profile:"
    warn "  export ANTHROPIC_API_KEY='sk-ant-...'"
    warn "  (Required before running any analysis)"
fi

# ─── SIFT Tool Checks ────────────────────────────────────────────────────────
if [[ "$SKIP_DEPS_CHECK" == false ]]; then
    info "Checking SIFT forensic tools..."

    MISSING_TOOLS=()
    OPTIONAL_TOOLS=()

    # Required for disk analysis
    for tool in log2timeline.py psort.py; do
        if command -v "$tool" &>/dev/null; then
            success "$tool"
        else
            MISSING_TOOLS+=("$tool (log2timeline/plaso)")
        fi
    done

    # Eric Zimmerman tools (common SIFT locations)
    EZ_PATHS=("/usr/local/bin" "/opt/EZTools" "$HOME/.local/bin")
    for tool in MFTECmd PECmd AmcacheParser SBECmd RECmd; do
        FOUND=false
        for dir in "${EZ_PATHS[@]}"; do
            if [[ -f "$dir/$tool" ]] || [[ -f "$dir/${tool}.exe" ]]; then
                FOUND=true
                success "$tool"
                break
            fi
        done
        if [[ "$FOUND" == false ]]; then
            MISSING_TOOLS+=("$tool (Eric Zimmerman Tools)")
        fi
    done

    # Volatility3
    if command -v vol3 &>/dev/null || command -v vol &>/dev/null; then
        success "Volatility3"
    else
        MISSING_TOOLS+=("vol3 (Volatility3)")
    fi

    # RegRipper
    if command -v rip.pl &>/dev/null || command -v regripper &>/dev/null; then
        success "RegRipper"
    else
        OPTIONAL_TOOLS+=("rip.pl (RegRipper — optional, enhances registry analysis)")
    fi

    if [[ "${#MISSING_TOOLS[@]}" -gt 0 ]]; then
        echo ""
        warn "Some forensic tools are missing:"
        for t in "${MISSING_TOOLS[@]}"; do
            warn "  - $t"
        done
        warn "SIFT-HUNTER will work but skip tools that aren't installed."
        warn "On SIFT Workstation: sudo apt-get install -y plaso-tools volatility3"
        warn "Eric Zimmerman Tools: https://ericzimmerman.github.io/"
        echo ""
    fi

    for t in "${OPTIONAL_TOOLS[@]}"; do
        warn "Optional: $t"
    done
fi

# ─── Install Python Package ──────────────────────────────────────────────────
info "Creating virtual environment at $VENV_DIR..."
mkdir -p "$INSTALL_DIR"
python3 -m venv "$VENV_DIR"

VENV_PYTHON="$VENV_DIR/bin/python"
VENV_PIP="$VENV_DIR/bin/pip"

info "Upgrading pip in virtual environment..."
"$VENV_PYTHON" -m pip install --upgrade pip --quiet

# If we're in the repo directory, install from local path
if [[ -f "pyproject.toml" ]] && grep -q "sift-hunter" pyproject.toml 2>/dev/null; then
    info "Installing from local source..."
    if [[ "$DEV_MODE" == true ]]; then
        "$VENV_PIP" install -e ".[dev]" --quiet
    else
        "$VENV_PIP" install "." --quiet
    fi
else
    info "Installing from requirements.txt..."
    if [[ -f "requirements.txt" ]]; then
        "$VENV_PIP" install -r requirements.txt --quiet
    else
        # Fallback: install core dependencies directly
        "$VENV_PIP" install \
            "mcp>=1.0.0" \
            "langgraph>=0.2.0" \
            "langchain-anthropic>=0.3.0" \
            "anthropic>=0.40.0" \
            "pydantic>=2.0.0" \
            "rich>=13.0.0" \
            "typer>=0.12.0" \
            "httpx>=0.27.0" \
            --quiet
    fi
fi
success "Python packages installed"

# ─── Install CLI Shim ────────────────────────────────────────────────────────
info "Installing sift-hunter CLI..."

LOCAL_BIN="$HOME/.local/bin"
mkdir -p "$LOCAL_BIN"

cat > "$LOCAL_BIN/sift-hunter" << SHIM
#!/usr/bin/env bash
exec "$VENV_PYTHON" -m agents.cli "\$@"
SHIM

chmod +x "$LOCAL_BIN/sift-hunter"

# Check if ~/.local/bin is in PATH
if [[ ":$PATH:" != *":$LOCAL_BIN:"* ]]; then
    warn "~/.local/bin is not in your PATH."
    warn "Add this to your shell profile (~/.bashrc or ~/.zshrc):"
    warn '  export PATH="$HOME/.local/bin:$PATH"'
    warn "Then restart your terminal or run: source ~/.bashrc"
    echo ""
fi

success "CLI installed at $LOCAL_BIN/sift-hunter"

# ─── Configure Default Evidence Roots ────────────────────────────────────────
info "Configuring evidence roots..."

CONFIG_FILE="$INSTALL_DIR/config.env"
cat > "$CONFIG_FILE" << CONFIG
# SIFT-HUNTER Configuration
# Source this file or set these variables in your shell profile

# Allowed evidence directories (colon-separated)
export SIFT_EVIDENCE_ROOTS="/cases:/mnt/evidence:/media"

# Output directory for reports and timelines
export SIFT_OUTPUT_ROOT="/tmp/sift-output"

# Claude model ID
export SIFT_MODEL="claude-opus-4-7-20250514"

# API keys (fill these in)
# export ANTHROPIC_API_KEY="sk-ant-..."
# export VT_API_KEY="..."
# export ABUSEIPDB_API_KEY="..."

# Audit log path
export SIFT_AUDIT_LOG="/var/log/sift-hunter/audit.jsonl"
CONFIG

# Create output directory
mkdir -p /tmp/sift-output 2>/dev/null || true

success "Configuration written to $CONFIG_FILE"

# ─── Post-Install Shell Profile Update ────────────────────────────────────────
SHELL_PROFILE=""
if [[ -f "$HOME/.zshrc" ]]; then
    SHELL_PROFILE="$HOME/.zshrc"
elif [[ -f "$HOME/.bashrc" ]]; then
    SHELL_PROFILE="$HOME/.bashrc"
fi

if [[ -n "$SHELL_PROFILE" ]]; then
    if ! grep -q "sift-hunter" "$SHELL_PROFILE" 2>/dev/null; then
        echo "" >> "$SHELL_PROFILE"
        echo "# SIFT-HUNTER" >> "$SHELL_PROFILE"
        echo "source \"$CONFIG_FILE\"" >> "$SHELL_PROFILE"
        echo "export PATH=\"\$HOME/.local/bin:\$PATH\"" >> "$SHELL_PROFILE"
        success "Added SIFT-HUNTER to $SHELL_PROFILE"
    else
        info "SIFT-HUNTER already configured in $SHELL_PROFILE"
    fi
fi

# ─── Verification ────────────────────────────────────────────────────────────
info "Running verification tests..."

if "$VENV_PYTHON" -c "
import sys
try:
    from mcp_server.security import check_command_safety, SecurityError
    # Test that destructive commands are blocked
    try:
        check_command_safety('rm')
        print('FAIL: rm should be blocked')
        sys.exit(1)
    except SecurityError:
        pass
    print('Security layer: OK')
except Exception as e:
    print(f'Security layer: FAIL ({e})')
    sys.exit(1)
" 2>/dev/null; then
    success "Security guardrails verified"
else
    warn "Could not verify security layer (may need to set PYTHONPATH)"
fi

# ─── Done ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}Installation complete!${RESET}"
echo ""
echo "Quick start:"
echo "  source $CONFIG_FILE   # Load configuration"
echo ""
echo "  # Set your API key"
echo "  export ANTHROPIC_API_KEY='sk-ant-...'"
echo ""
echo "  # Run analysis"
echo "  sift-hunter analyze /cases/disk.dd /cases/memory.dmp --output /tmp/report.md"
echo ""
echo "  # Test security guardrails"
echo "  sift-hunter check 'rm -rf /evidence'    # Should be BLOCKED"
echo "  sift-hunter check 'vol3 -f mem.dmp windows.pslist.PsList'  # Should be ALLOWED"
echo ""
echo "  # View help"
echo "  sift-hunter --help"
echo ""
echo -e "Documentation: ${CYAN}docs/ARCHITECTURE.md${RESET} | ${CYAN}docs/ADDING_TOOLS.md${RESET}"
echo ""
