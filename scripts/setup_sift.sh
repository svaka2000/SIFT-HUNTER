#!/usr/bin/env bash
# SIFT Workstation setup - installs all forensic tool dependencies
# Run this once on a fresh SIFT Workstation before using SIFT-HUNTER

set -euo pipefail

BOLD="\033[1m"
GREEN="\033[32m"
YELLOW="\033[33m"
CYAN="\033[36m"
RESET="\033[0m"

info()    { echo -e "${CYAN}[INFO]${RESET} $*"; }
success() { echo -e "${GREEN}[OK]${RESET}   $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET} $*"; }

echo -e "${BOLD}SIFT-HUNTER: SIFT Workstation Setup${RESET}"
echo ""

# Check we're on Ubuntu/Debian
if ! command -v apt-get &>/dev/null; then
    warn "This script is for SIFT Workstation (Ubuntu/Debian). Adapt for other distros."
fi

# ─── Python 3.11 ────────────────────────────────────────────────────────────
info "Installing Python 3.11..."
sudo apt-get update -qq
sudo apt-get install -y python3.11 python3.11-venv python3.11-dev python3-pip 2>/dev/null || true
success "Python 3.11"

# ─── Plaso / log2timeline ────────────────────────────────────────────────────
if ! command -v log2timeline.py &>/dev/null; then
    info "Installing plaso (log2timeline)..."
    sudo apt-get install -y plaso-tools 2>/dev/null || \
    pip3 install plaso 2>/dev/null || \
    warn "Could not install plaso automatically. See: https://plaso.readthedocs.io/en/latest/sources/user/Installing-plaso.html"
else
    success "plaso already installed"
fi

# ─── Volatility3 ────────────────────────────────────────────────────────────
if ! command -v vol3 &>/dev/null && ! command -v vol &>/dev/null; then
    info "Installing Volatility3..."
    sudo apt-get install -y volatility3 2>/dev/null || {
        pip3 install volatility3 2>/dev/null || {
            # Manual install
            info "Installing Volatility3 from source..."
            cd /opt
            sudo git clone https://github.com/volatilityfoundation/volatility3.git
            cd volatility3
            sudo pip3 install -e . --quiet
            sudo ln -sf /opt/volatility3/vol.py /usr/local/bin/vol3
        }
    }
    success "Volatility3"
else
    success "Volatility3 already installed"
fi

# ─── Eric Zimmerman Tools ───────────────────────────────────────────────────
EZ_DIR="/opt/EZTools"
if [[ ! -d "$EZ_DIR" ]]; then
    info "Installing Eric Zimmerman Tools..."
    sudo mkdir -p "$EZ_DIR"

    # Download Get-ZimmermanTools script equivalent for Linux
    # EZ Tools Linux releases are .net binaries requiring mono or dotnet
    if command -v dotnet &>/dev/null; then
        info "dotnet found, downloading EZ Tools binaries..."
        sudo apt-get install -y wget unzip 2>/dev/null || true

        EZ_RELEASE_URL="https://download.ericzimmerman.org/GetZimmermanTools/net6/GetZimmermanTools.zip"
        TEMP_DIR=$(mktemp -d)
        wget -q -O "$TEMP_DIR/ez.zip" "$EZ_RELEASE_URL" 2>/dev/null || {
            warn "Could not download EZ Tools automatically."
            warn "Download from: https://ericzimmerman.github.io/"
            warn "Place MFTECmd, PECmd, AmcacheParser, SBECmd in $EZ_DIR"
        }
    else
        info "Installing dotnet runtime for EZ Tools..."
        wget -q https://packages.microsoft.com/config/ubuntu/22.04/packages-microsoft-prod.deb -O /tmp/packages-microsoft-prod.deb
        sudo dpkg -i /tmp/packages-microsoft-prod.deb 2>/dev/null || true
        sudo apt-get update -qq
        sudo apt-get install -y dotnet-runtime-8.0 2>/dev/null || warn "Could not install dotnet - EZ Tools may not work"
    fi

    # Create wrapper scripts so tools are callable by name
    for tool in MFTECmd PECmd AmcacheParser SBECmd RECmd; do
        if [[ -f "$EZ_DIR/$tool.exe" ]]; then
            cat > "/usr/local/bin/$tool" << WRAPPER
#!/usr/bin/env bash
exec dotnet "$EZ_DIR/$tool.exe" "\$@"
WRAPPER
            chmod +x "/usr/local/bin/$tool"
            success "$tool wrapper created"
        fi
    done
else
    success "EZ Tools directory exists at $EZ_DIR"
fi

# ─── RegRipper ──────────────────────────────────────────────────────────────
if ! command -v rip.pl &>/dev/null; then
    info "Installing RegRipper..."
    sudo apt-get install -y regripper 2>/dev/null || {
        # Manual install
        cd /opt
        sudo git clone https://github.com/keydet89/RegRipper3.0.git regripper
        sudo ln -sf /opt/regripper/rip.pl /usr/local/bin/rip.pl
        sudo chmod +x /opt/regripper/rip.pl
    }
    success "RegRipper"
else
    success "RegRipper already installed"
fi

# ─── Sleuth Kit ─────────────────────────────────────────────────────────────
if ! command -v fls &>/dev/null; then
    info "Installing Sleuth Kit..."
    sudo apt-get install -y sleuthkit 2>/dev/null || warn "Could not install Sleuth Kit"
else
    success "Sleuth Kit already installed"
fi

# ─── Additional Utilities ───────────────────────────────────────────────────
info "Installing additional utilities..."
sudo apt-get install -y jq sqlite3 file xxd binwalk 2>/dev/null || true
success "Additional utilities"

# ─── Create Evidence Directories ────────────────────────────────────────────
info "Creating evidence directories..."
sudo mkdir -p /cases /mnt/evidence
sudo chown "$USER:$USER" /cases /mnt/evidence 2>/dev/null || true
success "Created /cases and /mnt/evidence"

# ─── Python Packages for SIFT-HUNTER ────────────────────────────────────────
info "Installing SIFT-HUNTER Python dependencies..."
pip3 install --user mcp langgraph langchain-anthropic anthropic pydantic rich typer httpx 2>/dev/null || \
    warn "Could not install Python packages. Run: pip3 install mcp langgraph anthropic pydantic rich typer"
success "Python packages"

# ─── Summary ────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}SIFT Workstation setup complete!${RESET}"
echo ""
echo "Tool availability:"
for tool in python3.11 log2timeline.py vol3 rip.pl fls; do
    if command -v "$tool" &>/dev/null; then
        echo -e "  ${GREEN}OK${RESET}  $tool"
    else
        echo -e "  ${YELLOW}--${RESET}  $tool (not found)"
    fi
done

echo ""
echo "Next step: Run the SIFT-HUNTER installer"
echo "  bash install.sh"
echo ""
