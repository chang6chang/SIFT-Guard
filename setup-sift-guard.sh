#!/usr/bin/env bash
# ============================================================================
# SIFT-Guard — Enterprise Setup Script
# 
# Run this on a fresh SIFT Workstation VM (or any Ubuntu/Debian 22.04+).
# It installs everything needed to analyze forensic evidence with one command.
#
# Usage:
#   chmod +x setup-sift-guard.sh
#   sudo ./setup-sift-guard.sh
#
# After setup, switch to your normal user and run:
#   sift-guard analyze /path/to/evidence/folder
# ============================================================================

set -euo pipefail

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fail()  { echo -e "${RED}[FAIL]${NC}  $*"; exit 1; }

# --- Pre-flight ---
if [[ $EUID -ne 0 ]]; then
    fail "Run this script with sudo: sudo ./setup-sift-guard.sh"
fi

INSTALL_DIR="/opt/sift-guard"
VENV_DIR="${INSTALL_DIR}/.venv"
VOL_SYMBOLS_DIR="/opt/volatility3/symbols"
SIFT_GUARD_REPO="https://github.com/chang6chang/SIFT-Guard.git"
SIFT_GUARD_BRANCH="enterprise"
VOL_SYMBOLS_URL="https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip"

echo ""
echo "============================================="
echo "  SIFT-Guard — Enterprise Setup"
echo "============================================="
echo ""
info "Install directory: ${INSTALL_DIR}"
info "Branch: ${SIFT_GUARD_BRANCH}"
echo ""

# =========================================================================
# 1. System dependencies
# =========================================================================
info "Installing system dependencies..."

apt-get update -qq
apt-get install -y -qq \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    git \
    curl \
    wget \
    unzip \
    libewf-dev \
    ewf-tools \
    sleuthkit \
    libguestfs-tools \
    qemu-utils \
    build-essential \
    2>/dev/null

ok "System dependencies installed."

# =========================================================================
# 2. Check Python version (need 3.11+)
# =========================================================================
PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PYTHON_MAJOR=$(echo "$PYTHON_VERSION" | cut -d. -f1)
PYTHON_MINOR=$(echo "$PYTHON_VERSION" | cut -d. -f2)

if [[ "$PYTHON_MAJOR" -lt 3 ]] || [[ "$PYTHON_MAJOR" -eq 3 && "$PYTHON_MINOR" -lt 11 ]]; then
    warn "Python ${PYTHON_VERSION} detected. SIFT-Guard needs 3.11+."
    info "Installing Python 3.12 via deadsnakes PPA..."
    apt-get install -y -qq software-properties-common
    add-apt-repository -y ppa:deadsnakes/ppa
    apt-get update -qq
    apt-get install -y -qq python3.12 python3.12-venv python3.12-dev
    PYTHON_BIN="python3.12"
    ok "Python 3.12 installed."
else
    PYTHON_BIN="python3"
    ok "Python ${PYTHON_VERSION} — compatible."
fi

# =========================================================================
# 3. Install Volatility 3
# =========================================================================
info "Checking Volatility 3..."

if command -v vol &>/dev/null; then
    VOL_VERSION=$(vol --version 2>&1 | head -1 || echo "unknown")
    ok "Volatility 3 already installed: ${VOL_VERSION}"
elif command -v vol.py &>/dev/null; then
    ok "Volatility 3 found as vol.py"
else
    info "Installing Volatility 3..."
    ${PYTHON_BIN} -m pip install --break-system-packages volatility3 2>/dev/null \
        || ${PYTHON_BIN} -m pip install volatility3
    ok "Volatility 3 installed."
fi

# =========================================================================
# 4. Download Volatility symbol tables
# =========================================================================
info "Checking Volatility Windows symbols..."

if [[ -d "${VOL_SYMBOLS_DIR}/windows" ]] && [[ $(find "${VOL_SYMBOLS_DIR}/windows" -name "*.json.xz" | head -1) ]]; then
    SYMBOL_COUNT=$(find "${VOL_SYMBOLS_DIR}/windows" -name "*.json.xz" | wc -l)
    ok "Windows symbols already present (${SYMBOL_COUNT} ISF files)."
else
    info "Downloading Windows symbol tables (~300MB)... This takes a few minutes."
    mkdir -p "${VOL_SYMBOLS_DIR}/windows"
    
    TEMP_ZIP=$(mktemp /tmp/vol-symbols-XXXX.zip)
    wget -q --show-progress -O "${TEMP_ZIP}" "${VOL_SYMBOLS_URL}" \
        || curl -L -o "${TEMP_ZIP}" "${VOL_SYMBOLS_URL}"
    
    info "Extracting symbols..."
    unzip -qo "${TEMP_ZIP}" -d "${VOL_SYMBOLS_DIR}/windows/"
    rm -f "${TEMP_ZIP}"
    
    SYMBOL_COUNT=$(find "${VOL_SYMBOLS_DIR}/windows" -name "*.json.xz" | wc -l)
    ok "Windows symbols installed (${SYMBOL_COUNT} ISF files)."
fi

# =========================================================================
# 5. Install disk forensic tools
# =========================================================================
info "Checking disk forensic tools..."

# log2timeline (plaso)
if command -v log2timeline.py &>/dev/null; then
    ok "log2timeline.py found."
else
    warn "log2timeline.py not found. Installing plaso..."
    ${PYTHON_BIN} -m pip install --break-system-packages plaso 2>/dev/null \
        || ${PYTHON_BIN} -m pip install plaso \
        || warn "plaso install failed — disk MFT timeline analysis will be unavailable."
fi

# python-evtx
if ${PYTHON_BIN} -c "import Evtx" 2>/dev/null; then
    ok "python-evtx found."
else
    info "Installing python-evtx..."
    ${PYTHON_BIN} -m pip install --break-system-packages python-evtx 2>/dev/null \
        || ${PYTHON_BIN} -m pip install python-evtx
    ok "python-evtx installed."
fi

# RegRipper
if command -v rip.pl &>/dev/null || command -v regripper &>/dev/null; then
    ok "RegRipper found."
else
    warn "RegRipper not found. Registry analysis will be unavailable."
    warn "Install manually from: https://github.com/keydet89/RegRipper3.0"
fi

# =========================================================================
# 6. Clone SIFT-Guard
# =========================================================================
info "Setting up SIFT-Guard..."

if [[ -d "${INSTALL_DIR}/.git" ]]; then
    info "Existing installation found. Pulling latest..."
    cd "${INSTALL_DIR}"
    git fetch origin
    git checkout "${SIFT_GUARD_BRANCH}"
    git pull origin "${SIFT_GUARD_BRANCH}"
    ok "Updated to latest ${SIFT_GUARD_BRANCH}."
else
    info "Cloning repository..."
    git clone -b "${SIFT_GUARD_BRANCH}" "${SIFT_GUARD_REPO}" "${INSTALL_DIR}"
    cd "${INSTALL_DIR}"
    ok "Cloned to ${INSTALL_DIR}."
fi

# =========================================================================
# 7. Create virtualenv and install SIFT-Guard
# =========================================================================
info "Creating Python virtual environment..."

${PYTHON_BIN} -m venv "${VENV_DIR}"
source "${VENV_DIR}/bin/activate"

info "Installing SIFT-Guard and dependencies..."
pip install --upgrade pip -q
pip install -e ".[rag,dev]" -q

ok "SIFT-Guard installed in virtualenv."

# =========================================================================
# 8. Build RAG index
# =========================================================================
info "Building RAG index (MITRE ATT&CK + Sigma rules)..."

if [[ -f "${INSTALL_DIR}/rag/data/attack-enterprise.faiss" ]]; then
    ok "RAG index already exists. Skipping rebuild."
else
    python -m rag.build_index 2>/dev/null \
        || warn "RAG index build failed. Run manually: python -m rag.build_index"
fi

# =========================================================================
# 9. Create symlink for global access
# =========================================================================
info "Creating global command link..."

cat > /usr/local/bin/sift-guard << 'WRAPPER'
#!/usr/bin/env bash
# SIFT-Guard wrapper — activates venv and runs the CLI
INSTALL_DIR="/opt/sift-guard"
source "${INSTALL_DIR}/.venv/bin/activate"
exec python -m sift_guard.cli "$@"
WRAPPER

chmod +x /usr/local/bin/sift-guard
ok "Global command 'sift-guard' installed."

# =========================================================================
# 10. Create default config
# =========================================================================
CONFIG_FILE="/etc/sift-guard.yaml"
if [[ ! -f "${CONFIG_FILE}" ]]; then
    info "Creating default config at ${CONFIG_FILE}..."
    cat > "${CONFIG_FILE}" << YAML
# SIFT-Guard configuration
# See ${INSTALL_DIR}/sift-guard.yaml.example for all options

volatility:
  # Auto-detected if on PATH. Override here if needed:
  # path: /usr/bin/vol
  symbols_dir: ${VOL_SYMBOLS_DIR}

disk_tools:
  # Auto-detected if on PATH. Override here if needed:
  # log2timeline: /usr/bin/log2timeline.py
  # evtx_dump: /usr/bin/evtx_dump.py
  # regripper: /usr/bin/rip.pl

analysis:
  max_iterations: 6
  token_budget: 2000000
  # model: claude-sonnet-4-20250514

output:
  generate_report: true
  report_format: both   # markdown, json, or both
YAML
    ok "Config created at ${CONFIG_FILE}."
else
    ok "Config already exists at ${CONFIG_FILE}."
fi

# =========================================================================
# 11. Run tests to verify installation
# =========================================================================
info "Running test suite..."

cd "${INSTALL_DIR}"
source "${VENV_DIR}/bin/activate"

TEST_RESULT=$(python -m pytest tests/ -x -q --tb=line 2>&1 | tail -3)
echo "  ${TEST_RESULT}"

if echo "${TEST_RESULT}" | grep -q "passed"; then
    ok "Tests passed."
else
    warn "Some tests failed. Check: cd ${INSTALL_DIR} && source .venv/bin/activate && pytest -v"
fi

# =========================================================================
# 12. Smoke test
# =========================================================================
info "Running smoke test..."

if sift-guard --help &>/dev/null; then
    ok "sift-guard CLI responds."
else
    warn "sift-guard CLI not responding. Check the wrapper at /usr/local/bin/sift-guard"
fi

# =========================================================================
# Done
# =========================================================================
echo ""
echo "============================================="
echo -e "  ${GREEN}SIFT-Guard setup complete!${NC}"
echo "============================================="
echo ""
echo "  Next steps:"
echo ""
echo "  1. Set your Anthropic API key:"
echo "     export ANTHROPIC_API_KEY=sk-ant-..."
echo "     (add to ~/.bashrc to persist)"
echo ""
echo "  2. Drop evidence in a folder and analyze:"
echo "     sift-guard analyze /path/to/evidence/"
echo ""
echo "  3. View results:"
echo "     cat results/report.md"
echo ""
echo "  Example with a case directory:"
echo "     mkdir -p /cases/case-001/evidence"
echo "     cp /seized/memory.raw /cases/case-001/evidence/"
echo "     cp /seized/disk.E01 /cases/case-001/evidence/"
echo "     sift-guard analyze /cases/case-001/evidence \\"
echo "         --output-dir /cases/case-001/results"
echo ""
echo "  Config: ${CONFIG_FILE}"
echo "  Install: ${INSTALL_DIR}"
echo "  Logs:    <output-dir>/audit/"
echo ""
echo "  For help: sift-guard --help"
echo ""