#!/usr/bin/env bash
# ============================================================================
# SIFT-Guard — Main-branch Turnkey Setup
#
# Run this on a fresh SIFT Workstation VM (or any Ubuntu/Debian 22.04+).
# It installs everything needed to analyze forensic evidence with one command,
# using Claude Code as the agent harness — no API key required for users
# with a Max subscription.
#
# Usage:
#   chmod +x setup-sift-guard.sh
#   sudo ./setup-sift-guard.sh
#
# After setup, switch to your normal user and run:
#   claude login                        # one-time auth (Max subscription OK)
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

# Identify the invoking (non-root) user. We need it so that
# `claude login` can run under the right home directory at the end.
INVOKING_USER="${SUDO_USER:-${USER:-root}}"
if [[ "${INVOKING_USER}" == "root" ]]; then
    warn "Running as root without sudo — claude login will store credentials"
    warn "in /root. Re-run with sudo from a regular user account if that"
    warn "is not what you want."
fi

INSTALL_DIR="/opt/sift-guard"
VENV_DIR="${INSTALL_DIR}/.venv"
VOL_SYMBOLS_DIR="/opt/volatility3/symbols"
SIFT_GUARD_REPO="https://github.com/chang6chang/SIFT-Guard.git"
SIFT_GUARD_BRANCH="main"
VOL_SYMBOLS_URL="https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip"

echo ""
echo "============================================="
echo "  SIFT-Guard — Turnkey Setup (main branch)"
echo "============================================="
echo ""
info "Install directory: ${INSTALL_DIR}"
info "Branch:            ${SIFT_GUARD_BRANCH}"
info "Auth:              Claude Code (claude login)"
info "Invoking user:     ${INVOKING_USER}"
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
    ca-certificates \
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
# 3. Install Node.js (required by Claude Code) + Claude Code itself
# =========================================================================
info "Checking Node.js (Claude Code dependency)..."

if command -v node &>/dev/null; then
    NODE_VERSION=$(node --version)
    ok "Node.js found: ${NODE_VERSION}"
else
    info "Installing Node.js LTS via NodeSource..."
    curl -fsSL https://deb.nodesource.com/setup_lts.x | bash -
    apt-get install -y -qq nodejs
    ok "Node.js installed: $(node --version)"
fi

info "Checking Claude Code CLI..."

if command -v claude &>/dev/null; then
    ok "Claude Code already installed: $(claude --version 2>&1 | head -1)"
else
    info "Installing Claude Code globally via npm..."
    npm install -g @anthropic-ai/claude-code 2>&1 | tail -5
    if command -v claude &>/dev/null; then
        ok "Claude Code installed: $(claude --version 2>&1 | head -1)"
    else
        warn "Claude Code install completed but the 'claude' command was not"
        warn "found on PATH. You may need to add npm's global bin directory:"
        warn "  echo 'export PATH=\"\$(npm config get prefix)/bin:\$PATH\"' >> ~/.bashrc"
    fi
fi

# =========================================================================
# 4. Install Volatility 3
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
# 5. Download Volatility symbol tables
# =========================================================================
info "Checking Volatility Windows symbols..."

if [[ -d "${VOL_SYMBOLS_DIR}/windows" ]] \
    && [[ $(find "${VOL_SYMBOLS_DIR}/windows" -name "*.json.xz" 2>/dev/null | head -1) ]]; then
    SYMBOL_COUNT=$(find "${VOL_SYMBOLS_DIR}/windows" -name "*.json.xz" | wc -l)
    ok "Windows symbols already present (${SYMBOL_COUNT} ISF files)."
else
    info "Downloading Windows symbol tables (~300MB) — this takes a few minutes..."
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

# Tell the runtime where the symbols live (so vol picks them up
# even if the system VOLATILITY3_SYMBOL_DIRS isn't set).
ENV_FILE="/etc/profile.d/sift-guard.sh"
cat > "${ENV_FILE}" << ENVSH
# SIFT-Guard runtime defaults (created by setup-sift-guard.sh)
export VOLATILITY3_SYMBOL_DIRS="${VOL_SYMBOLS_DIR}"
ENVSH
chmod 644 "${ENV_FILE}"
ok "Wrote ${ENV_FILE}."

# =========================================================================
# 6. Install disk forensic tools
# =========================================================================
info "Checking disk forensic tools..."

if command -v log2timeline.py &>/dev/null; then
    ok "log2timeline.py found."
else
    warn "log2timeline.py not found. Installing plaso..."
    ${PYTHON_BIN} -m pip install --break-system-packages plaso 2>/dev/null \
        || ${PYTHON_BIN} -m pip install plaso \
        || warn "plaso install failed — disk MFT timeline analysis will be unavailable."
fi

if ${PYTHON_BIN} -c "import Evtx" 2>/dev/null; then
    ok "python-evtx found."
else
    info "Installing python-evtx..."
    ${PYTHON_BIN} -m pip install --break-system-packages python-evtx 2>/dev/null \
        || ${PYTHON_BIN} -m pip install python-evtx
    ok "python-evtx installed."
fi

if command -v rip.pl &>/dev/null || command -v regripper &>/dev/null; then
    ok "RegRipper found."
else
    warn "RegRipper not found. Registry analysis will be unavailable."
    warn "Install manually from: https://github.com/keydet89/RegRipper3.0"
fi

# =========================================================================
# 7. Clone SIFT-Guard
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
# 8. Create virtualenv and install SIFT-Guard
# =========================================================================
info "Creating Python virtual environment..."

${PYTHON_BIN} -m venv "${VENV_DIR}"
source "${VENV_DIR}/bin/activate"

info "Installing SIFT-Guard and dependencies..."
pip install --upgrade pip -q
pip install -e ".[dev]" -q

ok "SIFT-Guard installed in virtualenv."

# =========================================================================
# 9. Build RAG index (optional — only if the rag extra is available)
# =========================================================================
info "Building RAG index (optional, MITRE ATT&CK + Sigma rules)..."

if [[ -f "${INSTALL_DIR}/rag/data/attack-enterprise.faiss" ]]; then
    ok "RAG index already exists. Skipping rebuild."
else
    info "Installing RAG extras (sentence-transformers + faiss-cpu, ~2GB)..."
    pip install -e ".[rag]" -q 2>/dev/null \
        || warn "RAG extras install failed — validator's rag_query tool will be unavailable."
    if pip show sentence-transformers &>/dev/null; then
        python -m rag.build_index 2>/dev/null \
            || warn "RAG index build failed. Run manually: python -m rag.build_index"
    fi
fi

# =========================================================================
# 10. Wire MCP server into Claude Code's user config
# =========================================================================
info "Configuring Claude Code to find the SIFT-Guard MCP server..."

# Update the in-repo .mcp.json to point at the actual install path.
MCP_JSON="${INSTALL_DIR}/.mcp.json"
cat > "${MCP_JSON}" << JSON
{
  "mcpServers": {
    "sift-guard": {
      "command": "${VENV_DIR}/bin/python",
      "args": ["-m", "server.main"],
      "cwd": "${INSTALL_DIR}"
    }
  }
}
JSON
chown "${INVOKING_USER}":"${INVOKING_USER}" "${MCP_JSON}" 2>/dev/null || true
ok "Wrote ${MCP_JSON}."

# =========================================================================
# 11. Create global wrapper for the CLI
# =========================================================================
info "Creating global command link..."

cat > /usr/local/bin/sift-guard << 'WRAPPER'
#!/usr/bin/env bash
# SIFT-Guard wrapper — activates the install venv and runs the CLI
INSTALL_DIR="/opt/sift-guard"
source "${INSTALL_DIR}/.venv/bin/activate"
exec python -m sift_guard.cli "$@"
WRAPPER

chmod +x /usr/local/bin/sift-guard
ok "Global command 'sift-guard' installed."

# =========================================================================
# 12. Run tests to verify installation
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
# 13. Disk-mount privilege wiring (sudoers + fuse group)
# =========================================================================
# disk_mount.py walks a fallback chain for ewfmount + loop-mount:
# (1) direct call, (2) `sudo -n` retry, (3) guestmount FUSE. Direct
# calls succeed only if the user is in the `fuse` group (for
# ewfmount, which is FUSE-based) and has root (for loop-mount,
# which always needs CAP_SYS_ADMIN). Step (2) needs a NOPASSWD
# sudoers entry. Step (3) is the always-available fallback but is
# noticeably slower because it spins up libguestfs. We wire (1)
# and (2) here so the fast path is the default.

info "Configuring disk-mount privileges..."

# Add the invoking user to the `fuse` group so ewfmount can mount
# without sudo. Skip when running as root (no fuse group needed —
# root can do anything anyway).
if [[ "${INVOKING_USER}" != "root" ]] && getent group fuse &>/dev/null; then
    if id -nG "${INVOKING_USER}" | grep -qw fuse; then
        ok "${INVOKING_USER} already in fuse group."
    else
        usermod -aG fuse "${INVOKING_USER}"
        ok "Added ${INVOKING_USER} to fuse group (effective at next login)."
    fi
fi

# Write a tightly-scoped sudoers entry: ewfmount on any path,
# mount with `-o ro*` (so `-o ro,loop` matches) on any args, and
# umount limited to /tmp/sift-guard-mounts/* (the predictable mount
# base from disk_mount._MOUNT_BASE).
#
# `visudo -cf` validates the file before installing it; a broken
# sudoers file blocks sudo for everyone. visudo writes to a tmp
# file, validates, and only then copies to /etc/sudoers.d/ — if
# validation fails we abort cleanly rather than poisoning sudo.
SUDOERS_TMP=$(mktemp /tmp/sift-guard-sudoers-XXXX)
EWFMOUNT_PATH="$(command -v ewfmount || echo /usr/bin/ewfmount)"
MOUNT_PATH="$(command -v mount || echo /usr/bin/mount)"
UMOUNT_PATH="$(command -v umount || echo /usr/bin/umount)"
FUSERMOUNT_PATH="$(command -v fusermount || echo /usr/bin/fusermount)"
cat > "${SUDOERS_TMP}" << SUDOERS
# SIFT-Guard — disk-mount privilege wiring (installed by setup-sift-guard.sh).
# These entries let server/runners/disk_mount.py mount E01 / raw disk
# images read-only without prompting for a password. Scope is the
# narrowest the fallback chain can use: ewfmount on any path (the
# image is passed as argv), mount restricted to read-only options,
# umount + fusermount restricted to the predictable mount base.
${INVOKING_USER} ALL=(root) NOPASSWD: ${EWFMOUNT_PATH}
${INVOKING_USER} ALL=(root) NOPASSWD: ${MOUNT_PATH} -o ro*
${INVOKING_USER} ALL=(root) NOPASSWD: ${UMOUNT_PATH} /tmp/sift-guard-mounts/*
${INVOKING_USER} ALL=(root) NOPASSWD: ${FUSERMOUNT_PATH} -u /tmp/sift-guard-mounts/*
SUDOERS

if visudo -cf "${SUDOERS_TMP}" &>/dev/null; then
    install -m 0440 -o root -g root "${SUDOERS_TMP}" /etc/sudoers.d/sift-guard
    ok "Installed /etc/sudoers.d/sift-guard."
else
    warn "Sudoers validation failed; not installing. Disk mount will fall back"
    warn "to guestmount (slower but does not need sudo)."
fi
rm -f "${SUDOERS_TMP}"

# Verification.
if command -v ewfmount &>/dev/null; then
    ok "ewfmount available: $(ewfmount -V 2>&1 | head -1)"
else
    warn "ewfmount not found on PATH. Disk-image (E01) analysis will rely on"
    warn "guestmount only — slower but functional. Install ewf-tools to fix."
fi
if id -nG "${INVOKING_USER}" 2>/dev/null | grep -qw fuse; then
    ok "${INVOKING_USER} is in fuse group (effective in new shells)."
else
    warn "${INVOKING_USER} not currently in fuse group; ewfmount will need sudo"
    warn "until the user logs out and back in."
fi

# =========================================================================
# 14. Smoke test
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
echo "  1. Authenticate Claude Code (one-time, opens a browser):"
echo "     claude login"
echo "     (No API key needed — your Max subscription handles auth.)"
echo ""
echo "  2. Drop evidence in a folder and analyze:"
echo "     sift-guard analyze /path/to/evidence/"
echo ""
echo "  3. View results:"
echo "     cat results-*/report.md"
echo ""
echo "  Example:"
echo "     mkdir -p /cases/case-001/evidence"
echo "     cp /seized/memory.raw /cases/case-001/evidence/"
echo "     cp /seized/disk.E01 /cases/case-001/evidence/"
echo "     sift-guard analyze /cases/case-001/evidence \\"
echo "         --output-dir /cases/case-001/results"
echo ""
echo "  Preview mode (no token cost):"
echo "     sift-guard analyze /cases/case-001/evidence --scan-only"
echo "     sift-guard mock-run        # show what real-time output looks like"
echo ""
echo "  Install: ${INSTALL_DIR}"
echo "  MCP:     ${INSTALL_DIR}/.mcp.json"
echo "  Logs:    <output-dir>/audit/"
echo ""
echo "  For help: sift-guard --help"
echo ""
