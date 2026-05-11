#!/usr/bin/env bash
# ============================================================================
# SIFT-Guard — Turnkey Setup (main branch)
#
# Run this on a fresh SIFT Workstation VM or any Ubuntu/Debian 22.04+.
# It installs everything needed to analyze forensic evidence with one
# command, using Claude Code as the agent harness — no API key required
# for users with a Max subscription.
#
# Usage:
#   chmod +x setup-sift-guard.sh
#   sudo ./setup-sift-guard.sh
#
# After setup, switch to your normal user and run:
#   claude login                        # one-time auth (Max subscription OK)
#   sift-guard analyze /path/to/evidence/folder
#
# Design rules for this script:
#
#   1. No ``set -e``. Errors are handled manually with an error
#      counter so the operator sees every failure at once, not just
#      the first one. The component-status table at the end is the
#      source of truth.
#   2. No silent ``2>/dev/null``. Every failure is visible; install
#      logs for failed packages are saved to /tmp/sift-guard-install-
#      <pkg>.log.
#   3. Per-package ``apt-get install``, not one giant call. One
#      conflict (SIFT-PPA-shipped libewf vs upstream ewf-tools) used
#      to take the entire script down.
# ============================================================================

# Bash safety: pipefail + nounset, but NOT errexit — we handle errors
# explicitly. Without -u a typo in a variable name silently turns into
# empty string and an apt install of literally nothing.
set -uo pipefail

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# --- Error / warning counters; component status map ---
ERROR_COUNT=0
WARNING_COUNT=0

# Component name → status (one of: ok / fail / warn / skip)
declare -A COMPONENT_STATUS
# Component name → human-readable detail (version, count, etc.)
declare -A COMPONENT_DETAIL
# Ordered list of component names (associative arrays don't preserve order)
COMPONENT_ORDER=()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; WARNING_COUNT=$((WARNING_COUNT + 1)); }
fail()  { echo -e "${RED}[FAIL]${NC}  $*"; ERROR_COUNT=$((ERROR_COUNT + 1)); }

# Hard-fail (used only for pre-flight checks where continuing makes no
# sense — root check, network check on hard fail).
die() { echo -e "${RED}[FATAL]${NC} $*"; exit 1; }

# Record a component's outcome for the summary table.
#
#   record_component <name> <status> [detail...]
#
# status: ok | fail | warn | skip
# detail: free-form, prints after the component name in the table.
record_component() {
    local name="$1"; shift
    local status="$1"; shift
    local detail="$*"
    if [[ -z "${COMPONENT_STATUS[$name]+x}" ]]; then
        COMPONENT_ORDER+=("$name")
    fi
    COMPONENT_STATUS["$name"]="$status"
    COMPONENT_DETAIL["$name"]="$detail"
}

# Install one apt package, surfacing its log on failure. Returns 0
# on success, 1 on failure. Each call writes /tmp/sift-guard-install-
# <pkg>.log so the operator can diff what each package complained
# about — preferable to one mega-log on a single apt-get install.
try_apt_install() {
    local pkg="$1"
    local logfile="/tmp/sift-guard-install-${pkg}.log"
    if dpkg -l "${pkg}" 2>/dev/null | grep -q "^ii"; then
        ok "${pkg} already installed"
        return 0
    fi
    if DEBIAN_FRONTEND=noninteractive apt-get install -y "${pkg}" \
            > "${logfile}" 2>&1; then
        ok "${pkg} installed"
        return 0
    fi
    warn "${pkg} install failed — see ${logfile} (last 5 lines below)"
    tail -5 "${logfile}" | sed 's/^/         /'
    return 1
}

# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------

if [[ $EUID -ne 0 ]]; then
    die "Run this script with sudo: sudo ./setup-sift-guard.sh"
fi

INVOKING_USER="${SUDO_USER:-${USER:-root}}"
if [[ "${INVOKING_USER}" == "root" ]]; then
    warn "Running as root without sudo — claude login will store credentials"
    warn "in /root. Re-run with sudo from a regular user account if that"
    warn "is not what you want."
fi
INVOKING_HOME="$(getent passwd "${INVOKING_USER}" | cut -d: -f6)"
if [[ -z "${INVOKING_HOME}" ]]; then
    INVOKING_HOME="/root"
fi

INSTALL_DIR="/opt/sift-guard"
VENV_DIR="${INSTALL_DIR}/.venv"
VOL_SYMBOLS_DIR="/opt/volatility3/symbols"
SIFT_GUARD_REPO="https://github.com/chang6chang/SIFT-Guard.git"
SIFT_GUARD_BRANCH="main"
VOL_SYMBOLS_URL="https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip"
DEFAULT_OUTPUT_DIR="${INVOKING_HOME}/sift-guard-results"

echo ""
echo "============================================="
echo "  SIFT-Guard — Turnkey Setup (main branch)"
echo "============================================="
echo ""
info "Install directory: ${INSTALL_DIR}"
info "Branch:            ${SIFT_GUARD_BRANCH}"
info "Auth:              Claude Code (claude login)"
info "Invoking user:     ${INVOKING_USER} (home: ${INVOKING_HOME})"
info "Default output:    ${DEFAULT_OUTPUT_DIR}"
echo ""

# ---------------------------------------------------------------------------
# 1. Network check
# ---------------------------------------------------------------------------
# Most setup failures on a fresh SIFT VM are network-shaped: VirtualBox
# NAT not exposing DNS, or the host firewall blocking the package
# mirrors. We test ICMP-to-public + DNS-resolve before touching apt
# so the operator gets a fixable error first instead of an opaque
# "package not found" 30 seconds later.

echo "============================================="
echo "  Step 1/14 — Network connectivity"
echo "============================================="

info "Interface addresses:"
ip -brief addr show | sed 's/^/         /' || true

info "Default route:"
ip route show default | sed 's/^/         /' || \
    echo "         (no default route)"

info "DNS configuration:"
if [[ -r /etc/resolv.conf ]]; then
    grep -E '^(nameserver|search)' /etc/resolv.conf | sed 's/^/         /' || \
        echo "         (no nameserver entries)"
else
    echo "         (/etc/resolv.conf unreadable)"
fi
echo ""

IP_OK=true
DNS_OK=true

info "Pinging 8.8.8.8 (IP-layer connectivity)..."
if ping -c 2 -W 3 8.8.8.8 >/dev/null 2>&1; then
    ok "IP-layer reachable (8.8.8.8)"
else
    fail "8.8.8.8 unreachable — no IP-layer internet"
    IP_OK=false
fi

info "Resolving + pinging google.com (DNS)..."
if ping -c 2 -W 3 google.com >/dev/null 2>&1; then
    ok "DNS resolution works (google.com)"
else
    warn "google.com unreachable or unresolvable"
    DNS_OK=false
fi

if ! ${IP_OK}; then
    echo ""
    echo -e "${RED}No internet connectivity. Common fixes:${NC}"
    echo ""
    echo "  VirtualBox: VM Settings → Network → Adapter 1 → 'NAT'"
    echo "              or 'Bridged Adapter', then restart the VM."
    echo "              Verify with: ip route show default"
    echo ""
    echo "  VMware:     VM Settings → Network Adapter → 'NAT'"
    echo "              or 'Bridged', then restart the VM."
    echo ""
    echo "  Host check: Confirm the host's network is up and that the"
    echo "              hypervisor isn't blocking outbound traffic."
    echo ""
    die "Aborting — restore internet access and re-run this script."
fi

if ${IP_OK} && ! ${DNS_OK}; then
    echo ""
    echo -e "${YELLOW}IP works but DNS resolution failed. Likely fix:${NC}"
    echo ""
    echo "  echo 'nameserver 8.8.8.8' | sudo tee /etc/resolv.conf"
    echo "  echo 'nameserver 1.1.1.1' | sudo tee -a /etc/resolv.conf"
    echo ""
    echo "  Then re-run this script. (systemd-resolved users may need"
    echo "  to edit /etc/systemd/resolved.conf instead.)"
    echo ""
    warn "Continuing — apt may still work via configured mirrors, but"
    warn "expect some downloads to fail. Fix DNS first for cleanest run."
fi
record_component "network" "ok" "$(ip -brief addr show | awk '/UP/{print $1; exit}') reachable"

# ---------------------------------------------------------------------------
# 2. System dependencies — per-package
# ---------------------------------------------------------------------------
# Each package is installed individually so one failure doesn't take
# down the rest of the script. The SIFT Workstation ships its own
# libewf / libguestfs builds via the SIFT PPA, which sometimes
# conflict with the Ubuntu archive's ewf-tools / libguestfs-tools
# packages. We probe for the binaries first and only attempt the
# apt install when missing.

echo ""
echo "============================================="
echo "  Step 2/14 — System dependencies"
echo "============================================="

info "Refreshing apt package index..."
if apt-get update > /tmp/sift-guard-install-apt-update.log 2>&1; then
    ok "apt-get update"
else
    warn "apt-get update reported errors (see /tmp/sift-guard-install-apt-update.log)"
    warn "Continuing — individual installs will surface specific failures."
fi

# Core packages: no SIFT-shipped conflicts, install plainly.
CORE_PKGS=(
    python3
    python3-pip
    python3-venv
    python3-dev
    git
    curl
    wget
    unzip
    build-essential
    ca-certificates
    sleuthkit
    qemu-utils
)

CORE_INSTALL_FAILURES=0
for pkg in "${CORE_PKGS[@]}"; do
    if ! try_apt_install "${pkg}"; then
        CORE_INSTALL_FAILURES=$((CORE_INSTALL_FAILURES + 1))
    fi
done
if [[ ${CORE_INSTALL_FAILURES} -eq 0 ]]; then
    record_component "core-pkgs" "ok" "${#CORE_PKGS[@]} packages"
else
    record_component "core-pkgs" "warn" \
        "${CORE_INSTALL_FAILURES} of ${#CORE_PKGS[@]} failed"
fi

# SIFT-shipped-or-Ubuntu-archive: ewf-tools (provides ewfmount),
# libguestfs-tools (provides guestmount). The SIFT PPA's libewf3 /
# libguestfs0 packages conflict with the archive's tool packages.
# Skip the apt install when the binaries are already there.
info "Checking ewfmount / guestmount (may be SIFT-PPA-shipped)..."

if command -v ewfmount >/dev/null 2>&1; then
    ok "ewfmount already present at $(command -v ewfmount)"
    record_component "ewfmount" "ok" "$(ewfmount -V 2>&1 | head -1 | tr -d '\n')"
else
    info "ewfmount missing; attempting ewf-tools install..."
    if try_apt_install ewf-tools; then
        if command -v ewfmount >/dev/null 2>&1; then
            record_component "ewfmount" "ok" "$(ewfmount -V 2>&1 | head -1 | tr -d '\n')"
        else
            record_component "ewfmount" "warn" "package installed but binary missing"
        fi
    else
        record_component "ewfmount" "warn" \
            "ewf-tools install failed (likely SIFT-PPA conflict); guestmount fallback only"
    fi
fi

if command -v guestmount >/dev/null 2>&1; then
    ok "guestmount already present at $(command -v guestmount)"
    record_component "guestmount" "ok" "$(guestmount --version 2>&1 | head -1 | tr -d '\n')"
else
    info "guestmount missing; attempting libguestfs-tools install..."
    if try_apt_install libguestfs-tools; then
        if command -v guestmount >/dev/null 2>&1; then
            record_component "guestmount" "ok" \
                "$(guestmount --version 2>&1 | head -1 | tr -d '\n')"
        else
            record_component "guestmount" "warn" "package installed but binary missing"
        fi
    else
        record_component "guestmount" "warn" \
            "libguestfs-tools install failed; ewfmount-only mount path"
    fi
fi

# libewf-dev is the development headers; needed only when building
# pyewf from source. Tolerate failure quietly.
try_apt_install libewf-dev >/dev/null || \
    warn "libewf-dev unavailable; pyewf source builds may fail later"

# ---------------------------------------------------------------------------
# 3. Python 3.11+
# ---------------------------------------------------------------------------

echo ""
echo "============================================="
echo "  Step 3/14 — Python 3.11+"
echo "============================================="

PYTHON_VERSION="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")' 2>/dev/null || echo "unknown")"
PYTHON_MAJOR="$(echo "$PYTHON_VERSION" | cut -d. -f1)"
PYTHON_MINOR="$(echo "$PYTHON_VERSION" | cut -d. -f2)"

if [[ "${PYTHON_MAJOR}" != "3" ]] || [[ "${PYTHON_MINOR}" -lt 11 ]]; then
    warn "Python ${PYTHON_VERSION} detected. SIFT-Guard needs 3.11+."
    info "Installing Python 3.12 via the deadsnakes PPA..."
    try_apt_install software-properties-common
    if add-apt-repository -y ppa:deadsnakes/ppa \
            > /tmp/sift-guard-install-deadsnakes.log 2>&1; then
        apt-get update > /tmp/sift-guard-install-apt-update-2.log 2>&1 || true
        for p in python3.12 python3.12-venv python3.12-dev; do
            try_apt_install "$p"
        done
        PYTHON_BIN="python3.12"
        if command -v python3.12 >/dev/null 2>&1; then
            ok "Python 3.12 installed."
            record_component "python" "ok" "$(python3.12 --version 2>&1 | head -1)"
        else
            record_component "python" "fail" "python3.12 install failed; see /tmp/sift-guard-install-python3.12.log"
        fi
    else
        fail "deadsnakes PPA add-apt-repository failed (see /tmp/sift-guard-install-deadsnakes.log)"
        record_component "python" "fail" "Python ${PYTHON_VERSION} too old; deadsnakes unavailable"
    fi
else
    PYTHON_BIN="python3"
    ok "Python ${PYTHON_VERSION} — compatible."
    record_component "python" "ok" "Python ${PYTHON_VERSION}"
fi

# ---------------------------------------------------------------------------
# 4. Node.js + Claude Code
# ---------------------------------------------------------------------------

echo ""
echo "============================================="
echo "  Step 4/14 — Node.js + Claude Code"
echo "============================================="

if command -v node >/dev/null 2>&1; then
    NODE_VERSION="$(node --version)"
    ok "Node.js found: ${NODE_VERSION}"
    record_component "node" "ok" "${NODE_VERSION}"
else
    info "Installing Node.js LTS via NodeSource..."
    if curl -fsSL https://deb.nodesource.com/setup_lts.x \
            > /tmp/sift-guard-install-nodesource-setup.sh 2>&1; then
        if bash /tmp/sift-guard-install-nodesource-setup.sh \
                > /tmp/sift-guard-install-nodesource.log 2>&1; then
            try_apt_install nodejs
        else
            fail "NodeSource setup script failed (see /tmp/sift-guard-install-nodesource.log)"
        fi
    else
        fail "Could not download NodeSource setup script — check network"
    fi
    if command -v node >/dev/null 2>&1; then
        record_component "node" "ok" "$(node --version)"
    else
        record_component "node" "fail" "Claude Code requires Node.js"
    fi
fi

if command -v claude >/dev/null 2>&1; then
    CLAUDE_VERSION="$(claude --version 2>&1 | head -1 || echo unknown)"
    ok "Claude Code already installed: ${CLAUDE_VERSION}"
    record_component "claude-code" "ok" "${CLAUDE_VERSION}"
else
    info "Installing Claude Code globally via npm..."
    if npm install -g @anthropic-ai/claude-code \
            > /tmp/sift-guard-install-claude-code.log 2>&1; then
        if command -v claude >/dev/null 2>&1; then
            CLAUDE_VERSION="$(claude --version 2>&1 | head -1)"
            ok "Claude Code installed: ${CLAUDE_VERSION}"
            record_component "claude-code" "ok" "${CLAUDE_VERSION}"
        else
            warn "npm install succeeded but 'claude' not on PATH. Add"
            warn "  export PATH=\"\$(npm config get prefix)/bin:\$PATH\""
            warn "to your shell rc, or symlink the binary into /usr/local/bin."
            record_component "claude-code" "warn" "installed but not on PATH"
        fi
    else
        fail "Claude Code install failed (see /tmp/sift-guard-install-claude-code.log)"
        record_component "claude-code" "fail" "npm install failed"
    fi
fi

# ---------------------------------------------------------------------------
# 5. Volatility 3
# ---------------------------------------------------------------------------

echo ""
echo "============================================="
echo "  Step 5/14 — Volatility 3"
echo "============================================="

VOL_BIN=""
VOL_VERSION_STR=""
if command -v vol >/dev/null 2>&1; then
    VOL_BIN="vol"
elif command -v vol.py >/dev/null 2>&1; then
    VOL_BIN="vol.py"
fi

if [[ -n "${VOL_BIN}" ]]; then
    # Vol 3 has no --version flag; the version lives in
    # volatility3.framework.constants.PACKAGE_VERSION.
    VOL_VERSION_STR="$(python3 -c \
        'from volatility3.framework import constants; print(constants.PACKAGE_VERSION)' \
        2>/dev/null || echo "unknown")"
    ok "Volatility 3 already installed: ${VOL_VERSION_STR}"
    record_component "volatility3" "ok" "${VOL_VERSION_STR}"
else
    info "Installing Volatility 3 via pip..."
    if ${PYTHON_BIN} -m pip install --break-system-packages volatility3 \
            > /tmp/sift-guard-install-volatility3.log 2>&1; then
        VOL_VERSION_STR="$(${PYTHON_BIN} -c \
            'from volatility3.framework import constants; print(constants.PACKAGE_VERSION)' \
            2>/dev/null || echo "unknown")"
        ok "Volatility 3 installed (${VOL_VERSION_STR})"
        record_component "volatility3" "ok" "${VOL_VERSION_STR}"
    else
        fail "Volatility 3 install failed (see /tmp/sift-guard-install-volatility3.log)"
        record_component "volatility3" "fail" "memory analysis unavailable"
    fi
fi

# ---------------------------------------------------------------------------
# 6. Windows symbol tables
# ---------------------------------------------------------------------------

echo ""
echo "============================================="
echo "  Step 6/14 — Volatility Windows symbols"
echo "============================================="

if [[ -d "${VOL_SYMBOLS_DIR}/windows" ]] && \
       find "${VOL_SYMBOLS_DIR}/windows" -name "*.json.xz" -print -quit \
       | grep -q .; then
    SYMBOL_COUNT="$(find "${VOL_SYMBOLS_DIR}/windows" -name "*.json.xz" | wc -l)"
    ok "Windows symbols already present (${SYMBOL_COUNT} ISF files)."
    record_component "vol-symbols" "ok" "${SYMBOL_COUNT} ISF files"
else
    info "Downloading Windows symbol tables (~300MB)..."
    mkdir -p "${VOL_SYMBOLS_DIR}/windows"
    TEMP_ZIP="$(mktemp /tmp/vol-symbols-XXXX.zip)"
    DOWNLOAD_OK=true
    if ! wget --show-progress -O "${TEMP_ZIP}" "${VOL_SYMBOLS_URL}" \
            2> /tmp/sift-guard-install-vol-symbols-wget.log; then
        warn "wget failed; trying curl..."
        if ! curl -L -o "${TEMP_ZIP}" "${VOL_SYMBOLS_URL}" \
                2> /tmp/sift-guard-install-vol-symbols-curl.log; then
            fail "Vol symbol download failed (logs in /tmp/)"
            DOWNLOAD_OK=false
        fi
    fi
    if ${DOWNLOAD_OK}; then
        info "Extracting symbols..."
        if unzip -qo "${TEMP_ZIP}" -d "${VOL_SYMBOLS_DIR}/windows/" \
                2> /tmp/sift-guard-install-vol-symbols-unzip.log; then
            SYMBOL_COUNT="$(find "${VOL_SYMBOLS_DIR}/windows" -name "*.json.xz" | wc -l)"
            ok "Windows symbols installed (${SYMBOL_COUNT} ISF files)."
            record_component "vol-symbols" "ok" "${SYMBOL_COUNT} ISF files"
        else
            fail "Symbol unzip failed"
            record_component "vol-symbols" "fail" "extraction failed"
        fi
        rm -f "${TEMP_ZIP}"
    else
        record_component "vol-symbols" "fail" "download failed"
    fi
fi

# ---------------------------------------------------------------------------
# 7. Disk forensic tools
# ---------------------------------------------------------------------------

echo ""
echo "============================================="
echo "  Step 7/14 — Disk forensic tools"
echo "============================================="

# log2timeline.py (plaso).
if command -v log2timeline.py >/dev/null 2>&1; then
    L2T_VER="$(log2timeline.py --version 2>&1 | head -1 | tr -d '\n')"
    ok "log2timeline.py found: ${L2T_VER}"
    record_component "log2timeline" "ok" "${L2T_VER}"
else
    info "Installing plaso (log2timeline.py)..."
    if ${PYTHON_BIN} -m pip install --break-system-packages plaso \
            > /tmp/sift-guard-install-plaso.log 2>&1; then
        if command -v log2timeline.py >/dev/null 2>&1; then
            ok "plaso installed"
            record_component "log2timeline" "ok" \
                "$(log2timeline.py --version 2>&1 | head -1 | tr -d '\n')"
        else
            warn "plaso installed but log2timeline.py not on PATH"
            record_component "log2timeline" "warn" "installed but not on PATH"
        fi
    else
        warn "plaso install failed — disk MFT timeline analysis unavailable"
        record_component "log2timeline" "warn" \
            "plaso install failed; MFT timeline unavailable"
    fi
fi

# python-evtx for EVTX event-log parsing.
if ${PYTHON_BIN} -c "import Evtx" 2>/dev/null; then
    ok "python-evtx found"
    record_component "python-evtx" "ok" "import Evtx OK"
else
    info "Installing python-evtx..."
    if ${PYTHON_BIN} -m pip install --break-system-packages python-evtx \
            > /tmp/sift-guard-install-python-evtx.log 2>&1; then
        ok "python-evtx installed"
        record_component "python-evtx" "ok" "installed"
    else
        warn "python-evtx install failed"
        record_component "python-evtx" "warn" "install failed"
    fi
fi

# RegRipper — registry-hive parser; optional, install requires manual
# step on most distros so we just probe.
if command -v rip.pl >/dev/null 2>&1 || command -v regripper >/dev/null 2>&1; then
    ok "RegRipper found"
    record_component "regripper" "ok" "available"
else
    warn "RegRipper not found. Registry analysis will be unavailable."
    warn "Install manually: https://github.com/keydet89/RegRipper3.0"
    record_component "regripper" "warn" "missing (optional)"
fi

# ---------------------------------------------------------------------------
# 8. Clone or update the SIFT-Guard repo
# ---------------------------------------------------------------------------

echo ""
echo "============================================="
echo "  Step 8/14 — Clone / update SIFT-Guard"
echo "============================================="

if [[ -d "${INSTALL_DIR}/.git" ]]; then
    info "Existing checkout found; pulling latest..."
    if cd "${INSTALL_DIR}" && \
            git fetch origin > /tmp/sift-guard-git-fetch.log 2>&1 && \
            git checkout "${SIFT_GUARD_BRANCH}" > /tmp/sift-guard-git-checkout.log 2>&1 && \
            git pull origin "${SIFT_GUARD_BRANCH}" > /tmp/sift-guard-git-pull.log 2>&1; then
        ok "Updated to latest ${SIFT_GUARD_BRANCH}"
        record_component "repo" "ok" "$(git -C ${INSTALL_DIR} rev-parse --short HEAD)"
    else
        fail "Git update failed — see /tmp/sift-guard-git-*.log"
        record_component "repo" "fail" "pull failed"
    fi
else
    info "Cloning repository..."
    if git clone -b "${SIFT_GUARD_BRANCH}" "${SIFT_GUARD_REPO}" "${INSTALL_DIR}" \
            > /tmp/sift-guard-git-clone.log 2>&1; then
        ok "Cloned to ${INSTALL_DIR}"
        record_component "repo" "ok" "$(git -C ${INSTALL_DIR} rev-parse --short HEAD)"
    else
        fail "Git clone failed — see /tmp/sift-guard-git-clone.log"
        record_component "repo" "fail" "clone failed"
    fi
fi

cd "${INSTALL_DIR}" 2>/dev/null || die "Cannot cd into ${INSTALL_DIR}"

# ---------------------------------------------------------------------------
# 9. Python virtualenv + SIFT-Guard package
# ---------------------------------------------------------------------------

echo ""
echo "============================================="
echo "  Step 9/14 — Virtualenv + pip install"
echo "============================================="

if [[ ! -d "${VENV_DIR}" ]]; then
    info "Creating virtual environment at ${VENV_DIR}..."
    if ${PYTHON_BIN} -m venv "${VENV_DIR}" \
            > /tmp/sift-guard-install-venv.log 2>&1; then
        ok "Virtualenv created"
    else
        fail "Virtualenv creation failed (see /tmp/sift-guard-install-venv.log)"
        record_component "venv" "fail" "venv create failed"
    fi
else
    ok "Virtualenv already exists at ${VENV_DIR}"
fi

# shellcheck source=/dev/null
source "${VENV_DIR}/bin/activate"

info "Upgrading pip..."
if pip install --upgrade pip > /tmp/sift-guard-install-pip-upgrade.log 2>&1; then
    ok "pip upgraded"
else
    warn "pip upgrade failed — continuing with existing version"
fi

info "Installing SIFT-Guard editable + dev extras..."
if pip install -e ".[dev]" > /tmp/sift-guard-install-pip-editable.log 2>&1; then
    ok "SIFT-Guard installed in virtualenv"
    record_component "venv" "ok" "$(${VENV_DIR}/bin/python --version 2>&1)"
else
    fail "pip install failed (see /tmp/sift-guard-install-pip-editable.log)"
    record_component "venv" "fail" "package install failed"
fi

# ---------------------------------------------------------------------------
# 10. RAG index (optional)
# ---------------------------------------------------------------------------

echo ""
echo "============================================="
echo "  Step 10/14 — RAG index"
echo "============================================="

RAG_INDEX_FILE="${INSTALL_DIR}/rag/data/attack-enterprise.faiss"
if [[ -f "${RAG_INDEX_FILE}" ]]; then
    RAG_BYTES="$(stat -c%s "${RAG_INDEX_FILE}" 2>/dev/null || echo "?")"
    ok "RAG index already exists (${RAG_BYTES} bytes)"
    record_component "rag-index" "ok" "${RAG_BYTES} bytes"
else
    info "Installing RAG extras (sentence-transformers + faiss-cpu, ~2GB)..."
    if pip install -e ".[rag]" > /tmp/sift-guard-install-rag.log 2>&1; then
        info "Building RAG index from MITRE ATT&CK + Sigma corpus..."
        if python -m rag.build_index > /tmp/sift-guard-rag-build.log 2>&1; then
            if [[ -f "${RAG_INDEX_FILE}" ]]; then
                RAG_BYTES="$(stat -c%s "${RAG_INDEX_FILE}" 2>/dev/null || echo "?")"
                ok "RAG index built (${RAG_BYTES} bytes)"
                record_component "rag-index" "ok" "${RAG_BYTES} bytes"
            else
                warn "RAG build reported success but index file missing"
                record_component "rag-index" "warn" "build silent failure"
            fi
        else
            warn "RAG index build failed (see /tmp/sift-guard-rag-build.log)"
            record_component "rag-index" "warn" "build failed; rag_query unavailable"
        fi
    else
        warn "RAG extras install failed (see /tmp/sift-guard-install-rag.log)"
        record_component "rag-index" "warn" "extras install failed"
    fi
fi

# ---------------------------------------------------------------------------
# 11. MCP server config
# ---------------------------------------------------------------------------

echo ""
echo "============================================="
echo "  Step 11/14 — MCP server config"
echo "============================================="

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
if chown "${INVOKING_USER}":"${INVOKING_USER}" "${MCP_JSON}"; then
    ok "Wrote ${MCP_JSON} (owner: ${INVOKING_USER})"
    record_component "mcp-config" "ok" "${MCP_JSON}"
else
    warn "Wrote ${MCP_JSON} but chown to ${INVOKING_USER} failed"
    record_component "mcp-config" "warn" "ownership not set"
fi

# ---------------------------------------------------------------------------
# 12. Disk-mount privilege wiring (sudoers + fuse group + env defaults)
# ---------------------------------------------------------------------------
# disk_mount.py walks a fallback chain for ewfmount + loop-mount:
# (1) direct call, (2) `sudo -n` retry, (3) guestmount FUSE. We wire
# steps (1) and (2) here so the fast path is the default. Step (3) is
# unconditional fallback handled by libguestfs.

echo ""
echo "============================================="
echo "  Step 12/14 — Disk-mount privileges + env defaults"
echo "============================================="

# Ensure the fuse group exists (some minimal Ubuntu installs lack it).
if ! getent group fuse >/dev/null 2>&1; then
    info "Creating fuse group..."
    if groupadd fuse > /tmp/sift-guard-groupadd-fuse.log 2>&1; then
        ok "Created fuse group"
    else
        warn "Could not create fuse group (see /tmp/sift-guard-groupadd-fuse.log)"
    fi
fi

# Add the invoking user to fuse. Skip when running as root — fuse
# membership is a no-op there.
if [[ "${INVOKING_USER}" != "root" ]] && getent group fuse >/dev/null 2>&1; then
    if id -nG "${INVOKING_USER}" | tr ' ' '\n' | grep -qw fuse; then
        ok "${INVOKING_USER} already in fuse group"
        record_component "fuse-group" "ok" "${INVOKING_USER}"
    else
        if usermod -aG fuse "${INVOKING_USER}" \
                > /tmp/sift-guard-usermod-fuse.log 2>&1; then
            ok "Added ${INVOKING_USER} to fuse group"
            warn "fuse group membership takes effect at next login — log out"
            warn "and back in (or run \`newgrp fuse\`) before running sift-guard."
            record_component "fuse-group" "warn" \
                "${INVOKING_USER} (re-login required)"
        else
            warn "usermod -aG fuse ${INVOKING_USER} failed"
            record_component "fuse-group" "fail" "could not add user"
        fi
    fi
else
    record_component "fuse-group" "skip" "root install"
fi

# Sudoers entry. Validate with `visudo -cf` before installing; an
# invalid sudoers file would lock everyone out of sudo.
SUDOERS_TMP="$(mktemp /tmp/sift-guard-sudoers-XXXX)"
EWFMOUNT_PATH="$(command -v ewfmount || echo /usr/bin/ewfmount)"
MOUNT_PATH="$(command -v mount || echo /usr/bin/mount)"
UMOUNT_PATH="$(command -v umount || echo /usr/bin/umount)"
FUSERMOUNT_PATH="$(command -v fusermount || echo /usr/bin/fusermount)"
cat > "${SUDOERS_TMP}" << SUDOERS
# SIFT-Guard — disk-mount privilege wiring (installed by setup-sift-guard.sh).
# Each NOPASSWD entry is scoped to the narrowest shape the fallback
# chain requires:
#   - ewfmount on any path (the image is passed as argv).
#   - mount restricted to read-only options ("-o ro,loop" matches "-o ro*").
#   - umount + fusermount restricted to the predictable mount base.
${INVOKING_USER} ALL=(root) NOPASSWD: ${EWFMOUNT_PATH}
${INVOKING_USER} ALL=(root) NOPASSWD: ${MOUNT_PATH} -o ro*
${INVOKING_USER} ALL=(root) NOPASSWD: ${UMOUNT_PATH} /tmp/sift-guard-mounts/*
${INVOKING_USER} ALL=(root) NOPASSWD: ${FUSERMOUNT_PATH} -u /tmp/sift-guard-mounts/*
SUDOERS

if visudo -cf "${SUDOERS_TMP}" > /tmp/sift-guard-visudo.log 2>&1; then
    install -m 0440 -o root -g root "${SUDOERS_TMP}" /etc/sudoers.d/sift-guard
    ok "Installed /etc/sudoers.d/sift-guard"
    record_component "sudoers" "ok" "configured for ${INVOKING_USER}"
else
    warn "Sudoers validation failed; not installing (see /tmp/sift-guard-visudo.log)"
    warn "Disk mount will fall back to guestmount (slower but root-free)."
    record_component "sudoers" "warn" "validation failed; guestmount fallback only"
fi
rm -f "${SUDOERS_TMP}"

# Env defaults: VOLATILITY3_SYMBOL_DIRS + SIFT_GUARD_OUTPUT_DIR.
# /etc/profile.d/ is sourced by every login shell, so the values
# are picked up by anyone running `sift-guard` from a fresh terminal.
ENV_FILE="/etc/profile.d/sift-guard.sh"
cat > "${ENV_FILE}" << ENVSH
# SIFT-Guard runtime defaults (installed by setup-sift-guard.sh).
# Edit \`/etc/profile.d/sift-guard.sh\` directly to override.

# Tell Volatility 3 where the Windows symbol pack lives. Vol falls
# back to ./symbols and ~/.cache/volatility3/symbols when this is
# unset; we point at the system-wide install for shared use.
export VOLATILITY3_SYMBOL_DIRS="${VOL_SYMBOLS_DIR}"

# Default output directory for \`sift-guard analyze\`. Without this,
# the CLI puts \`results-<timestamp>/\` in the current working
# directory — which lands under /opt/sift-guard/ (root-owned) if
# the operator happened to cd there first. Pointing at the
# invoking user's home avoids that footgun.
export SIFT_GUARD_OUTPUT_DIR="${DEFAULT_OUTPUT_DIR}"
ENVSH
chmod 644 "${ENV_FILE}"
ok "Wrote ${ENV_FILE}"

# Make sure the default output dir actually exists and is writable
# by the invoking user. mkdir -p is idempotent.
if [[ "${INVOKING_USER}" != "root" ]]; then
    install -d -o "${INVOKING_USER}" -g "${INVOKING_USER}" "${DEFAULT_OUTPUT_DIR}"
    ok "Default output dir ${DEFAULT_OUTPUT_DIR} ready"
fi
record_component "output-dir" "ok" "${DEFAULT_OUTPUT_DIR}"

# ---------------------------------------------------------------------------
# 13. Global CLI wrapper + test suite
# ---------------------------------------------------------------------------

echo ""
echo "============================================="
echo "  Step 13/14 — Global wrapper + test suite"
echo "============================================="

info "Installing /usr/local/bin/sift-guard wrapper..."
cat > /usr/local/bin/sift-guard << 'WRAPPER'
#!/usr/bin/env bash
# SIFT-Guard wrapper — activates the install venv and runs the CLI.
INSTALL_DIR="/opt/sift-guard"
# shellcheck source=/dev/null
source "${INSTALL_DIR}/.venv/bin/activate"
exec python -m sift_guard.cli "$@"
WRAPPER
chmod +x /usr/local/bin/sift-guard
ok "Wrapper installed"

info "Running the test suite (this takes ~2 minutes)..."
TEST_LOG="/tmp/sift-guard-pytest.log"
cd "${INSTALL_DIR}"
# shellcheck source=/dev/null
source "${VENV_DIR}/bin/activate"
if python -m pytest tests/ -q --tb=line > "${TEST_LOG}" 2>&1; then
    TEST_SUMMARY="$(tail -1 "${TEST_LOG}")"
    ok "Tests passed — ${TEST_SUMMARY}"
    record_component "tests" "ok" "${TEST_SUMMARY}"
else
    TEST_SUMMARY="$(tail -1 "${TEST_LOG}")"
    warn "Some tests failed — ${TEST_SUMMARY}"
    warn "Inspect: cat ${TEST_LOG}"
    record_component "tests" "warn" "${TEST_SUMMARY}"
fi

# ---------------------------------------------------------------------------
# 14. Smoke test
# ---------------------------------------------------------------------------

echo ""
echo "============================================="
echo "  Step 14/14 — Smoke test"
echo "============================================="

if sift-guard --help > /tmp/sift-guard-smoke.log 2>&1; then
    ok "sift-guard CLI responds (--help)"
    record_component "sift-guard" "ok" "ready"
else
    warn "sift-guard --help failed — see /tmp/sift-guard-smoke.log"
    record_component "sift-guard" "fail" "wrapper non-functional"
fi

# ---------------------------------------------------------------------------
# Component status table
# ---------------------------------------------------------------------------

echo ""
echo "============================================="
echo "  Component status"
echo "============================================="
echo ""

# Compute column widths. Names are short and known; detail can be long.
NAME_WIDTH=14
for c in "${COMPONENT_ORDER[@]}"; do
    if [[ ${#c} -gt ${NAME_WIDTH} ]]; then
        NAME_WIDTH=${#c}
    fi
done
NAME_WIDTH=$((NAME_WIDTH + 2))

for c in "${COMPONENT_ORDER[@]}"; do
    status="${COMPONENT_STATUS[$c]}"
    detail="${COMPONENT_DETAIL[$c]:-}"
    label="${c}:"
    case "${status}" in
        ok)
            mark="${GREEN}✓${NC}"
            ;;
        warn)
            mark="${YELLOW}⚠${NC}"
            ;;
        fail)
            mark="${RED}✗${NC}"
            ;;
        skip)
            mark="${CYAN}—${NC}"
            ;;
        *)
            mark="?"
            ;;
    esac
    printf "  %-${NAME_WIDTH}s %-32s %b\n" "${label}" "${detail}" "${mark}"
done

echo ""
if [[ ${ERROR_COUNT} -eq 0 && ${WARNING_COUNT} -eq 0 ]]; then
    echo -e "  ${GREEN}${BOLD}All components OK.${NC}"
elif [[ ${ERROR_COUNT} -eq 0 ]]; then
    echo -e "  ${YELLOW}${BOLD}${WARNING_COUNT} warnings, no errors.${NC}"
    echo "  Setup is functional; review warnings above (typically optional"
    echo "  components like RegRipper or the RAG index)."
else
    echo -e "  ${RED}${BOLD}${ERROR_COUNT} errors, ${WARNING_COUNT} warnings.${NC}"
    echo "  Some core components failed. Inspect /tmp/sift-guard-install-*.log"
    echo "  for the specific failures, fix them, then re-run this script."
fi
echo ""

# ---------------------------------------------------------------------------
# Next-steps banner
# ---------------------------------------------------------------------------

echo "============================================="
echo -e "  ${GREEN}SIFT-Guard setup complete${NC}"
echo "============================================="
echo ""
echo "  Next steps:"
echo ""
echo "  1. Pick up the new shell environment (fuse group + env vars):"
echo "     - Open a new terminal, OR"
echo "     - In the current shell: source /etc/profile.d/sift-guard.sh"
echo ""
echo "  2. Authenticate Claude Code (one-time, opens a browser):"
echo "     claude login"
echo "     (No API key needed — your Max subscription handles auth.)"
echo ""
echo "  3. Analyze evidence (one command):"
echo "     sift-guard analyze /path/to/evidence/"
echo ""
echo "  4. View results:"
echo "     cat ${DEFAULT_OUTPUT_DIR}/<case>/report.md"
echo ""
echo "  Useful flags:"
echo "     sift-guard analyze <dir> --scan-only       # preview, no tokens"
echo "     sift-guard analyze <dir> --no-parallel     # legacy sequential"
echo "     sift-guard analyze <dir> --output-dir <p>  # override output"
echo "     sift-guard mock-run                        # see live UI"
echo ""
echo "  Install:        ${INSTALL_DIR}"
echo "  MCP:            ${INSTALL_DIR}/.mcp.json"
echo "  Default output: ${DEFAULT_OUTPUT_DIR}"
echo "  Audit logs:     <output-dir>/audit/"
echo "  Install logs:   /tmp/sift-guard-install-*.log"
echo ""
echo "  For help: sift-guard --help"
echo ""

# Exit non-zero when any component is in fail state so CI / wrapper
# scripts can detect bad installs without parsing stdout.
if [[ ${ERROR_COUNT} -gt 0 ]]; then
    exit 1
fi
exit 0
