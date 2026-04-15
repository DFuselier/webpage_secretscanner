#!/usr/bin/env bash
# install_tools.sh
# Installs the complementary passive analysis tools.
# Run once after setting up the Python virtualenv.
#
# Requirements:
#   - Go 1.21+  (for jsluice, trufflehog)
#   - Node.js   (for source-map-explorer)
#   - pip       (for gitleaks Python wrapper or direct binary)
#
# For authorized security research and bug bounty use only.

set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[-]${NC} $*"; }

# ---------------------------------------------------------------------------
# Check prerequisites
# ---------------------------------------------------------------------------

check_cmd() {
    if ! command -v "$1" &>/dev/null; then
        error "Required tool not found: $1"
        echo "    Install it and re-run this script."
        return 1
    fi
}

info "Checking prerequisites..."
MISSING=0
check_cmd go   || MISSING=1
check_cmd node || MISSING=1
check_cmd npm  || MISSING=1
check_cmd pip3 || MISSING=1

if [[ $MISSING -eq 1 ]]; then
    error "One or more prerequisites are missing. Aborting."
    exit 1
fi

GO_VERSION=$(go version | awk '{print $3}')
info "Go: $GO_VERSION"
info "Node: $(node --version)"
echo

# ---------------------------------------------------------------------------
# Python dependencies (scanner itself)
# ---------------------------------------------------------------------------

info "Installing Python dependencies..."
pip3 install -q -r requirements.txt --break-system-packages 2>/dev/null || \
pip3 install -q -r requirements.txt
info "Python deps installed."
echo

# ---------------------------------------------------------------------------
# TruffleHog (Go binary -- entropy + regex secret scanner)
# ---------------------------------------------------------------------------

info "Installing TruffleHog..."
if command -v trufflehog &>/dev/null; then
    warn "trufflehog already installed: $(trufflehog --version 2>&1 | head -1)"
else
    go install github.com/trufflesecurity/trufflehog/v3@latest
    info "trufflehog installed."
fi
echo

# ---------------------------------------------------------------------------
# jsluice (Go binary -- structured secret + endpoint extractor)
# ---------------------------------------------------------------------------

info "Installing jsluice..."
if command -v jsluice &>/dev/null; then
    warn "jsluice already installed."
else
    go install github.com/BishopFox/jsluice/cmd/jsluice@latest
    info "jsluice installed."
fi
echo

# ---------------------------------------------------------------------------
# Gitleaks (Go binary -- secret scanning with broad ruleset)
# ---------------------------------------------------------------------------

info "Installing gitleaks..."
if command -v gitleaks &>/dev/null; then
    warn "gitleaks already installed: $(gitleaks version 2>&1 | head -1)"
else
    # Try go install first; fall back to manual binary download
    go install github.com/gitleaks/gitleaks/v8@latest 2>/dev/null && \
        info "gitleaks installed via go." || {
        warn "go install failed, downloading release binary..."
        OS=$(uname -s | tr '[:upper:]' '[:lower:]')
        ARCH=$(uname -m)
        [[ "$ARCH" == "x86_64" ]] && ARCH="x64"
        [[ "$ARCH" == "aarch64" ]] && ARCH="arm64"
        GITLEAKS_VERSION="8.18.4"
        TARBALL="gitleaks_${GITLEAKS_VERSION}_${OS}_${ARCH}.tar.gz"
        URL="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/${TARBALL}"
        curl -sL "$URL" -o /tmp/gitleaks.tar.gz
        tar -xzf /tmp/gitleaks.tar.gz -C /tmp gitleaks
        sudo mv /tmp/gitleaks /usr/local/bin/gitleaks
        rm -f /tmp/gitleaks.tar.gz
        info "gitleaks installed via binary."
    }
fi
echo

# ---------------------------------------------------------------------------
# source-map-explorer (npm -- reconstructs source from .map files)
# ---------------------------------------------------------------------------

info "Installing source-map-explorer..."
if command -v source-map-explorer &>/dev/null; then
    warn "source-map-explorer already installed."
else
    npm install -g source-map-explorer --silent
    info "source-map-explorer installed."
fi
echo

# ---------------------------------------------------------------------------
# Verify Go binaries are on PATH
# ---------------------------------------------------------------------------

GOPATH_BIN="$(go env GOPATH)/bin"
if [[ ":$PATH:" != *":$GOPATH_BIN:"* ]]; then
    warn "Go bin directory is not in your PATH."
    echo    "    Add this to your ~/.bashrc or ~/.zshrc:"
    echo    "      export PATH=\"\$PATH:$GOPATH_BIN\""
    echo    "    Then run: source ~/.bashrc"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo
info "Installation complete. Tool status:"
echo

TOOLS=("trufflehog" "jsluice" "gitleaks" "source-map-explorer")
for tool in "${TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        echo -e "  ${GREEN}OK${NC}  $tool"
    else
        echo -e "  ${RED}MISSING${NC}  $tool  (check Go PATH)"
    fi
done

echo
info "Run './analyze.sh --help' to see the analysis pipeline options."
