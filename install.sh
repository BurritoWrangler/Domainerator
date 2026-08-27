#!/usr/bin/env bash
#
# Domainerator installer.
#
# Installs Domainerator and its external tool dependencies on a Linux
# pentest host (built for Kali). Uses pipx so each tool lands in its own
# isolated environment, which is required on PEP 668 "externally managed"
# distros like modern Kali/Debian.
#
# Usage:
#   ./install.sh              # install Domainerator + all external tools
#   ./install.sh --core-only  # install only Domainerator (skip external tools)
#   ./install.sh --no-tools   # alias for --core-only
#
# Idempotent: re-running upgrades/reinstalls in place.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE_ONLY=0

for arg in "$@"; do
    case "$arg" in
        --core-only|--no-tools) CORE_ONLY=1 ;;
        -h|--help)
            grep '^#' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "unknown option: $arg" >&2
            exit 2
            ;;
    esac
done

info()  { printf '\033[1;34m[*]\033[0m %s\n' "$*"; }
ok()    { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn()  { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
err()   { printf '\033[1;31m[-]\033[0m %s\n' "$*" >&2; }

# --- prerequisites --------------------------------------------------------

if ! command -v python3 >/dev/null 2>&1; then
    err "python3 not found. Install Python 3.11+ first."
    exit 1
fi

PYVER="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
info "Found Python ${PYVER}"
python3 - <<'PY' || { echo "Domainerator requires Python 3.11+"; exit 1; }
import sys
raise SystemExit(0 if sys.version_info[:2] >= (3, 11) else 1)
PY

# Ensure pipx is present. Prefer the distro package, fall back to pip --user.
if ! command -v pipx >/dev/null 2>&1; then
    info "pipx not found; attempting to install it"
    if command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update -y && sudo apt-get install -y pipx
    else
        python3 -m pip install --user pipx
    fi
    python3 -m pipx ensurepath || true
    # Make pipx available in the current shell session.
    export PATH="$HOME/.local/bin:$PATH"
fi

if ! command -v pipx >/dev/null 2>&1; then
    err "pipx is still not on PATH. Open a new shell (so ~/.local/bin is on PATH) and re-run."
    exit 1
fi
ok "pipx available: $(command -v pipx)"

# --- install Domainerator -------------------------------------------------

info "Installing Domainerator from ${SCRIPT_DIR}"
pipx install --force "${SCRIPT_DIR}"
ok "Domainerator installed. Try: domainerator --help"

if [ "$CORE_ONLY" -eq 1 ]; then
    warn "Skipping external tools (--core-only). Install them yourself to enable checks."
    exit 0
fi

# --- external tools -------------------------------------------------------
# Each tool is installed in its own pipx environment. Failures are warned
# about, not fatal, so a single unavailable package doesn't abort the rest.

install_pipx() {
    local name="$1"; shift
    local pkg="$1"; shift
    if command -v "$name" >/dev/null 2>&1; then
        ok "$name already present"
        return 0
    fi
    info "Installing $name ($pkg)"
    if pipx install "$pkg"; then
        ok "$name installed"
    else
        warn "failed to install $pkg via pipx; install it manually"
    fi
}

# NetExec (nxc) - core SMB/LDAP engine.
install_pipx nxc "git+https://github.com/Pennyw0rth/NetExec"

# Certipy - AD CS (ESC1-ESC11).
install_pipx certipy "certipy-ad"

# Impacket - GetNPUsers/secretsdump/addcomputer/etc.
install_pipx impacket-GetNPUsers "impacket"

# BloodHound-CE collector.
install_pipx bloodhound-python "bloodhound-ce"

echo
ok "Done. Verify tool availability with:  domainerator --help  and  domainerator -t <dc> -v --dry-run"
warn "Some tools (e.g. NetExec) are large; ensure they finished before running against a target."
