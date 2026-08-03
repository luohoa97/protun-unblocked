#!/usr/bin/env bash
#
# Copyright (C) 2026 Neil Luo
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation, either version 3 of the License, or (at your
# option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program. If not, see <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later

#
# pvpn installer.
#
#   ./setup.sh              install
#   ./setup.sh --uninstall  remove everything it installed
#
# Installs entirely under $HOME. No root needed for the install itself
# (pvpn asks for sudo at runtime only to clean up a stray kill-switch
# device). Nothing outside these paths is touched:
#
#   ~/.local/bin/pvpn
#   ~/.local/bin/vpn-check
#   ~/.local/share/pvpn/          (python shims)
#
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$HOME/.local/bin"
LIB="$HOME/.local/share/pvpn"

c(){ printf '\033[%sm%s\033[0m\n' "$1" "$2"; }
ok(){ c '1;32' "  ok    $1"; }; bad(){ c '1;31' "  MISS  $1"; }
note(){ c '0;37' "        $1"; }; head_(){ c '1;36' "$1"; }

if [[ "${1:-}" == "--uninstall" ]]; then
    rm -f "$BIN/pvpn" "$BIN/vpn-check"
    rm -rf "$LIB"
    c '1;32' "Removed pvpn. Your Proton config in ~/.config/Proton was left alone."
    echo "To remove that too:  rm -rf ~/.config/Proton ~/.cache/Proton"
    exit 0
fi

head_ "Checking dependencies"
missing=0

if command -v protonvpn >/dev/null; then
    ok "proton-vpn-cli ($(rpm -q --qf '%{version}' proton-vpn-cli 2>/dev/null || echo present))"
else
    bad "proton-vpn-cli - the actual VPN client"
    note "Fedora/Bluefin, via Proton's repo:"
    note "  curl -fsSLO \"https://repo.protonvpn.com/fedora-\$(rpm -E %fedora)-stable/protonvpn-stable-release/protonvpn-stable-release-1.0.4-1.noarch.rpm\""
    note "  sudo dnf install -y ./protonvpn-stable-release-1.0.4-1.noarch.rpm"
    note "  sudo dnf install -y proton-vpn-cli"
    note "On an rpm-ostree system use 'rpm-ostree install' instead of dnf."
    missing=1
fi

if command -v torsocks >/dev/null; then ok "torsocks"
else
    bad "torsocks - needed only if Proton's API is blocked on your network"
    note "  sudo dnf install -y tor torsocks && sudo systemctl enable --now tor"
fi

command -v curl    >/dev/null && ok "curl"    || { bad "curl";    missing=1; }
command -v nmcli   >/dev/null && ok "nmcli"   || { bad "nmcli (NetworkManager)"; missing=1; }
[[ -x /usr/bin/python3 ]]     && ok "system python3" || { bad "/usr/bin/python3"; missing=1; }

# pvpn's shims must be importable by the SYSTEM python that runs protonvpn,
# not by a Homebrew/pyenv python. Warn if `python3` on PATH is a different one.
if [[ "$(command -v python3)" != "/usr/bin/python3" ]]; then
    note "note: 'python3' on your PATH is $(command -v python3)"
    note "      pvpn always calls /usr/bin/python3 explicitly, so this is fine."
fi

if (( missing )); then
    echo; c '1;31' "Install the missing pieces above, then re-run ./setup.sh"
    exit 1
fi

echo
head_ "Installing"
mkdir -p "$BIN" "$LIB"
install -m755 "$SRC/bin/pvpn"      "$BIN/pvpn";      ok "$BIN/pvpn"
install -m755 "$SRC/bin/vpn-check" "$BIN/vpn-check"; ok "$BIN/vpn-check"
install -m644 "$SRC/lib/sitecustomize.py" "$LIB/";   ok "$LIB/sitecustomize.py"
install -m644 "$SRC/lib/aiodns.py"        "$LIB/";   ok "$LIB/aiodns.py"
[[ -f "$SRC/lib/debug-signin.py" ]] && install -m755 "$SRC/lib/debug-signin.py" "$LIB/" && ok "$LIB/debug-signin.py"
install -m755 "$SRC/lib/pvpn-scan.py"   "$LIB/";   ok "$LIB/pvpn-scan.py"

# --- optional libadwaita GUI ------------------------------------------
# Skipped unless you ask for it: it needs a Rust toolchain and pulls the
# gtk4/libadwaita crates, which is a few minutes of compiling. The CLI is
# fully functional without it.
if [[ "${1:-}" == "--gui" ]]; then
    if ! command -v cargo >/dev/null; then
        note "--gui needs a Rust toolchain (cargo). Skipping the GUI."
    elif ! pkg-config --exists gtk4 libadwaita-1 2>/dev/null; then
        note "--gui needs gtk4-devel and libadwaita-devel. Skipping the GUI."
    else
        head_ "Building the GUI (first build takes a few minutes)..."
        if (cd "$SRC/gui" && cargo build --release --quiet); then
            install -m755 "$SRC/gui/target/release/pvpn-gui" "$BIN/"
            ok "$BIN/pvpn-gui"
            install -d "$HOME/.local/share/applications"
            install -m644 "$SRC/gui/data/dev.pvpn.Gui.desktop" \
                "$HOME/.local/share/applications/"
            ok "$HOME/.local/share/applications/dev.pvpn.Gui.desktop"
        else
            note "GUI build failed - the CLI is installed and works regardless."
        fi
    fi
fi

# pvpn defaults its shim dir to ~/.local/share/protonvpn-torshim for backward
# compatibility; point it at the installed location instead.
if grep -q 'protonvpn-torshim' "$BIN/pvpn"; then
    sed -i "s|\$HOME/.local/share/protonvpn-torshim|\$HOME/.local/share/pvpn|g" "$BIN/pvpn"
    ok "shim path set to $LIB"
fi

case ":$PATH:" in
    *":$BIN:"*) ok "$BIN already on PATH" ;;
    *)  for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
            [[ -f $rc ]] && ! grep -q '.local/bin' "$rc" \
                && echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$rc"
        done
        c '1;33' "  Added $BIN to PATH - open a new shell or: source ~/.bashrc" ;;
esac

echo
head_ "Done"
cat <<'EOF'
  vpn-check          will a VPN work on this wifi?
  pvpn login         sign in to Proton (once)
  pvpn up            connect
  pvpn down          disconnect
  pvpn status        where am I exiting?

First run on a filtered network downloads Proton's ~2.5 MB server list
over Tor. That is slow once, then cached, and it happens before any
routing changes - your connection keeps working throughout.
EOF
