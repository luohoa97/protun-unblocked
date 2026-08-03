# vim: set ft=make :
#
# Copyright (C) 2026 Neil Luo
# SPDX-License-Identifier: GPL-3.0-or-later
#
# ujust recipes for pvpn.
#
# Deliberately ONLY the one-off tasks. `pvpn up` is a daily-use command and
# lives in /usr/bin, so you type `pvpn up`, not `ujust pvpn-up` - wrapping a
# frequent command in a launcher makes it worse, not better. What belongs
# here is the onboarding: things you do once per account or once per
# network, which is exactly what ujust is discoverable for.

# Sign in to Proton VPN (once per account)
[group('Network')]
pvpn-login:
    #!/usr/bin/bash
    echo "Proton's API is blocked on some networks; pvpn routes the login"
    echo "through Tor automatically when it has to."
    pvpn login

# Will a VPN work on the wifi I'm on right now?
[group('Network')]
pvpn-check:
    #!/usr/bin/bash
    vpn-check

# Measure Proton's free servers from here and rank them
[group('Network')]
pvpn-scan filter="":
    #!/usr/bin/bash
    pvpn scan {{ filter }}

# Show what pvpn can actually connect with on this machine
[group('Network')]
pvpn-protocols:
    #!/usr/bin/bash
    pvpn protocols

# Build and install the libadwaita GUI (needs a Rust toolchain)
[group('Network')]
pvpn-gui-install:
    #!/usr/bin/bash
    set -euo pipefail
    if ! command -v cargo >/dev/null; then
        echo "Needs a Rust toolchain. Install one first, e.g.:"
        echo "  brew install rust        # or rustup"
        exit 1
    fi
    # The GUI is not baked into the image on purpose: it would drag cargo
    # and the gtk4/libadwaita crates into every build for something most
    # people will not use. Building it here takes about a minute.
    tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
    git clone --depth 1 https://github.com/luohoa97/protun-unblocked.git "$tmp/src"
    cd "$tmp/src/gui" && cargo build --release
    install -Dm755 target/release/pvpn-gui "$HOME/.local/bin/pvpn-gui"
    install -Dm644 data/dev.pvpn.Gui.desktop \
        "$HOME/.local/share/applications/dev.pvpn.Gui.desktop"
    echo "Installed to ~/.local/bin/pvpn-gui"
