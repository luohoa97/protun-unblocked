#!/usr/bin/env bash
# Adversarial replay: feed the REAL pvpnd a scripted NetworkManager signal
# stream and assert what it does to intent.
#
# WHY THIS EXISTS
#
# Both bugs this project shipped were the daemon reconnecting something the
# user had deliberately turned off, and neither would have been caught by a
# unit test — the parsers were fine. What was wrong was the decision made
# from correctly-parsed input. So this drives the actual binary.
#
# Every scenario below is either a bug that reached a user, or a case that
# would have become one. Named so a failure says which.
#
# Offline and destructive to nothing: gdbus, nmcli and pvpn are all replaced
# by fakes, HOME and XDG_RUNTIME_DIR point into a temp dir, and no real
# tunnel is touched. Safe to run with the VPN up.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${PVPND_BIN:-$ROOT/target/release/pvpnd}"

if [ ! -x "$BIN" ]; then
    echo "building pvpnd..."
    (cd "$ROOT" && cargo build --release -p pvpnd) || exit 1
fi

T="$(mktemp -d)"
# Kill the whole process group's stragglers as well as removing the dir.
# The fake gdbus sleeps for 600s after replaying its signals, so without
# this every run leaks two processes that outlive the test by ten minutes.
cleanup() {
    pkill -f "$T/bin/gdbus" 2>/dev/null || true
    rm -rf "$T"
}
trap cleanup EXIT INT TERM
mkdir -p "$T/home/.config/pvpn" "$T/run" "$T/bin"

# autoreconnect is OFF for the whole suite. This tests the signal path, and
# leaving the health loop on would let its reconnects race the signals and
# make results depend on wall-clock timing rather than on behaviour.
cat > "$T/home/.config/pvpn/config" <<'EOF'
watch_interval=5
probe_timeout=1
strikes=1
autoreconnect=off
EOF

# Fake NetworkManager over gdbus. Object 303 is wifi, 9 is a wireguard
# tunnel — the same topology as the machine the regression was found on.
cat > "$T/bin/gdbus" <<'EOF'
#!/usr/bin/env bash
mode=$1
if [ "$mode" = call ]; then
  case "$*" in
    *ActiveConnections*) echo "(<[objectpath '/org/freedesktop/NetworkManager/ActiveConnection/303']>,)" ;;
    */ActiveConnection/303*Type*) echo "(<'802-11-wireless'>,)" ;;
    */ActiveConnection/9*Type*)   echo "(<'wireguard'>,)" ;;
    *) echo "(<''>,)" ;;
  esac
  exit 0
fi
[ "$mode" = monitor ] && { sleep 1; cat "$FAKE_SIGNALS"; sleep 600; }
EOF
# No VPN, per nmcli. Keeps "is a tunnel up" out of the signal decision.
printf '#!/usr/bin/env bash\nexit 0\n' > "$T/bin/nmcli"
# Records reconnects instead of performing them.
printf '#!/usr/bin/env bash\necho "pvpn $*" >> "$PVPN_CALLS"\nexit 0\n' > "$T/bin/pvpn"
chmod +x "$T/bin"/*

AC=/org/freedesktop/NetworkManager/ActiveConnection
IF=org.freedesktop.NetworkManager.Connection.Active.StateChanged
VIF=org.freedesktop.NetworkManager.VPN.Connection.VpnStateChanged

pass=0; fail=0
red=$'\033[31m'; green=$'\033[32m'; off=$'\033[0m'
[ -t 1 ] || { red=""; green=""; off=""; }

# run <name> <starting-intent> <signals-file> <expected-intent>
run() {
    echo "$2" > "$T/home/.config/pvpn/intent"
    : > "$T/calls"
    env -i HOME="$T/home" XDG_RUNTIME_DIR="$T/run" PATH="$T/bin:/usr/bin:/bin" \
        FAKE_SIGNALS="$3" PVPN_CALLS="$T/calls" "$BIN" > "$T/log-$1" 2>&1 &
    local pid=$!
    sleep 9
    kill $pid 2>/dev/null; wait $pid 2>/dev/null

    local got calls
    got=$(cat "$T/home/.config/pvpn/intent")
    # wc, not `grep -c`: grep prints 0 AND exits 1 on no match, so a
    # `|| echo 0` fallback appends a second zero and the comparison below
    # then fails on every passing case.
    calls=$(wc -l < "$T/calls" | tr -d ' ')

    if [ "$got" = "$4" ] && [ "$calls" -eq 0 ]; then
        printf '  %spass%s  %s\n' "$green" "$off" "$1"
        pass=$((pass + 1))
    else
        printf '  %sFAIL%s  %s\n' "$red" "$off" "$1"
        printf '        intent %s -> %s (expected %s), reconnects=%s\n' "$2" "$got" "$4" "$calls"
        printf '        log: %s\n' "$T/log-$1"
        sed 's/^/          /' "$T/log-$1" | head -20
        fail=$((fail + 1))
    fi
}

printf '%s: %s (uint32 2, uint32 1)\n'  "$AC/303" "$IF"  > "$T/s-wifi-on"
printf '%s: %s (uint32 2, uint32 1)\n'  "$AC/9"   "$IF"  > "$T/s-tun-on"
printf '%s: %s (uint32 4, uint32 2)\n'  "$AC/303" "$IF"  > "$T/s-wifi-off"
printf '%s: %s (uint32 7, uint32 2)\n'  "$AC/12"  "$VIF" > "$T/s-user-off"
printf '%s: %s (uint32 6, uint32 10)\n' "$AC/12"  "$VIF" > "$T/s-login-failed"
printf '%s: %s (uint32 7, uint32 11)\n' "$AC/12"  "$VIF" > "$T/s-removed"
{ printf '%s: %s (uint32 2, uint32 1)\n' "$AC/9" "$IF"
  printf '%s: %s (uint32 4, uint32 2)\n' "$AC/9" "$IF"; } > "$T/s-up-then-down"
printf 'org.freedesktop.DBus.Properties.PropertiesChanged (junk)\n' > "$T/s-noise"
: > "$T/s-silence"

echo "adversarial replay against $BIN"
echo

# THE regression, reported as "pvpn down just restarts the vpn". Tearing a
# tunnel out re-activates the wifi under it, and the wifi's ACTIVATED is
# byte-identical to a tunnel's on the shared interface. Only the sender's
# object path distinguishes them.
run "wifi-activating-must-not-adopt"        down "$T/s-wifi-on"      down

# The control: a real tunnel appearing IS the user switching it on.
run "real-tunnel-activating-adopts"         down "$T/s-tun-on"       up

# Turning off wifi is not an instruction about the VPN.
run "wifi-off-is-not-a-vpn-instruction"     up   "$T/s-wifi-off"     up

# GNOME's switch, nmcli, and `pvpn down` all produce USER_DISCONNECTED.
run "gnome-switch-off-stands-down"          up   "$T/s-user-off"     down

# CONNECTION_REMOVED, as `pvpn hop` produces when it deletes a profile.
run "profile-removed-stands-down"           up   "$T/s-removed"      down

# A fault must NOT stand down — doing so disables autoreconnect exactly
# when it is needed.
run "login-failed-is-a-fault-not-a-request" up   "$T/s-login-failed" up

# A tunnel we watched activate must still be attributable on the way out,
# when the D-Bus object is already gone and cannot be interrogated.
run "tunnel-up-then-down-is-tracked"        down "$T/s-up-then-down" down

# Unparseable input must be inert, never a guess.
run "unrecognised-signals-are-inert"        up   "$T/s-noise"        up
run "silence-changes-nothing"               up   "$T/s-silence"      up

echo
echo "  $pass passed, $fail failed"
[ "$fail" -eq 0 ]
