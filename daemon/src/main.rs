// Copyright (C) 2026 Neil Luo
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program. If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! pvpnd - keeps a Proton VPN tunnel alive, and repairs it when it dies.
//!
//! WHY THIS EXISTS
//!
//! The tunnel dies in ways nothing else notices. After a suspend, from the
//! NetworkManager journal:
//!
//!     Received TransportAlert(Shutdown(StreamId(1)))
//!     Shutdown(StreamId(1)): reconnecting
//!     WireguardUdp/handshake probe failed
//!     already disconnected
//!
//! protun tries to reconnect with a WireGuard UDP handshake probe. On a
//! UDP-blocking network - the reason for using Stealth at all - that probe
//! can never succeed, so it retries forever while NetworkManager keeps
//! proton0 "activated" and the CLI keeps reporting Connected. The tunnel
//! looks perfect and carries nothing, and it cannot heal itself.
//!
//! The same shape appears without suspending: boringtun logs
//! HANDSHAKE(REKEY_TIMEOUT) when the inner handshake goes unanswered, and
//! retries on a 5s timer. Until it completes there are no session keys, so
//! every packet is dropped while the route already points into the tunnel.
//!
//! So something outside the client has to watch and act.
//!
//! WHAT IT WILL NOT DO
//!
//! Fight you. If you run `pvpn down`, that is an instruction, not a fault -
//! a daemon that reconnects two seconds later is worse than no daemon. So
//! `pvpn` records INTENT, and this only ever acts to satisfy it.
//!
//! That has to hold for the GNOME quick-settings VPN switch too, which does
//! not know pvpn exists - it talks to NetworkManager directly. So NM is
//! treated as a second place you can express intent, and toggling the VPN
//! there means exactly what `pvpn up` / `pvpn down` mean.
//!
//! This is done with D-Bus SIGNALS, and the first attempt at it - polling
//! NM's connection list - is worth recording, because it broke `pvpn down`.
//! Polling samples STATE, and state cannot distinguish "this tunnel is
//! here" from "this tunnel is thirty milliseconds from being gone". A poll
//! landed in the gap between `pvpn down` writing intent=down and NM
//! finishing the teardown, saw a live tunnel with intent=down, concluded
//! the user must have switched it on from GNOME, and adopted it back to
//! intent=up. Autoreconnect then did the rest, and the VPN would not stay
//! off.
//!
//! A signal carries the TRANSITION and NM's own reason code
//! (USER_DISCONNECTED vs a fault), so that gap does not exist and nothing
//! has to be inferred.
//!
//! Signals alone were still not enough, and the second mistake is worth
//! recording too. NM's Connection.Active.StateChanged is emitted by EVERY
//! active connection - wifi, bridges, loopback - not just tunnels. Tearing
//! the tunnel out re-activates the wifi underneath it, so `pvpn down` was
//! immediately followed by the wifi announcing ACTIVATED on the very same
//! interface, with the very same state number a tunnel would use. That was
//! read as "the user switched the VPN on", intent went back to up, and the
//! VPN restarted itself. Listening to the right interface is not enough:
//! the SENDER has to be checked as well, which is what the tunnel path set
//! in spawn_nm_watcher is for.

use std::collections::{HashSet, VecDeque};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const PROBE_HOST: &str = "connectivitycheck.gstatic.com";

fn home() -> PathBuf {
    PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/tmp".into()))
}

fn intent_path() -> PathBuf {
    home().join(".config/pvpn/intent")
}

fn state_path() -> PathBuf {
    // Runtime dir, not $HOME: this is ephemeral and must not survive a
    // reboot claiming a tunnel is up.
    let base = std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(base).join("pvpnd.state")
}

fn busy_path() -> PathBuf {
    // Runtime dir for the same reason as the state file: a marker that
    // outlived a reboot would silence the daemon for two minutes at boot.
    let base = std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(base).join("pvpn.busy")
}

fn config_path() -> PathBuf {
    home().join(".config/pvpn/config")
}

fn pvpn_bin() -> String {
    let local = home().join(".local/bin/pvpn");
    if local.is_file() {
        local.to_string_lossy().into_owned()
    } else {
        "pvpn".into()
    }
}

/// Read `KEY=value` from pvpn's config. Shared with the shell, so the two
/// front-ends cannot disagree about your settings.
fn config_get(key: &str) -> Option<String> {
    let text = fs::read_to_string(config_path()).ok()?;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            if k.trim() == key {
                return Some(v.trim().trim_matches('"').to_string());
            }
        }
    }
    None
}

fn config_num(key: &str, default: u64) -> u64 {
    config_get(key).and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn config_bool(key: &str, default: bool) -> bool {
    match config_get(key).as_deref() {
        Some("1") | Some("on") | Some("yes") | Some("true") => true,
        Some("0") | Some("off") | Some("no") | Some("false") => false,
        _ => default,
    }
}

/// What the user last asked for. Absent means "never said", which we treat
/// as "leave me alone" rather than guessing.
#[derive(PartialEq, Debug, Clone, Copy)]
enum Intent {
    Up,
    Down,
    Unset,
}

fn read_intent() -> Intent {
    match fs::read_to_string(intent_path()) {
        Ok(s) => match s.trim() {
            "up" => Intent::Up,
            "down" => Intent::Down,
            _ => Intent::Unset,
        },
        Err(_) => Intent::Unset,
    }
}

/// Record intent on the user's behalf, when they expressed it somewhere
/// other than the pvpn CLI - i.e. the GNOME VPN switch.
fn write_intent(i: Intent) {
    let p = intent_path();
    if let Some(dir) = p.parent() {
        let _ = fs::create_dir_all(dir);
    }
    let word = match i {
        Intent::Up => "up",
        Intent::Down => "down",
        Intent::Unset => return,
    };
    // Same temp+rename pvpn uses: a half-written intent file read by the
    // next tick would be worse than no file at all.
    let tmp = p.with_extension("tmp");
    if fs::write(&tmp, format!("{word}\n")).is_ok() {
        let _ = fs::rename(&tmp, &p);
    }
}

/// Is pvpn itself mid-operation right now?
///
/// During a connect there is a real window where NetworkManager shows no
/// VPN at all - the old one is gone and the new one has not arrived. Read
/// naively that is indistinguishable from you switching the VPN off in
/// GNOME, and pvpnd would "helpfully" stand down halfway through your own
/// `pvpn up`. pvpn drops this marker for the length of any operation that
/// touches the tunnel, and we simply do not judge NM while it is there.
fn pvpn_is_busy() -> bool {
    let p = busy_path();
    let meta = match fs::metadata(&p) {
        Ok(m) => m,
        Err(_) => return false,
    };
    // A crashed pvpn must not wedge the daemon forever, so the marker
    // expires. Two minutes is comfortably longer than the slowest measured
    // connect (41s on detnsw) and far shorter than "until you reboot".
    match meta.modified().ok().and_then(|t| t.elapsed().ok()) {
        Some(age) => age < Duration::from_secs(120),
        None => true,
    }
}

/// The VPN as NetworkManager sees it, which is what GNOME's switch drives.
/// Returns the connection name, or None when no VPN is up.
///
/// Used only to answer "is a tunnel up right now" for the health loop and
/// the state file - NEVER to decide what the user wants. That decision is
/// made from signals; see spawn_nm_watcher for why sampling cannot make it
/// correctly. It replaces the old `pvpn status` call, which spawned the
/// whole Python client to answer the same question.
///
/// Any active vpn/wireguard profile counts, not just ones named "ProtonVPN":
/// hopping leaves profiles named after bare server IPs.
fn nm_vpn_connection() -> Option<String> {
    let out = Command::new("nmcli")
        .args(["-t", "-f", "NAME,TYPE", "connection", "show", "--active"])
        .stderr(Stdio::null())
        .output()
        .ok()?;
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        // -t output is colon-separated; a connection name may itself contain
        // an escaped colon, so take the TYPE from the END, not from field 2.
        let (name, kind) = match line.rsplit_once(':') {
            Some(pair) => pair,
            None => continue,
        };
        if kind == "vpn" || kind == "wireguard" {
            return Some(name.to_string());
        }
    }
    None
}

/// Something happened to the VPN, as reported by NetworkManager itself.
#[derive(PartialEq, Debug, Clone, Copy)]
enum Ev {
    /// A tunnel finished activating.
    Activated,
    /// It went away because somebody asked: GNOME's switch, nmcli, pvpn down.
    WentDownDeliberately,
    /// It went away on its own.
    Failed,
}

/// D-Bus reason codes, from NetworkManager's own enums
/// (NMActiveConnectionStateReason / NMVpnConnectionStateReason). Only the two
/// that mean "a human asked for this" matter; everything else is a fault.
const REASON_USER_DISCONNECTED: u32 = 2;
const REASON_CONNECTION_REMOVED: u32 = 11;

/// Pull `(state, reason)` out of a gdbus signal line.
///
/// The line looks like:
///     /org/.../ActiveConnection/12: org...VpnStateChanged (uint32 7, uint32 2)
/// Parsed by splitting on literal markers rather than by pattern matching, so
/// a wording change produces None - and None is inert - instead of a
/// confident misread.
fn parse_state_reason(line: &str, marker: &str) -> Option<(u32, u32)> {
    let rest = line.split_once(marker)?.1;
    let mut nums: Vec<u32> = Vec::new();
    for chunk in rest.split("uint32 ").skip(1) {
        let digits: String = chunk.chars().take_while(|c| c.is_ascii_digit()).collect();
        nums.push(digits.parse().ok()?);
        if nums.len() == 2 {
            return Some((nums[0], nums[1]));
        }
    }
    None
}

const AC_PREFIX: &str = "/org/freedesktop/NetworkManager/ActiveConnection/";

/// Which interface a signal arrived on, and what it said.
///
/// This distinction is not pedantry, it is the bug. `VPN.Connection` is a
/// VPN-only interface, so anything arriving on it is a tunnel by
/// construction. `Connection.Active` is the BASE interface that EVERY active
/// connection implements - wifi, bridges, loopback, virbr0 - so a state
/// change there says nothing about the VPN until the sender is identified.
#[derive(PartialEq, Debug, Clone)]
enum Sig {
    /// From the VPN-only interface: trust it.
    Vpn(Ev),
    /// From the shared interface: vet `path` before believing it.
    Generic { path: String, ev: Ev },
}

/// Turn one line of gdbus output into a signal, if it is one we can read.
///
/// Two interfaces, because NetworkManager models the two tunnel kinds
/// differently and they do NOT share a state enum:
///
///   VPN.Connection.VpnStateChanged      protun / OpenVPN.  5=ACTIVATED,
///                                       6=FAILED, 7=DISCONNECTED
///   Connection.Active.StateChanged      WireGuard.         2=ACTIVATED,
///                                       4=DEACTIVATED
fn parse_signal(line: &str) -> Option<Sig> {
    let generic = if line.contains(".VPN.Connection.VpnStateChanged") {
        false
    } else if line.contains(".Connection.Active.StateChanged") {
        true
    } else {
        return None;
    };

    let (activated, gone, (state, reason)) = if generic {
        (2u32, [4u32, 4u32], parse_state_reason(line, "StateChanged")?)
    } else {
        (5u32, [6u32, 7u32], parse_state_reason(line, "VpnStateChanged")?)
    };

    let ev = if state == activated {
        Ev::Activated
    } else if gone.contains(&state) {
        // NM says outright whether a human asked for this, so there is no
        // window to sample wrongly and no guessing from whether the
        // internet happens to work.
        if reason == REASON_USER_DISCONNECTED || reason == REASON_CONNECTION_REMOVED {
            Ev::WentDownDeliberately
        } else {
            Ev::Failed
        }
    } else {
        return None;
    };

    if !generic {
        return Some(Sig::Vpn(ev));
    }
    // "/org/.../ActiveConnection/9: org.freedesktop..." - the sender is
    // everything before the first ": ".
    let path = line.split_once(": ")?.0.trim().to_string();
    if !path.starts_with(AC_PREFIX) {
        return None;
    }
    Some(Sig::Generic { path, ev })
}

/// The system bus address. A systemd *user* service does not inherit it, and
/// without it gdbus fails with "No such file or directory" - which reads like
/// a permissions problem and is not one.
fn dbus_addr() -> String {
    std::env::var("DBUS_SYSTEM_BUS_ADDRESS")
        .unwrap_or_else(|_| "unix:path=/run/dbus/system_bus_socket".into())
}

/// Read one property off a NetworkManager object as raw gdbus text.
fn nm_get(path: &str, iface: &str, prop: &str) -> Option<String> {
    let out = Command::new("gdbus")
        .args([
            "call",
            "--system",
            "--dest",
            "org.freedesktop.NetworkManager",
            "--object-path",
            path,
            "--method",
            "org.freedesktop.DBus.Properties.Get",
            iface,
            prop,
        ])
        .env("DBUS_SYSTEM_BUS_ADDRESS", dbus_addr())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Pull the first quoted value out of gdbus output: `(<'wireguard'>,)`.
fn first_quoted(raw: &str) -> Option<String> {
    let (_, rest) = raw.split_once('\'')?;
    Some(rest.chars().take_while(|c| *c != '\'').collect())
}

/// Is the active connection at `path` actually a tunnel?
///
/// Sampling NM here is safe in a way the old polling loop was not: this only
/// runs just after NM reported ACTIVATED, so the object exists by definition.
/// We are identifying something that is present, not guessing whether
/// something is still there.
fn is_tunnel_path(path: &str) -> bool {
    let raw = match nm_get(
        path,
        "org.freedesktop.NetworkManager.Connection.Active",
        "Type",
    ) {
        Some(s) => s,
        None => return false,
    };
    matches!(first_quoted(&raw).as_deref(), Some("vpn") | Some("wireguard"))
}

/// Which active connections are tunnels right now.
///
/// Seeded when the watcher starts so a tunnel that was already up before the
/// daemon started is still recognised when it later goes away.
fn seed_tunnel_paths() -> HashSet<String> {
    let mut set = HashSet::new();
    let raw = match nm_get(
        "/org/freedesktop/NetworkManager",
        "org.freedesktop.NetworkManager",
        "ActiveConnections",
    ) {
        Some(s) => s,
        None => return set,
    };
    // (<[objectpath '/org/...', '/org/...']>,)
    for token in raw.split('\'') {
        if token.starts_with(AC_PREFIX) && is_tunnel_path(token) {
            set.insert(token.to_string());
        }
    }
    set
}

/// Watch NetworkManager's D-Bus signals forever, forwarding events.
///
/// Signals, not polling, and that distinction is the whole point. Polling
/// samples STATE, so it cannot tell "this tunnel is on its way out" from
/// "this tunnel is here" - which is exactly how `pvpn down` broke: the poll
/// landed in the gap between intent being written and NM finishing the
/// teardown, saw a live tunnel with intent=down, and adopted it back.
/// A signal carries the TRANSITION and its REASON, so that gap does not
/// exist.
///
/// Unprivileged: receiving NM's broadcast signals needs no root, verified on
/// this machine. DBUS_SYSTEM_BUS_ADDRESS has to be set by hand because a
/// systemd *user* service does not inherit it.
fn spawn_nm_watcher(tx: Sender<Ev>) {
    std::thread::spawn(move || loop {
        // Re-seeded per gdbus session, so a NetworkManager restart cannot
        // leave us holding stale object paths.
        let mut tunnels = seed_tunnel_paths();
        let child = Command::new("gdbus")
            .args(["monitor", "--system", "--dest", "org.freedesktop.NetworkManager"])
            .env(
                "DBUS_SYSTEM_BUS_ADDRESS",
                std::env::var("DBUS_SYSTEM_BUS_ADDRESS")
                    .unwrap_or_else(|_| "unix:path=/run/dbus/system_bus_socket".into()),
            )
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn();

        match child {
            Ok(mut c) => {
                if let Some(out) = c.stdout.take() {
                    for line in BufReader::new(out).lines().map_while(Result::ok) {
                        let ev = match parse_signal(&line) {
                            Some(Sig::Vpn(ev)) => Some(ev),
                            // Every active connection speaks on this
                            // interface, so an ACTIVATED here is only ours if
                            // NM says the sender is a tunnel. Skipping this
                            // check is what made `pvpn down` bounce straight
                            // back up: tearing the tunnel out re-activates
                            // the wifi, and the wifi's own ACTIVATED was
                            // being read as "the user switched the VPN on".
                            Some(Sig::Generic {
                                path,
                                ev: Ev::Activated,
                            }) => {
                                if is_tunnel_path(&path) {
                                    tunnels.insert(path);
                                    Some(Ev::Activated)
                                } else {
                                    None
                                }
                            }
                            // On the way out the object may already be gone
                            // and so cannot be interrogated - which is
                            // exactly why tunnels are remembered on the way
                            // in.
                            Some(Sig::Generic { path, ev }) => {
                                if tunnels.remove(&path) {
                                    Some(ev)
                                } else {
                                    None
                                }
                            }
                            None => None,
                        };
                        if let Some(ev) = ev {
                            if tx.send(ev).is_err() {
                                return; // main loop is gone
                            }
                        }
                    }
                }
                let _ = c.wait();
                log("nm watcher: gdbus exited, restarting in 5s");
            }
            Err(e) => log(&format!("nm watcher: cannot start gdbus ({e}), retrying in 5s")),
        }
        // NM restarting takes its monitor down with it; never spin on it.
        std::thread::sleep(Duration::from_secs(5));
    });
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn log(msg: &str) {
    // stdout is the journal under systemd; no log file to rotate.
    println!("[{}] {}", now_secs(), msg);
    let _ = std::io::stdout().flush();
}

/// Is traffic ACTUALLY passing?
///
/// Deliberately a raw TCP connect plus a byte of HTTP rather than shelling
/// out to curl: this runs every few seconds forever, and spawning a process
/// each time is the kind of thing that makes a daemon unwelcome.
///
/// IPv4 only, and no proxy: a tunnel can advertise IPv6 DNS while installing
/// no IPv6 route, and honouring $HTTPS_PROXY would measure the proxy rather
/// than the tunnel.
fn traffic_flows(timeout: Duration) -> bool {
    let addrs = match (PROBE_HOST, 80).to_socket_addrs() {
        Ok(a) => a,
        Err(_) => return false, // DNS is itself part of "does it work"
    };
    for addr in addrs {
        if !addr.is_ipv4() {
            continue;
        }
        if let Ok(mut s) = TcpStream::connect_timeout(&addr, timeout) {
            let _ = s.set_read_timeout(Some(timeout));
            let req = format!(
                "GET /generate_204 HTTP/1.1\r\nHost: {PROBE_HOST}\r\nConnection: close\r\n\r\n"
            );
            if s.write_all(req.as_bytes()).is_err() {
                continue;
            }
            let mut buf = [0u8; 16];
            if let Ok(n) = s.read(&mut buf) {
                if n > 0 && buf.starts_with(b"HTTP/") {
                    return true;
                }
            }
        }
    }
    false
}

fn write_state(connected: bool, healthy: bool, intent: Intent, note: &str) {
    // Plain JSON by hand - one small object is not worth a dependency.
    let json = format!(
        "{{\"connected\":{},\"traffic\":{},\"intent\":\"{}\",\"note\":\"{}\",\"updated\":{}}}\n",
        connected,
        healthy,
        match intent {
            Intent::Up => "up",
            Intent::Down => "down",
            Intent::Unset => "unset",
        },
        note.replace('"', "'"),
        now_secs()
    );
    let path = state_path();
    if let Some(dir) = path.parent() {
        let _ = fs::create_dir_all(dir);
    }
    // Write-then-rename, so a reader never sees half a file.
    let tmp = path.with_extension("tmp");
    if fs::write(&tmp, json).is_ok() {
        let _ = fs::rename(&tmp, &path);
    }
}

fn reconnect() -> bool {
    log("reconnecting: pvpn up");
    let ok = Command::new(pvpn_bin())
        .arg("up")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    log(if ok { "reconnect returned ok" } else { "reconnect failed" });
    ok
}

/// Apply one NetworkManager event to our idea of what you want.
fn handle_event(ev: Ev, strikes: &mut usize, backoff: &mut Duration) {
    // While pvpn is mid-operation its own signals are noise: `pvpn hop`
    // legitimately emits a deliberate down followed by an activate, and
    // acting on the down half would leave intent=down if the up half then
    // failed - quietly turning a failed hop into a permanent disconnect.
    // pvpn writes intent itself for these, so nothing is lost by ignoring
    // them.
    if pvpn_is_busy() {
        return;
    }
    match ev {
        Ev::Activated => {
            if read_intent() != Intent::Up {
                log("VPN switched on outside pvpn - adopting (intent=up)");
                write_intent(Intent::Up);
            }
            *strikes = 0;
            *backoff = Duration::from_secs(0);
        }
        Ev::WentDownDeliberately => {
            if read_intent() != Intent::Down {
                log("VPN switched off outside pvpn - standing down (intent=down)");
                write_intent(Intent::Down);
            }
            *strikes = 0;
            *backoff = Duration::from_secs(0);
        }
        // A fault does not change what you asked for, so intent is left
        // alone and the health loop handles it with strikes and backoff.
        Ev::Failed => log("NetworkManager reports the tunnel failed"),
    }
}

/// Wait for the next tick, but wake the moment NetworkManager says
/// something. This is what makes the GNOME switch feel instant instead of
/// taking up to `interval` seconds to register.
fn wait(rx: &Receiver<Ev>, d: Duration, strikes: &mut usize, backoff: &mut Duration) {
    let deadline = Instant::now() + d;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return;
        }
        match rx.recv_timeout(left) {
            Ok(ev) => {
                handle_event(ev, strikes, backoff);
                for extra in rx.try_iter() {
                    handle_event(extra, strikes, backoff);
                }
                // Re-evaluate now rather than sitting out the rest of the
                // tick - but not instantly, or a connect's burst of signals
                // would spin the loop.
                std::thread::sleep(Duration::from_secs(1));
                return;
            }
            Err(RecvTimeoutError::Timeout) => return,
            Err(RecvTimeoutError::Disconnected) => {
                // Watcher thread is gone; degrade to a plain timer.
                std::thread::sleep(left);
                return;
            }
        }
    }
}

fn main() {
    let interval = Duration::from_secs(config_num("watch_interval", 20).clamp(5, 600));
    let probe_timeout = Duration::from_secs(config_num("probe_timeout", 5).clamp(1, 30));
    // How many consecutive dead probes before acting. Not one: a single
    // failed probe is normal on flaky wifi, and reconnecting on it would
    // tear down working tunnels constantly.
    let strikes_needed = config_num("strikes", 3).clamp(1, 20) as usize;
    let enabled = config_bool("autoreconnect", true);

    log(&format!(
        "pvpnd starting: interval={}s probe_timeout={}s strikes={} autoreconnect={}",
        interval.as_secs(),
        probe_timeout.as_secs(),
        strikes_needed,
        enabled
    ));

    let mut strikes = 0usize;
    // Exponential backoff so a network that is simply down does not get
    // hammered, and a server refusing us does not spin.
    let mut backoff = Duration::from_secs(0);
    let mut last_attempt: Option<Instant> = None;
    let mut recent: VecDeque<bool> = VecDeque::with_capacity(8);

    let (tx, rx) = channel::<Ev>();
    spawn_nm_watcher(tx);

    loop {
        // --- NetworkManager as a second place you can express intent -----
        //
        // Driven by signals, never by sampling. Each event is a TRANSITION
        // NM actually performed, with NM's own reason code attached, so
        // there is no window in which a tunnel that is on its way out looks
        // like a tunnel that is present.
        //
        // pvpn's own commands land here too, and that is fine: `pvpn down`
        // produces USER_DISCONNECTED, which means exactly what pvpn already
        // wrote. The CLI and the GNOME switch stop being different cases.
        for ev in rx.try_iter() {
            handle_event(ev, &mut strikes, &mut backoff);
        }

        let intent = read_intent();
        // NM, not the Proton client, answers "is there a tunnel": it is one
        // cheap call instead of spawning the whole Python client.
        let connected = nm_vpn_connection().is_some();

        // Nothing to maintain unless the user asked to be up.
        if intent != Intent::Up {
            strikes = 0;
            backoff = Duration::from_secs(0);
            write_state(connected, connected, intent, "idle: intent is not up");
            wait(&rx, interval, &mut strikes, &mut backoff);
            continue;
        }

        let healthy = if connected {
            traffic_flows(probe_timeout)
        } else {
            false
        };

        recent.push_back(healthy);
        if recent.len() > 8 {
            recent.pop_front();
        }

        if healthy {
            if strikes > 0 {
                log("tunnel recovered");
            }
            strikes = 0;
            backoff = Duration::from_secs(0);
            write_state(true, true, intent, "healthy");
        } else {
            strikes += 1;
            let why = if connected {
                "client says connected but no traffic"
            } else {
                "tunnel is down"
            };
            write_state(connected, false, intent, why);
            log(&format!("strike {strikes}/{strikes_needed}: {why}"));

            if !enabled {
                // Still report it; just do not act.
                wait(&rx, interval, &mut strikes, &mut backoff);
                continue;
            }

            if strikes >= strikes_needed {
                let due = last_attempt
                    .map(|t| t.elapsed() >= backoff)
                    .unwrap_or(true);
                if due {
                    last_attempt = Some(Instant::now());
                    if reconnect() {
                        backoff = Duration::from_secs(0);
                    } else {
                        // 30s, 60s, 120s ... capped at 10 minutes.
                        backoff = if backoff.is_zero() {
                            Duration::from_secs(30)
                        } else {
                            (backoff * 2).min(Duration::from_secs(600))
                        };
                        log(&format!("backing off {}s", backoff.as_secs()));
                    }
                    // Reset either way: another attempt is gated by backoff,
                    // not by racking up more strikes.
                    strikes = 0;
                }
            }
        }

        wait(&rx, interval, &mut strikes, &mut backoff);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real gdbus lines. The reason codes are what make `pvpn down` work, so
    /// they are pinned here: a change in this table is a change in whether
    /// the daemon fights the user.
    #[test]
    fn signal_lines_map_to_the_right_events() {
        let vpn = "/org/freedesktop/NetworkManager/ActiveConnection/12: \
                   org.freedesktop.NetworkManager.VPN.Connection.VpnStateChanged";
        let act = "/org/freedesktop/NetworkManager/ActiveConnection/9: \
                   org.freedesktop.NetworkManager.Connection.Active.StateChanged";

        // GNOME switch off / pvpn down: DISCONNECTED + USER_DISCONNECTED.
        assert_eq!(
            parse_signal(&format!("{vpn} (uint32 7, uint32 2)")),
            Some(Sig::Vpn(Ev::WentDownDeliberately))
        );
        // Profile deleted, as `pvpn hop` does: CONNECTION_REMOVED.
        assert_eq!(
            parse_signal(&format!("{vpn} (uint32 7, uint32 11)")),
            Some(Sig::Vpn(Ev::WentDownDeliberately))
        );
        // LOGIN_FAILED is a fault - standing down here would disable
        // autoreconnect exactly when it is needed.
        assert_eq!(
            parse_signal(&format!("{vpn} (uint32 6, uint32 10)")),
            Some(Sig::Vpn(Ev::Failed))
        );
        assert_eq!(
            parse_signal(&format!("{vpn} (uint32 5, uint32 1)")),
            Some(Sig::Vpn(Ev::Activated))
        );

        // WireGuard reports on a different interface with a different enum:
        // 2 = ACTIVATED, 4 = DEACTIVATED. It carries the sender's path,
        // because that interface is shared with everything else on the box.
        let p = "/org/freedesktop/NetworkManager/ActiveConnection/9";
        assert_eq!(
            parse_signal(&format!("{act} (uint32 2, uint32 1)")),
            Some(Sig::Generic {
                path: p.to_string(),
                ev: Ev::Activated
            })
        );
        assert_eq!(
            parse_signal(&format!("{act} (uint32 4, uint32 2)")),
            Some(Sig::Generic {
                path: p.to_string(),
                ev: Ev::WentDownDeliberately
            })
        );
    }

    /// THE regression. `Connection.Active.StateChanged` is emitted by every
    /// active connection on the machine, so the wifi coming back after a
    /// tunnel is torn down looks byte-for-byte like a tunnel activating -
    /// same interface, same state 2. The ONLY thing separating them is the
    /// sender's object path, so the parser must carry it out intact and must
    /// never collapse the two into a bare "Activated".
    ///
    /// Reported as: "pvpn down just restarts the vpn".
    #[test]
    fn wifi_and_tunnel_activations_are_distinguishable() {
        let wifi = "/org/freedesktop/NetworkManager/ActiveConnection/303: \
                    org.freedesktop.NetworkManager.Connection.Active.StateChanged \
                    (uint32 2, uint32 1)";
        let tun = "/org/freedesktop/NetworkManager/ActiveConnection/9: \
                   org.freedesktop.NetworkManager.Connection.Active.StateChanged \
                   (uint32 2, uint32 1)";

        let (a, b) = (parse_signal(wifi), parse_signal(tun));
        assert_ne!(a, b, "wifi and tunnel activations must not be equal");
        match (a, b) {
            (Some(Sig::Generic { path: pa, .. }), Some(Sig::Generic { path: pb, .. })) => {
                assert!(pa.ends_with("/303"));
                assert!(pb.ends_with("/9"));
            }
            other => panic!("expected two Generic signals, got {other:?}"),
        }
    }

    /// Anything we do not positively recognise must be inert. A daemon that
    /// guesses from half-understood input is how the polling version broke.
    #[test]
    fn unrecognised_lines_are_inert() {
        let vpn = "/org/freedesktop/NetworkManager/ActiveConnection/12: \
                   org.freedesktop.NetworkManager.VPN.Connection.VpnStateChanged";
        // Mid-transition states are not decisions.
        assert_eq!(parse_signal(&format!("{vpn} (uint32 3, uint32 1)")), None);
        // Unrelated NM chatter.
        assert_eq!(
            parse_signal(
                "/org/freedesktop/NetworkManager/AccessPoint/13177: \
                 org.freedesktop.DBus.Properties.PropertiesChanged ('x',)"
            ),
            None
        );
        // Malformed payload must yield None, never a misparse.
        assert_eq!(parse_signal(&format!("{vpn} (garbage)")), None);
        assert_eq!(parse_signal(&format!("{vpn} (uint32 7)")), None);
        assert_eq!(parse_signal(""), None);
        // A shared-interface signal from something that is not an active
        // connection at all has no path to vet, so it cannot be believed.
        assert_eq!(
            parse_signal(
                "/org/freedesktop/NetworkManager/Devices/2: \
                 org.freedesktop.NetworkManager.Connection.Active.StateChanged \
                 (uint32 2, uint32 1)"
            ),
            None
        );
    }

    #[test]
    fn parses_both_numbers_not_just_the_first() {
        assert_eq!(
            parse_state_reason("x VpnStateChanged (uint32 7, uint32 11)", "VpnStateChanged"),
            Some((7, 11))
        );
    }
}
