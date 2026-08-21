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
//! not know pvpn exists - it talks to NetworkManager directly. Without the
//! NM polling below, flicking that switch off produced a standoff: NM tears
//! the tunnel down, pvpnd still reads intent=up, and puts it straight back.
//! So NM is treated as a second place you can express intent, and toggling
//! the VPN there means exactly what `pvpn up` / `pvpn down` mean.

use std::collections::VecDeque;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::process::{Command, Stdio};
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
/// Polled rather than subscribed to on purpose: watching signals on the
/// system bus needs root (`gdbus monitor --system` is refused for a user
/// session), and pvpnd deliberately runs as you, not as root. One nmcli
/// call per tick is the price. It replaces the old `pvpn status` call,
/// which spawned the whole Python client to answer the same question.
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

/// Why did the VPN go away?
#[derive(PartialEq, Debug, Clone, Copy)]
enum Reason {
    /// Somebody asked for it: the GNOME switch, nmcli, pvpn down.
    Deliberate,
    /// It fell over.
    Failure,
    Unknown,
}

/// Ask NetworkManager's journal why the tunnel went down.
///
/// This is the entire difference between "you turned it off" and "it broke",
/// and getting it wrong is bad in both directions - reconnecting after you
/// deliberately toggled the switch is the behaviour that makes a daemon
/// hateful, and standing down after a fault defeats the point of having one.
///
/// NM writes the answer in its state-change lines:
///     device (proton0): state change: ... (reason 'user-requested' ...
/// Matched as plain substrings, so if NM ever rewords these we degrade to
/// Unknown - which the caller resolves by other means - rather than
/// confidently misreading them.
fn nm_disconnect_reason() -> Reason {
    let out = Command::new("journalctl")
        .args(["-u", "NetworkManager", "--since", "-120s", "--no-pager", "-o", "cat"])
        .stderr(Stdio::null())
        .output();
    let out = match out {
        Ok(o) => o,
        Err(_) => return Reason::Unknown,
    };
    let text = String::from_utf8_lossy(&out.stdout);
    // Last verdict wins: we want the most recent transition, not the first.
    let mut verdict = Reason::Unknown;
    for line in text.lines() {
        if !line.contains("state change:") {
            continue;
        }
        if line.contains("reason 'user-requested'") || line.contains("reason 'connection-removed'")
        {
            verdict = Reason::Deliberate;
        } else if line.contains("reason 'login-failed'")
            || line.contains("reason 'no-secrets'")
            || line.contains("reason 'service-start-failed'")
            || line.contains("-> failed")
        {
            verdict = Reason::Failure;
        }
    }
    verdict
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

    loop {
        let intent = read_intent();
        // NetworkManager, not the Proton client, is the source of truth for
        // "is there a tunnel": it is what GNOME's switch acts on, and it is
        // one cheap call instead of spawning the whole Python client.
        let nm_vpn = nm_vpn_connection();
        let connected = nm_vpn.is_some();

        // --- NetworkManager as a second place you can express intent -----
        //
        // Skipped while pvpn is mid-operation. During a connect NM honestly
        // shows no VPN for a few seconds, and reading that as "they turned
        // it off in GNOME" would make pvpnd abandon your own `pvpn up`.
        if !pvpn_is_busy() {
            if intent != Intent::Up && connected {
                // Switched on from outside - the GNOME menu, or nmcli.
                // Adopt it, so status, the GUI and the daemon agree, and so
                // it gets kept alive like any tunnel pvpn started itself.
                log(&format!(
                    "VPN switched on outside pvpn ({}) - adopting, intent=up",
                    nm_vpn.as_deref().unwrap_or("?")
                ));
                write_intent(Intent::Up);
                write_state(true, true, Intent::Up, "adopted a VPN started outside pvpn");
                strikes = 0;
                backoff = Duration::from_secs(0);
                std::thread::sleep(interval);
                continue;
            }

            if intent == Intent::Up && !connected {
                // Gone from NM entirely. That is NOT what a broken tunnel
                // looks like here: the failure this daemon exists for
                // leaves proton0 "activated" and merely stops passing
                // packets. A vanished connection means something took it
                // down - so find out whether that something was you.
                let deliberate = match nm_disconnect_reason() {
                    Reason::Deliberate => true,
                    Reason::Failure => false,
                    // NM did not say. If the internet works without the
                    // tunnel then you are online and VPN-less, which is
                    // what the switch being off looks like. If it does not,
                    // the network itself went away - keep intent and wait,
                    // or turning off the wifi would silently disarm pvpnd.
                    Reason::Unknown => traffic_flows(probe_timeout),
                };
                if deliberate {
                    log("VPN switched off outside pvpn - standing down (intent=down)");
                    write_intent(Intent::Down);
                    write_state(false, false, Intent::Down, "switched off outside pvpn");
                    strikes = 0;
                    backoff = Duration::from_secs(0);
                    std::thread::sleep(interval);
                    continue;
                }
            }
        }

        // Nothing to maintain unless the user asked to be up.
        if intent != Intent::Up {
            strikes = 0;
            backoff = Duration::from_secs(0);
            write_state(connected, connected, intent, "idle: intent is not up");
            std::thread::sleep(interval);
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
                std::thread::sleep(interval);
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

        std::thread::sleep(interval);
    }
}
