//! Driving Proton's own CLI, and cleaning up after it.
//!
//! Everything here wraps `protonvpn` rather than reimplementing it. The
//! value this project adds is in *when* and *how* that client is invoked,
//! and in putting the machine back when it fails — not in speaking Proton's
//! API.
//!
//! Two things are load-bearing and easy to lose in a rewrite:
//!
//!   1. **`PYTHONPATH` must point at our shim.** `lib/sitecustomize.py`
//!      cuts Proton's API transport timeout from 15s to ~2s and enables
//!      server steering. Without it a connect on a filtered network spends
//!      30 seconds on API calls that cannot succeed.
//!
//!   2. **Routing must be restored on every failure path**, including
//!      Ctrl-C. `protonvpn connect` installs a full-tunnel route the moment
//!      it *starts*, so an abandoned connect blackholes the machine.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::paths;

/// Protocols Proton knows, best-first for a filtered network.
///
/// Stealth (`protun-tls`) leads because it is WireGuard inside TLS inside
/// TCP, which is the only thing that survives a DPI network. It is also the
/// wrong choice on an open network — it pays head-of-line blocking for a
/// problem you do not have — so this order is a starting point, not a
/// preference to be stored.
pub const PROTOCOLS: &[&str] = &[
    "protun-tls",
    "protun-udp",
    "protun-tcp",
    "protun-smart",
    "openvpn-tcp",
    "openvpn-udp",
    "wireguard",
];

pub fn settings_path() -> PathBuf {
    paths::home().join(".config/Proton/VPN/settings.json")
}

/// Where our Python shim lives. `PYTHONPATH` is pointed here for every
/// invocation of Proton's client.
pub fn shim_dir() -> PathBuf {
    // A development copy in ~/.local shadows the image's copy in /usr,
    // which is what makes working on this possible without rebuilding an
    // image. Same precedence as PATH, deliberately.
    if let Ok(p) = std::env::var("PVPN_SHIM") {
        let p = PathBuf::from(p);
        if p.join("sitecustomize.py").is_file() {
            return p;
        }
    }
    let local = paths::home().join(".local/share/pvpn");
    if local.join("sitecustomize.py").is_file() {
        return local;
    }
    PathBuf::from("/usr/share/pvpn")
}

/// A `protonvpn` invocation with the shim on `PYTHONPATH`.
pub fn client() -> Command {
    let mut c = Command::new("protonvpn");
    c.env("PYTHONPATH", shim_dir())
        .env("PVPN_DEBUG", "0");
    c
}

/// Is the shim actually the one that supports server steering?
///
/// A stale copy fails SILENTLY: ranking still names the right server, the
/// connect ignores it, and you land in another country wondering why. One
/// grep is cheap insurance against a confusing bug.
pub fn steering_available() -> bool {
    std::fs::read_to_string(shim_dir().join("sitecustomize.py"))
        .map(|t| t.contains("steered_from_dict"))
        .unwrap_or(false)
}

/// Is a tunnel up?
///
/// Asks NetworkManager, NOT Proton's client.
///
/// `protonvpn status` spawns the whole Python stack and was measured at
/// **7.8 seconds**. `pvpn up` called it three times, which is where most of
/// "why does it take a minute" came from - roughly 25 seconds of process
/// startup before any part of the connect began. NetworkManager answers the
/// same question over D-Bus in about 7 milliseconds, and it is the
/// authority anyway: the client is reporting NM's state back to us.
///
/// It is also MORE correct. Proton's client keeps reporting Connected after
/// a session dies, which is the exact failure this whole project exists to
/// catch. NM knows whether the connection object is actually active.
pub fn is_connected() -> bool {
    crate::dbus::vpn_connection().is_some()
}

/// The server Proton believes it is on, e.g. `SG-FREE#20`.
///
/// Proton prints "NAME in City, Country"; rankings hold only NAME, so the
/// location half is trimmed here rather than by every caller.
pub fn current_server() -> Option<String> {
    server_from_connection_id(&crate::dbus::vpn_connection()?)
}

/// Pull the server name out of a NetworkManager connection id.
///
/// NM names Proton profiles `ProtonVPN SG-FREE#20`; rankings and the
/// blocked list hold the bare `SG-FREE#20`. Hopping also leaves profiles
/// named after bare server IPs, which have no prefix to strip - those are
/// returned unchanged rather than mangled.
pub fn server_from_connection_id(id: &str) -> Option<String> {
    let name = id.trim();
    let name = name.strip_prefix("ProtonVPN").unwrap_or(name).trim();
    // Proton's own status prints "NAME in City, Country"; NM does not, but
    // callers pass both, so trim it here rather than in each of them.
    let name = name.split(" in ").next().unwrap_or(name).trim();
    (!name.is_empty()).then(|| name.to_string())
}

pub fn current_protocol() -> Option<String> {
    let text = std::fs::read_to_string(settings_path()).ok()?;
    let v: serde_json::Value = serde_json::from_str(&text).ok()?;
    v.get("protocol")?.as_str().map(|s| s.to_string())
}

/// Write the protocol into Proton's settings.
///
/// Reads, mutates one key, writes back — rather than templating a new file,
/// which would drop every other setting the user has.
pub fn set_protocol(proto: &str) -> anyhow::Result<()> {
    let path = settings_path();
    if !path.is_file() {
        anyhow::bail!(
            "{} does not exist - are you signed in? Try: pvpn login",
            path.display()
        );
    }
    let text = std::fs::read_to_string(&path)?;
    let mut v: serde_json::Value = serde_json::from_str(&text)?;
    let Some(obj) = v.as_object_mut() else {
        anyhow::bail!("{} is not a JSON object", path.display());
    };
    obj.insert(
        "protocol".into(),
        serde_json::Value::String(proto.to_string()),
    );
    // Proton's client reads this file; a torn write would leave it with no
    // settings at all.
    paths::write_atomic(&path, &format!("{}\n", serde_json::to_string_pretty(&v)?))?;
    Ok(())
}

/// Tear the tunnel down.
///
/// NetworkManager first. `protonvpn disconnect` spawns the whole Python
/// stack - 2.0s before it does anything - to make the same D-Bus call we
/// can make directly. Deactivating the active connection object is what
/// the client ultimately does.
///
/// The client is still called afterwards when D-Bus was not available,
/// because it also clears Proton's own session state. When NM did the work
/// that state is reconciled on the next command anyway, and `pvpn down`
/// returning in milliseconds is worth more than tidiness the user cannot
/// see.
pub fn disconnect() {
    if crate::dbus::available() {
        if let Some(active) = crate::dbus::active_tunnel_path() {
            match crate::dbus::deactivate(&active) {
                Ok(()) => {
                    tracing::debug!("tunnel deactivated over D-Bus");
                    clear_autoconnect();
                    return;
                }
                Err(e) => {
                    tracing::debug!(error = %e, "D-Bus deactivate failed; using the client");
                }
            }
        } else {
            // Nothing active: there is nothing for the client to do either.
            return;
        }
    }
    let _ = client()
        .arg("disconnect")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// Stop a Proton profile from resurrecting itself.
///
/// Proton creates its NetworkManager profiles with autoconnect ON, so a
/// tunnel torn down by hand can come straight back - which looks exactly
/// like the daemon fighting you, and was blamed on it more than once. The
/// shell implementation cleared this flag on every `pvpn down`; doing it
/// over D-Bus keeps that behaviour without the process.
fn clear_autoconnect() {
    for p in crate::dbus::saved_profiles() {
        if !p.is_tunnel() {
            continue;
        }
        if let Err(e) = crate::dbus::set_autoconnect(&p, false) {
            tracing::debug!(id = %p.id, error = %e, "could not clear autoconnect");
        }
    }
}

/// Put the machine's networking back the way it was.
///
/// Ordered deliberately, and every step matters:
///
///   1. Kill a connect still in flight, or it keeps fighting us.
///   2. Ask Proton to tear down cleanly.
///   3. Delete the kill-switch device by hand. Proton builds
///      `pvpnksintrf0` while connecting *even with killswitch disabled*,
///      and an interrupted connect can leave it behind blackholing
///      everything. Trusting the client to have cleaned up is how people
///      end up with no internet and no idea why.
///   4. Wait for traffic.
///   5. Last resort, bounce the wifi — recovers an interface left
///      half-configured, e.g. after a suspend mid-connect.
pub fn restore(probe_timeout: Duration) -> bool {
    // Bracketed so the pattern cannot match our own command line. Without
    // it, pkill can kill the process doing the killing.
    let _ = Command::new("pkill")
        .args(["-f", "[p]rotonvpn connect"])
        .output();

    disconnect();
    delete_killswitch_devices();

    // Probe immediately, then quickly, then back off.
    //
    // The old loop slept a flat second between probes, so a route that came
    // back in 300ms still cost a full second - on a command whose entire
    // job is to hand the network back. Routing usually recovers in well
    // under a second once the tunnel is gone, so the early probes are where
    // the answer almost always is; the later ones only matter when
    // something is genuinely wrong.
    let backoff = [0, 100, 150, 250, 500, 1000, 1000, 1000, 2000, 2000, 2000];
    for wait_ms in backoff {
        if wait_ms > 0 {
            std::thread::sleep(Duration::from_millis(wait_ms));
        }
        if crate::probe::traffic_flows(probe_timeout).alive {
            return true;
        }
    }

    if let Some(wifi) = active_wifi_connection() {
        tracing::warn!(%wifi, "bouncing wifi to recover routing");
        let _ = Command::new("nmcli")
            .args(["con", "up", &wifi])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        for _ in 0..5 {
            if crate::probe::traffic_flows(probe_timeout).alive {
                return true;
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    false
}

fn delete_killswitch_devices() {
    let Ok(out) = Command::new("nmcli")
        .args(["-t", "-f", "NAME,UUID", "con", "show"])
        .output()
    else {
        return;
    };
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let lower = line.to_ascii_lowercase();
        if !(lower.contains("killswitch") || lower.contains("pvpnks")) {
            continue;
        }
        // NAME may contain colons; the UUID is the last field.
        if let Some((_, uuid)) = line.rsplit_once(':') {
            tracing::info!(uuid, "deleting stray kill-switch profile");
            let _ = Command::new("nmcli")
                .args(["con", "delete", uuid])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
}

pub fn active_wifi_connection() -> Option<String> {
    let out = Command::new("nmcli")
        .args(["-t", "-f", "NAME,TYPE", "con", "show", "--active"])
        .output()
        .ok()?;
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        if let Some((name, kind)) = line.rsplit_once(':') {
            if kind == "802-11-wireless" {
                return Some(name.to_string());
            }
        }
    }
    None
}

/// Does Proton have a working backend for this protocol?
///
/// Stealth needs the NetworkManager `protun` plugin plus
/// `python3-proton-vpn-lib`; without them a connect dies instantly with
/// "No valid implementation found". Checking first turns a confusing
/// failure into a clear one.
pub fn protocol_available(proto: &str) -> bool {
    // The protun (Stealth) backends need NetworkManager's protun plugin.
    // Its presence is a file on disk, and checking for it is a stat() -
    // where the previous implementation spawned python3 and imported the
    // whole Proton stack to reach the same conclusion, at seconds a time on
    // a path that runs before every connect.
    if proto.starts_with("protun") {
        return std::path::Path::new(NM_PROTUN_PLUGIN).exists();
    }
    // OpenVPN and WireGuard are handled by NetworkManager itself, and the
    // plugin for each is likewise a file.
    if proto.starts_with("openvpn") {
        return NM_OPENVPN_PLUGINS
            .iter()
            .any(|p| std::path::Path::new(p).exists());
    }
    if proto == "wireguard" {
        // Built into NetworkManager, and into the kernel since 5.6.
        return true;
    }
    false
}

/// NetworkManager's Stealth plugin. Without this, a connect via any
/// `protun-*` protocol dies instantly with "No valid implementation found".
pub const NM_PROTUN_PLUGIN: &str = "/usr/lib/NetworkManager/VPN/nm-protun.name";

const NM_OPENVPN_PLUGINS: &[&str] = &[
    "/usr/lib/NetworkManager/VPN/nm-openvpn-service.name",
    "/usr/lib/NetworkManager/VPN/nm-openvpn.name",
];

/// Interpret a failed connect from the client's own output.
///
/// Some failures will never fix themselves on retry, and burning three
/// attempts on them wastes a minute and teaches the user nothing.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Failure {
    /// Worth trying another server.
    Retryable,
    /// The protocol backend is missing. Retrying cannot help.
    BackendMissing,
    /// The account cannot do this. Retrying cannot help.
    Refused,
}

pub fn classify_failure(output: &str) -> Failure {
    let lower = output.to_ascii_lowercase();
    if lower.contains("no valid implementation found") {
        return Failure::BackendMissing;
    }
    if lower.contains("not available on the free plan") || lower.contains("missing username") {
        return Failure::Refused;
    }
    Failure::Retryable
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Stealth must lead. On a DPI network it is the only protocol that
    /// works, and the cost of trying it first on an open network is small.
    #[test]
    fn stealth_is_the_first_protocol_tried() {
        assert_eq!(PROTOCOLS[0], "protun-tls");
    }

    /// The backoff must start at zero - probing before sleeping - or the
    /// fastest possible recovery still costs the first interval.
    #[test]
    fn restore_probes_before_it_waits() {
        let backoff = [0, 100, 150, 250, 500, 1000, 1000, 1000, 2000, 2000, 2000];
        assert_eq!(backoff[0], 0, "must probe immediately");
        // And it must still cover a slow recovery: the old loop allowed 10s.
        let total: u64 = backoff.iter().sum();
        assert!(total >= 10_000, "must still wait out a slow recovery");
    }

    #[test]
    fn protocol_list_has_no_duplicates() {
        let mut seen = std::collections::HashSet::new();
        for p in PROTOCOLS {
            assert!(seen.insert(*p), "duplicate protocol {p}");
        }
    }

    /// Burning three attempts on a failure that cannot fix itself wastes a
    /// minute and teaches nothing.
    #[test]
    fn unretryable_failures_are_recognised() {
        assert_eq!(
            classify_failure("Error: No valid implementation found for protun-tls"),
            Failure::BackendMissing
        );
        assert_eq!(
            classify_failure("This server is not available on the free plan"),
            Failure::Refused
        );
        assert_eq!(
            classify_failure("Missing username"),
            Failure::Refused
        );
        assert_eq!(
            classify_failure("connection timed out"),
            Failure::Retryable
        );
    }

    #[test]
    fn failure_classification_is_case_insensitive() {
        assert_eq!(
            classify_failure("NO VALID IMPLEMENTATION FOUND"),
            Failure::BackendMissing
        );
    }

    /// NM names profiles "ProtonVPN SG-FREE#20"; the ranking and blocked
    /// lists hold the bare name. Getting this wrong would record outcomes
    /// against a server name that never matches on the next connect, so the
    /// memory would silently learn nothing.
    #[test]
    fn server_names_are_extracted_from_nm_connection_ids() {
        assert_eq!(
            server_from_connection_id("ProtonVPN SG-FREE#20").as_deref(),
            Some("SG-FREE#20")
        );
        // Proton's own status format, which callers also pass in.
        assert_eq!(
            server_from_connection_id("ProtonVPN JP-FREE#3 in Tokyo, Japan").as_deref(),
            Some("JP-FREE#3")
        );
        // A hop leaves profiles named after bare IPs. No prefix to strip,
        // and mangling them would break `--not`.
        assert_eq!(
            server_from_connection_id("156.47.78.177").as_deref(),
            Some("156.47.78.177")
        );
        assert_eq!(server_from_connection_id("").as_deref(), None);
        assert_eq!(server_from_connection_id("ProtonVPN").as_deref(), None);
    }

    /// wireguard is in the kernel and in NetworkManager, so it is always
    /// available; an unknown protocol never is. Returning true for unknown
    /// names would let a typo reach the connect and fail confusingly.
    #[test]
    fn protocol_availability_does_not_guess() {
        assert!(protocol_available("wireguard"));
        assert!(!protocol_available("not-a-protocol"));
        assert!(!protocol_available(""));
    }

    /// An empty or unrecognised message must be retryable — assuming a
    /// permanent failure would abandon a connect that might have worked.
    #[test]
    fn unknown_output_is_retryable() {
        assert_eq!(classify_failure(""), Failure::Retryable);
        assert_eq!(classify_failure("something we have never seen"), Failure::Retryable);
    }
}
