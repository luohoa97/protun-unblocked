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

pub fn is_connected() -> bool {
    let Ok(out) = client().arg("status").output() else {
        return false;
    };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .any(|l| {
            let l = l.trim();
            l.starts_with("Status:") && l.contains("Connected")
        })
}

/// The server Proton believes it is on, e.g. `SG-FREE#20`.
///
/// Proton prints "NAME in City, Country"; rankings hold only NAME, so the
/// location half is trimmed here rather than by every caller.
pub fn current_server() -> Option<String> {
    let out = client().arg("status").output().ok()?;
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("Server:") {
            let name = rest.trim();
            let name = name.split(" in ").next().unwrap_or(name).trim();
            if !name.is_empty() {
                return Some(name.to_string());
            }
        }
    }
    None
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

pub fn disconnect() {
    let _ = client()
        .arg("disconnect")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
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

    for _ in 0..10 {
        if crate::probe::traffic_flows(probe_timeout).alive {
            return true;
        }
        std::thread::sleep(Duration::from_secs(1));
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
    let script = r#"
import sys
try:
    from proton.vpn.core.connection import VPNConnectorWrapper  # noqa
except Exception:
    pass
try:
    from proton.vpn.connection import events  # noqa
    from proton.vpn.connection.registry import get_registry
    reg = get_registry()
    sys.exit(0 if reg.get_from_factory(sys.argv[1]) else 1)
except Exception:
    # Fall back to the NM plugin file, which is what actually has to exist
    # for the protun backends.
    import os
    name = sys.argv[1]
    if name.startswith("protun"):
        sys.exit(0 if os.path.exists("/usr/lib/NetworkManager/VPN/nm-protun.name") else 1)
    sys.exit(0)
"#;
    Command::new("/usr/bin/python3")
        .arg("-c")
        .arg(script)
        .arg(proto)
        .env("PYTHONPATH", shim_dir())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

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

    /// An empty or unrecognised message must be retryable — assuming a
    /// permanent failure would abandon a connect that might have worked.
    #[test]
    fn unknown_output_is_retryable() {
        assert_eq!(classify_failure(""), Failure::Retryable);
        assert_eq!(classify_failure("something we have never seen"), Failure::Retryable);
    }
}
