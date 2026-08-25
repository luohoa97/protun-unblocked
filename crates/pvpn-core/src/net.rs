//! Which network am I on?
//!
//! Everything this project learns is learned *about a network*: which
//! servers this wifi lets through, which it refuses, how long a connect
//! takes here. So the identity has to be stable across reconnects and
//! distinct between networks that happen to share an SSID - "eduroam" is
//! not one network, and treating it as one would pool measurements from
//! opposite sides of the planet.
//!
//! SSID plus the gateway's MAC gets both: the MAC distinguishes two
//! networks with the same name, and survives DHCP handing you a different
//! address.

use std::process::Command;

/// The active wifi SSID, or `None` on wired/unknown.
pub fn wifi_ssid() -> Option<String> {
    let out = Command::new("nmcli")
        .args(["-t", "-f", "ACTIVE,SSID", "device", "wifi"])
        .output()
        .ok()?;
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        if let Some(ssid) = line.strip_prefix("yes:") {
            if !ssid.is_empty() {
                return Some(ssid.to_string());
            }
        }
    }
    None
}

/// The IPv4 default gateway.
pub fn default_gateway() -> Option<String> {
    let out = Command::new("ip")
        .args(["-4", "route", "show", "default"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    // "default via 192.168.1.1 dev wlan0 ..." - take the word after "via"
    // rather than a fixed field, because the format grows options over time.
    let mut words = text.split_whitespace();
    while let Some(w) = words.next() {
        if w == "via" {
            return words.next().map(|s| s.to_string());
        }
    }
    None
}

/// The gateway's MAC, pinging once if the neighbour table does not know it
/// yet. `ip neigh` only learns a gateway after something has talked to it,
/// so on a fresh connection the first lookup is empty.
pub fn gateway_mac(gw: &str) -> Option<String> {
    if let Some(mac) = neigh_lookup(gw) {
        return Some(mac);
    }
    let _ = Command::new("ping")
        .args(["-c1", "-W1", gw])
        .output();
    neigh_lookup(gw)
}

fn neigh_lookup(gw: &str) -> Option<String> {
    let out = Command::new("ip").args(["neigh", "show", gw]).output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let mut words = text.split_whitespace();
    while let Some(w) = words.next() {
        if w == "lladdr" {
            return words.next().map(|s| s.to_string());
        }
    }
    None
}

/// A stable identifier for the network we are on.
///
/// Format is `<ssid>-<10 hex chars>`, matching the shell implementation
/// byte for byte so both front-ends agree about which network's
/// measurements to use. The readable prefix is there so the cache
/// directory can be eyeballed when something looks wrong.
///
/// Returns `offline` when there is no SSID, no gateway and no MAC — which
/// is a real state, and must not be conflated with a network whose details
/// we merely failed to read.
pub fn network_id() -> String {
    let ssid = wifi_ssid();
    let gw = default_gateway();
    let mac = gw.as_deref().and_then(gateway_mac);

    if ssid.is_none() && gw.is_none() && mac.is_none() {
        return "offline".into();
    }

    let name = ssid.clone().unwrap_or_else(|| "wired".into());
    let tail = mac
        .or(gw)
        .unwrap_or_else(|| "none".into());
    let raw = format!("{name}|{tail}");
    format!("{name}-{}", short_hash(&raw))
}

/// First 10 hex characters of the SHA-256, via `sha256sum`.
///
/// Shelling out rather than vendoring a hash: this must produce the exact
/// same key as the shell front-end, which used `sha256sum | cut -c1-10`.
/// A different key would silently orphan everything already learned about
/// every network the user has been on. Runs once per invocation, not per
/// tick, so the process cost does not matter.
fn short_hash(input: &str) -> String {
    use std::io::Write;
    let mut child = match Command::new("sha256sum")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return "nohash0000".into(),
    };
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(input.as_bytes());
    }
    let Ok(out) = child.wait_with_output() else {
        return "nohash0000".into();
    };
    String::from_utf8_lossy(&out.stdout)
        .chars()
        .take(10)
        .collect()
}

/// Turn a network id into something safe to use as a filename.
///
/// SSIDs contain anything a human can type, including `/`. Sanitising by
/// allow-list rather than by escaping means a hostile SSID cannot escape
/// the cache directory.
pub fn sanitise(id: &str) -> String {
    id.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-' | '@') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An SSID is arbitrary user-controlled text. If it reached a path
    /// unsanitised, `../../` in an SSID would write outside the cache.
    #[test]
    fn sanitise_neutralises_path_traversal() {
        assert_eq!(sanitise("../../etc/passwd"), ".._.._etc_passwd");
        assert_eq!(sanitise("my wifi!"), "my_wifi_");
        assert_eq!(sanitise("cafe-2.4@home"), "cafe-2.4@home");
        assert!(!sanitise("a/b").contains('/'));
    }

    #[test]
    fn sanitise_is_idempotent() {
        let once = sanitise("weird/name here");
        assert_eq!(sanitise(&once), once);
    }

    /// The key must match the shell's `sha256sum | cut -c1-10` exactly, or
    /// everything already learned about every network is orphaned.
    #[test]
    fn short_hash_matches_the_shell_implementation() {
        // echo -n 'home|aa:bb:cc:dd:ee:ff' | sha256sum | cut -c1-10
        let h = short_hash("home|aa:bb:cc:dd:ee:ff");
        assert_eq!(h.len(), 10);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));

        let expected = std::process::Command::new("sh")
            .arg("-c")
            .arg("printf '%s' 'home|aa:bb:cc:dd:ee:ff' | sha256sum | cut -c1-10")
            .output()
            .unwrap();
        assert_eq!(h, String::from_utf8_lossy(&expected.stdout).trim());
    }

    #[test]
    fn short_hash_is_stable_and_distinct() {
        assert_eq!(short_hash("a"), short_hash("a"));
        assert_ne!(short_hash("a"), short_hash("b"));
    }
}
