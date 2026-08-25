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
///
/// D-Bus first, `nmcli` only if the bus is unreachable. Same reasoning as
/// everywhere else here: nmcli is a text layer over these exact calls and
/// costs ~45ms of process startup to produce them.
pub fn wifi_ssid() -> Option<String> {
    if let Some(s) = crate::dbus::wifi_ssid() {
        return Some(s);
    }
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

/// The IPv4 default gateway, from `/proc/net/route`.
///
/// Read rather than shelled out to. `ip route` costs a fork+exec for four
/// bytes that the kernel already exposes as a file, and this runs on every
/// `pvpn` invocation.
///
/// The format is fixed-width hex, little-endian, one route per line:
///     Iface  Destination  Gateway   Flags  ...
///     wlan0  00000000     0101A8C0  0003   ...
/// A destination of 00000000 is the default route.
pub fn default_gateway() -> Option<String> {
    let text = std::fs::read_to_string("/proc/net/route").ok()?;
    for line in text.lines().skip(1) {
        let mut f = line.split_whitespace();
        let _iface = f.next()?;
        let dest = f.next()?;
        let gw = f.next()?;
        if dest != "00000000" || gw == "00000000" {
            continue;
        }
        return hex_le_to_ipv4(gw);
    }
    None
}

/// `0101A8C0` -> `192.168.1.1`. Little-endian, as the kernel writes it.
fn hex_le_to_ipv4(hex: &str) -> Option<String> {
    let n = u32::from_str_radix(hex, 16).ok()?;
    let b = n.to_le_bytes();
    Some(format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]))
}

/// The gateway's MAC, from `/proc/net/arp`.
///
/// No ping fallback. The old implementation ran `ping -c1 -W1` when the
/// neighbour table had no entry, which costs a full second on a gateway
/// that does not answer ICMP - a second added to every `pvpn` command, to
/// refine a cache key. If the MAC is unknown the gateway IP is used
/// instead, which is stable enough and free.
pub fn gateway_mac(gw: &str) -> Option<String> {
    let text = std::fs::read_to_string("/proc/net/arp").ok()?;
    for line in text.lines().skip(1) {
        let mut f = line.split_whitespace();
        let ip = f.next()?;
        if ip != gw {
            continue;
        }
        let _hw_type = f.next()?;
        let _flags = f.next()?;
        let mac = f.next()?;
        // 00:00:00:00:00:00 means "known to be unknown".
        if mac != "00:00:00:00:00:00" {
            return Some(mac.to_string());
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

    /// The kernel writes the gateway little-endian. Getting the byte order
    /// wrong yields a plausible-looking but wrong address, which would
    /// silently split one network's memory across two cache keys.
    #[test]
    fn kernel_route_hex_decodes_little_endian() {
        assert_eq!(hex_le_to_ipv4("0101A8C0").as_deref(), Some("192.168.1.1"));
        assert_eq!(hex_le_to_ipv4("FE01A8C0").as_deref(), Some("192.168.1.254"));
        assert_eq!(hex_le_to_ipv4("00000000").as_deref(), Some("0.0.0.0"));
        assert_eq!(hex_le_to_ipv4("nonsense"), None);
    }

    /// Reading the real files must never panic, whatever they contain.
    #[test]
    fn proc_readers_are_safe() {
        let _ = default_gateway();
        let _ = gateway_mac("192.168.1.1");
        let _ = gateway_mac("not-an-ip");
    }

    #[test]
    fn short_hash_is_stable_and_distinct() {
        assert_eq!(short_hash("a"), short_hash("a"));
        assert_ne!(short_hash("a"), short_hash("b"));
    }
}
