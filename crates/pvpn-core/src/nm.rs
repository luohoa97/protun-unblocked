//! NetworkManager: what it is doing, and what it says the user asked for.
//!
//! Both of this project's shipped regressions live in this file's history,
//! so the reasoning is recorded rather than summarised.
//!
//! **First mistake: polling.** The daemon sampled NM's connection list to
//! decide what the user wanted. Polling samples STATE, and state cannot
//! distinguish "this tunnel is here" from "this tunnel is thirty
//! milliseconds from being gone". A poll landed in the gap between
//! `pvpn down` writing intent=down and NM finishing the teardown, saw a
//! live tunnel with intent=down, concluded the user must have switched it
//! on from GNOME, and adopted it back to intent=up. Autoreconnect finished
//! the job and the VPN would not stay off.
//!
//! A signal carries the TRANSITION and NM's own reason code, so that gap
//! does not exist and nothing has to be inferred.
//!
//! **Second mistake: the right signal, the wrong speaker.**
//! `Connection.Active.StateChanged` is the BASE interface, implemented by
//! every active connection - wifi, bridges, loopback, virbr0 - not just
//! tunnels. Tearing the tunnel out re-activates the wifi underneath it, so
//! `pvpn down` was immediately followed by the wifi announcing ACTIVATED on
//! the very same interface, with the very same state number a WireGuard
//! tunnel uses. That was read as "the user switched the VPN on" and the VPN
//! restarted itself.
//!
//! Listening to the right interface is not enough: the SENDER has to be
//! checked too. That is what `TunnelPaths` is for.
//!
//! **No regex here, deliberately.** Every parser below splits on literal
//! markers. If NetworkManager changes its wording, the result is `None` -
//! which is inert - rather than a confident misread. A pattern that matched
//! loosely would reintroduce exactly the class of bug this file is a
//! monument to.

use std::collections::HashSet;
use std::process::Command;

/// Something happened to the VPN, as reported by NetworkManager itself.
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub enum Ev {
    /// A tunnel finished activating.
    Activated,
    /// It went away because somebody asked: GNOME's switch, nmcli,
    /// `pvpn down`.
    WentDownDeliberately,
    /// It went away on its own.
    Failed,
}

/// D-Bus reason codes, from NetworkManager's own enums
/// (`NMActiveConnectionStateReason` / `NMVpnConnectionStateReason`). Only
/// the two that mean "a human asked for this" matter; everything else is a
/// fault, and treating a fault as an instruction would disable
/// autoreconnect exactly when it is needed.
pub const REASON_USER_DISCONNECTED: u32 = 2;
pub const REASON_CONNECTION_REMOVED: u32 = 11;

pub const AC_PREFIX: &str = "/org/freedesktop/NetworkManager/ActiveConnection/";

/// Which interface a signal arrived on, and what it said.
///
/// This distinction is not pedantry, it is the second bug. `VPN.Connection`
/// is a VPN-only interface, so anything arriving on it is a tunnel by
/// construction. `Connection.Active` is shared with everything on the box.
#[derive(PartialEq, Eq, Debug, Clone)]
pub enum Sig {
    /// From the VPN-only interface: trust it.
    Vpn(Ev),
    /// From the shared interface: vet `path` before believing it.
    Generic { path: String, ev: Ev },
}

/// Pull `(state, reason)` out of a gdbus signal line.
///
/// The line looks like:
///     /org/.../ActiveConnection/12: org...VpnStateChanged (uint32 7, uint32 2)
pub fn parse_state_reason(line: &str, marker: &str) -> Option<(u32, u32)> {
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

/// Turn one line of gdbus output into a signal, if it is one we can read.
///
/// Two interfaces, because NetworkManager models the two tunnel kinds
/// differently and they do NOT share a state enum:
///
///   VPN.Connection.VpnStateChanged      protun / OpenVPN.  5=ACTIVATED,
///                                       6=FAILED, 7=DISCONNECTED
///   Connection.Active.StateChanged      WireGuard.         2=ACTIVATED,
///                                       4=DEACTIVATED
pub fn parse_signal(line: &str) -> Option<Sig> {
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

/// The system bus address. A systemd *user* service does not inherit it,
/// and without it gdbus fails with "No such file or directory" - which
/// reads like a permissions problem and is not one. Receiving NM's
/// broadcast signals needs no root; that was verified, not assumed.
pub fn dbus_addr() -> String {
    std::env::var("DBUS_SYSTEM_BUS_ADDRESS")
        .unwrap_or_else(|_| "unix:path=/run/dbus/system_bus_socket".into())
}

/// Read one property off a NetworkManager object as raw gdbus text.
///
/// `--timeout` is set because the default is 25 seconds, and a stalled
/// system bus would otherwise stall signal processing for that long.
pub fn get_property(path: &str, iface: &str, prop: &str) -> Option<String> {
    let out = Command::new("gdbus")
        .args([
            "call",
            "--system",
            "--timeout",
            "5",
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
pub fn first_quoted(raw: &str) -> Option<String> {
    let (_, rest) = raw.split_once('\'')?;
    Some(rest.chars().take_while(|c| *c != '\'').collect())
}

/// The set of active-connection object paths that are tunnels.
///
/// Kept as a set rather than re-queried per signal, because on the way OUT
/// the object is already gone and cannot be interrogated. A tunnel is
/// recognised on the way in and remembered, so its later disappearance is
/// still attributable.
#[derive(Debug, Default)]
pub struct TunnelPaths(HashSet<String>);

impl TunnelPaths {
    /// Learn which active connections are tunnels right now.
    ///
    /// Seeded when the watcher starts so a tunnel that was already up
    /// before the daemon started is still recognised when it goes away.
    pub fn seeded() -> Self {
        let mut set = HashSet::new();
        let Some(raw) = get_property(
            "/org/freedesktop/NetworkManager",
            "org.freedesktop.NetworkManager",
            "ActiveConnections",
        ) else {
            return Self(set);
        };
        // (<[objectpath '/org/...', '/org/...']>,)
        for token in raw.split('\'') {
            if token.starts_with(AC_PREFIX) && is_tunnel_path(token) {
                set.insert(token.to_string());
            }
        }
        Self(set)
    }

    pub fn insert(&mut self, path: String) {
        self.0.insert(path);
    }

    pub fn remove(&mut self, path: &str) -> bool {
        self.0.remove(path)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Decide what a parsed signal means, given what we know about senders.
    ///
    /// Returns `None` for anything that cannot be positively attributed to
    /// a tunnel. Inert beats confident.
    pub fn classify(&mut self, sig: Sig) -> Option<Ev> {
        match sig {
            Sig::Vpn(ev) => Some(ev),
            // Every active connection speaks on this interface, so an
            // ACTIVATED here is only ours if NM says the sender is a
            // tunnel. Skipping this check is what made `pvpn down` bounce
            // straight back up.
            Sig::Generic {
                path,
                ev: Ev::Activated,
            } => {
                if is_tunnel_path(&path) {
                    self.0.insert(path);
                    Some(Ev::Activated)
                } else {
                    None
                }
            }
            Sig::Generic { path, ev } => {
                if self.0.remove(&path) {
                    Some(ev)
                } else {
                    None
                }
            }
        }
    }
}

/// Is the active connection at `path` actually a tunnel?
///
/// Sampling NM here is safe in a way the old polling loop was not: this
/// only runs just after NM reported ACTIVATED, so the object exists by
/// definition. We are identifying something that is present, not guessing
/// whether something is still there.
pub fn is_tunnel_path(path: &str) -> bool {
    let Some(raw) = get_property(
        path,
        "org.freedesktop.NetworkManager.Connection.Active",
        "Type",
    ) else {
        return false;
    };
    matches!(
        first_quoted(&raw).as_deref(),
        Some("vpn") | Some("wireguard")
    )
}

/// The VPN as NetworkManager sees it, which is what GNOME's switch drives.
/// Returns the connection name, or `None` when no VPN is up.
///
/// Used only to answer "is a tunnel up right now" for the health loop and
/// the state file - NEVER to decide what the user wants. That decision is
/// made from signals, for the reasons at the top of this file.
///
/// Any active vpn/wireguard profile counts, not just ones named
/// "ProtonVPN": hopping leaves profiles named after bare server IPs.
pub fn vpn_connection() -> Option<String> {
    let out = Command::new("nmcli")
        .args(["-t", "-f", "NAME,TYPE", "connection", "show", "--active"])
        .output()
        .ok()?;
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        // -t output is colon-separated; a connection name may itself
        // contain an escaped colon, so take TYPE from the END, not field 2.
        let Some((name, kind)) = line.rsplit_once(':') else {
            continue;
        };
        if kind == "vpn" || kind == "wireguard" {
            return Some(name.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const VPN: &str = "/org/freedesktop/NetworkManager/ActiveConnection/12: \
                       org.freedesktop.NetworkManager.VPN.Connection.VpnStateChanged";
    const ACT: &str = "/org/freedesktop/NetworkManager/ActiveConnection/9: \
                       org.freedesktop.NetworkManager.Connection.Active.StateChanged";

    /// The reason codes are what make `pvpn down` work, so they are pinned:
    /// a change in this table is a change in whether the daemon fights the
    /// user.
    #[test]
    fn signal_lines_map_to_the_right_events() {
        assert_eq!(
            parse_signal(&format!("{VPN} (uint32 7, uint32 2)")),
            Some(Sig::Vpn(Ev::WentDownDeliberately))
        );
        assert_eq!(
            parse_signal(&format!("{VPN} (uint32 7, uint32 11)")),
            Some(Sig::Vpn(Ev::WentDownDeliberately))
        );
        // LOGIN_FAILED is a fault - standing down here would disable
        // autoreconnect exactly when it is needed.
        assert_eq!(
            parse_signal(&format!("{VPN} (uint32 6, uint32 10)")),
            Some(Sig::Vpn(Ev::Failed))
        );
        assert_eq!(
            parse_signal(&format!("{VPN} (uint32 5, uint32 1)")),
            Some(Sig::Vpn(Ev::Activated))
        );

        let p = "/org/freedesktop/NetworkManager/ActiveConnection/9";
        assert_eq!(
            parse_signal(&format!("{ACT} (uint32 2, uint32 1)")),
            Some(Sig::Generic {
                path: p.to_string(),
                ev: Ev::Activated
            })
        );
        assert_eq!(
            parse_signal(&format!("{ACT} (uint32 4, uint32 2)")),
            Some(Sig::Generic {
                path: p.to_string(),
                ev: Ev::WentDownDeliberately
            })
        );
    }

    /// THE regression. `Connection.Active.StateChanged` is emitted by every
    /// active connection, so the wifi coming back after a tunnel is torn
    /// down looks byte-for-byte like a tunnel activating - same interface,
    /// same state 2. The only thing separating them is the sender's path.
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

    /// A DEACTIVATED from a path we never saw activate is not ours, and
    /// must not stand the daemon down. Turning off wifi is not the same as
    /// asking for the VPN to stay off.
    #[test]
    fn unknown_senders_cannot_stand_the_daemon_down() {
        let mut paths = TunnelPaths::default();
        let wifi = Sig::Generic {
            path: format!("{AC_PREFIX}303"),
            ev: Ev::WentDownDeliberately,
        };
        assert_eq!(paths.classify(wifi), None);

        // But a path we recorded as a tunnel IS ours.
        paths.insert(format!("{AC_PREFIX}9"));
        let tun = Sig::Generic {
            path: format!("{AC_PREFIX}9"),
            ev: Ev::WentDownDeliberately,
        };
        assert_eq!(paths.classify(tun), Some(Ev::WentDownDeliberately));
        // ...and only once; it is gone now.
        let again = Sig::Generic {
            path: format!("{AC_PREFIX}9"),
            ev: Ev::WentDownDeliberately,
        };
        assert_eq!(paths.classify(again), None);
    }

    /// Anything we do not positively recognise must be inert. A daemon that
    /// guesses from half-understood input is how the polling version broke.
    #[test]
    fn unrecognised_lines_are_inert() {
        assert_eq!(parse_signal(&format!("{VPN} (uint32 3, uint32 1)")), None);
        assert_eq!(
            parse_signal(
                "/org/freedesktop/NetworkManager/AccessPoint/13177: \
                 org.freedesktop.DBus.Properties.PropertiesChanged ('x',)"
            ),
            None
        );
        assert_eq!(parse_signal(&format!("{VPN} (garbage)")), None);
        assert_eq!(parse_signal(&format!("{VPN} (uint32 7)")), None);
        assert_eq!(parse_signal(""), None);
        // Shared interface, but the sender is not an active connection at
        // all, so there is no path to vet.
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

    #[test]
    fn first_quoted_reads_gdbus_property_output() {
        assert_eq!(first_quoted("(<'wireguard'>,)").as_deref(), Some("wireguard"));
        assert_eq!(first_quoted("(<''>,)").as_deref(), Some(""));
        assert_eq!(first_quoted("no quotes here"), None);
    }
}
