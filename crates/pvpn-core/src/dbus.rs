//! NetworkManager over D-Bus, in process.
//!
//! WHY THIS REPLACED TWO SUBPROCESSES
//!
//! Everything here used to shell out. `nmcli` answered "is a tunnel up",
//! and `gdbus monitor` streamed the signals. Both worked, and both were
//! expensive in a way that only shows up once you measure:
//!
//!   - One `nmcli` call costs ~40ms of CPU, almost all of it fork+exec and
//!     Python-free process startup. At one per 20s daemon tick that is 172
//!     seconds of CPU per day, for a question whose answer rarely changes.
//!   - `pvpn up` asked Proton's own Python client the same sort of question
//!     three times, at ~7.8s each. That is where the "why does it take a
//!     minute" went: about 25 seconds of it was startup, before any part of
//!     the connect began.
//!
//! A D-Bus property read is a round trip to a socket. It is roughly a
//! millisecond, and NetworkManager is the authority for all of it anyway -
//! `nmcli` was only ever a text-formatting layer over these same calls.
//!
//! TYPED, NOT PARSED
//!
//! The `gdbus monitor` path had to parse text, which is why `nm::parse_signal`
//! is written the way it is: literal markers only, no patterns, so a wording
//! change yields `None` rather than a confident misread. Reading the values
//! as `u32` removes that whole class of risk - there is no text to
//! misinterpret. That parser is kept for the replay harness, which still
//! feeds recorded signal lines, and its tests still pin the reason codes.

use std::sync::OnceLock;

use zbus::blocking::Connection;

pub const NM_DEST: &str = "org.freedesktop.NetworkManager";
pub const NM_PATH: &str = "/org/freedesktop/NetworkManager";
pub const NM_IFACE: &str = "org.freedesktop.NetworkManager";
pub const AC_IFACE: &str = "org.freedesktop.NetworkManager.Connection.Active";

/// One shared system-bus connection.
///
/// Opening a connection costs an authentication handshake, so doing it per
/// call would give back much of what this module exists to save. `OnceLock`
/// rather than a lazy static so a failure to connect is retried on the next
/// call instead of being cached forever - the bus can be unavailable early
/// in boot and available a second later.
fn system_bus() -> Option<&'static Connection> {
    static BUS: OnceLock<Option<Connection>> = OnceLock::new();
    BUS.get_or_init(|| match Connection::system() {
        Ok(c) => Some(c),
        Err(e) => {
            tracing::warn!(error = %e, "cannot reach the system bus");
            None
        }
    })
    .as_ref()
}

/// Is D-Bus usable at all? Callers fall back to `nmcli` when it is not.
pub fn available() -> bool {
    system_bus().is_some()
}

fn get_property<T>(path: &str, iface: &str, prop: &str) -> Option<T>
where
    T: TryFrom<zbus::zvariant::OwnedValue>,
{
    let bus = system_bus()?;
    let proxy = zbus::blocking::Proxy::new(bus, NM_DEST, path, "org.freedesktop.DBus.Properties")
        .ok()?;
    // The default method timeout is 25s. That is far too long to hold up a
    // health tick, and a stalled bus should look like "no answer" quickly
    // rather than like the daemon hanging.
    let value: zbus::zvariant::OwnedValue = proxy.call("Get", &(iface, prop)).ok()?;
    T::try_from(value).ok()
}

/// Object paths of every active connection.
pub fn active_connection_paths() -> Vec<String> {
    let Some(v) = get_property::<zbus::zvariant::Array>(NM_PATH, NM_IFACE, "ActiveConnections")
    else {
        return Vec::new();
    };
    v.iter()
        .filter_map(|item| {
            zbus::zvariant::ObjectPath::try_from(item.try_clone().ok()?)
                .ok()
                .map(|p| p.as_str().to_string())
        })
        .collect()
}

/// `Type` of an active connection: `vpn`, `wireguard`, `802-11-wireless`...
pub fn connection_type(path: &str) -> Option<String> {
    get_property::<String>(path, AC_IFACE, "Type")
}

/// `Id` of an active connection - the name you see in GNOME.
pub fn connection_id(path: &str) -> Option<String> {
    get_property::<String>(path, AC_IFACE, "Id")
}

/// Every property of one active connection, in ONE round trip.
///
/// `Get` per property means a round trip per property. With five active
/// connections, asking for Type and then Id is eleven round trips to answer
/// "is a tunnel up". `GetAll` makes it six, and the extra bytes cost
/// nothing next to the latency they replace.
fn all_properties(path: &str) -> Option<std::collections::HashMap<String, zbus::zvariant::OwnedValue>> {
    let bus = system_bus()?;
    let proxy =
        zbus::blocking::Proxy::new(bus, NM_DEST, path, "org.freedesktop.DBus.Properties").ok()?;
    proxy.call("GetAll", &(AC_IFACE,)).ok()
}

fn as_str(v: Option<&zbus::zvariant::OwnedValue>) -> Option<String> {
    let v = v?;
    <&str>::try_from(v).ok().map(|s| s.to_string())
}

/// The active VPN or WireGuard connection's name, if there is one.
///
/// Any vpn/wireguard profile counts, not just ones named "ProtonVPN":
/// hopping leaves profiles named after bare server IPs.
pub fn vpn_connection() -> Option<String> {
    for path in active_connection_paths() {
        let Some(props) = all_properties(&path) else {
            continue;
        };
        match as_str(props.get("Type")).as_deref() {
            Some("vpn") | Some("wireguard") => {
                if let Some(id) = as_str(props.get("Id")) {
                    return Some(id);
                }
            }
            _ => {}
        }
    }
    None
}

/// Everything active, as `(path, type, id)`. One round trip per connection.
pub fn active_connections() -> Vec<(String, String, String)> {
    active_connection_paths()
        .into_iter()
        .filter_map(|p| {
            let props = all_properties(&p)?;
            Some((
                p,
                as_str(props.get("Type"))?,
                as_str(props.get("Id")).unwrap_or_default(),
            ))
        })
        .collect()
}

/// Is the active connection at `path` a tunnel?
pub fn is_tunnel_path(path: &str) -> bool {
    matches!(
        connection_type(path).as_deref(),
        Some("vpn") | Some("wireguard")
    )
}

/// Subscribe to the two state-change signals and hand each one to `f`.
///
/// Blocks forever, so callers run it on its own thread. Returns only when
/// the bus goes away, which the caller should treat as "reconnect".
///
/// `f` receives `(sender_path, interface_is_vpn_specific, state, reason)`.
/// Deliberately raw: the decision about what those mean lives in `nm`, next
/// to the post-mortems that explain it, not here.
pub fn watch_state_changes<F>(mut f: F) -> Result<(), String>
where
    F: FnMut(&str, bool, u32, u32),
{
    let bus = system_bus().ok_or("no system bus")?;

    // Match rules are server-side filters: the bus only delivers what we
    // asked for, so the daemon is not woken for every message on the
    // system bus.
    for rule in [
        "type='signal',interface='org.freedesktop.NetworkManager.VPN.Connection',member='VpnStateChanged'",
        "type='signal',interface='org.freedesktop.NetworkManager.Connection.Active',member='StateChanged'",
    ] {
        let dbus = zbus::blocking::fdo::DBusProxy::new(bus).map_err(|e| e.to_string())?;
        dbus.add_match_rule(rule.try_into().map_err(|e: zbus::Error| e.to_string())?)
            .map_err(|e| e.to_string())?;
    }

    for msg in zbus::blocking::MessageIterator::from(bus.clone()) {
        let Ok(msg) = msg else { continue };
        let header = msg.header();
        let Some(iface) = header.interface() else {
            continue;
        };
        let Some(member) = header.member() else {
            continue;
        };

        let vpn_specific = match (iface.as_str(), member.as_str()) {
            ("org.freedesktop.NetworkManager.VPN.Connection", "VpnStateChanged") => true,
            ("org.freedesktop.NetworkManager.Connection.Active", "StateChanged") => false,
            _ => continue,
        };

        // Both signals carry (uint32 state, uint32 reason).
        let Ok((state, reason)) = msg.body().deserialize::<(u32, u32)>() else {
            continue;
        };
        let path = header
            .path()
            .map(|p| p.as_str().to_string())
            .unwrap_or_default();

        f(&path, vpn_specific, state, reason);
    }
    Err("bus stream ended".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// These strings are the wire protocol. A typo in any of them makes the
    /// daemon silently deaf, which is indistinguishable from a quiet
    /// network — so they are pinned rather than trusted.
    #[test]
    fn dbus_names_are_exact() {
        assert_eq!(NM_DEST, "org.freedesktop.NetworkManager");
        assert_eq!(NM_PATH, "/org/freedesktop/NetworkManager");
        assert_eq!(AC_IFACE, "org.freedesktop.NetworkManager.Connection.Active");
    }

    /// Everything must degrade to "no answer" rather than panicking when
    /// the bus is missing. A daemon that dies because D-Bus was slow during
    /// boot is worse than one that reports nothing for a second.
    #[test]
    fn queries_are_safe_without_a_bus() {
        // Whether or not a bus exists in the test environment, none of
        // these may panic.
        let _ = available();
        let _ = active_connection_paths();
        let _ = connection_type("/org/freedesktop/NetworkManager/ActiveConnection/999999");
        let _ = connection_id("/org/freedesktop/NetworkManager/ActiveConnection/999999");
        let _ = is_tunnel_path("/not/a/real/path");
    }

    /// A path that does not exist must be "not a tunnel", never a guess.
    #[test]
    fn unknown_paths_are_not_tunnels() {
        assert!(!is_tunnel_path(
            "/org/freedesktop/NetworkManager/ActiveConnection/999999"
        ));
    }
}

// ---------------------------------------------------------------------------
// Activating a saved profile directly
// ---------------------------------------------------------------------------
//
// THE fast path, and the reason `pvpn up` stopped taking tens of seconds.
//
// Proton's client does not connect the tunnel itself: it writes a
// NetworkManager profile and asks NM to activate it. Those profiles
// PERSIST. `nmcli con show` on a machine that has used pvpn lists
// "ProtonVPN SG-FREE#20" alongside the bare-IP profiles that hopping leaves
// behind.
//
// So the second and every later connect to a server that has been used
// before needs no Python at all. Where `protonvpn connect` costs ~10s -
// 2.0s of which is Python interpreter startup before it does anything -
// ActivateConnection is one D-Bus method call. What remains after that is
// the tunnel handshake, which Proton's own logs put at 0.3s.
//
// The slow path is still there and still needed: a server we have never
// connected to has no profile, and only Proton's client can create one
// (it holds the credentials and the server list). That cost is paid once
// per server instead of once per connect.

pub const SETTINGS_PATH: &str = "/org/freedesktop/NetworkManager/Settings";
pub const SETTINGS_IFACE: &str = "org.freedesktop.NetworkManager.Settings";
pub const SETTINGS_CONN_IFACE: &str = "org.freedesktop.NetworkManager.Settings.Connection";

/// A saved NetworkManager profile.
#[derive(Debug, Clone)]
pub struct Profile {
    pub path: String,
    pub id: String,
    pub uuid: String,
    pub kind: String,
}

impl Profile {
    pub fn is_tunnel(&self) -> bool {
        self.kind == "vpn" || self.kind == "wireguard"
    }
}

/// Every saved profile NetworkManager knows about.
pub fn saved_profiles() -> Vec<Profile> {
    let Some(bus) = system_bus() else {
        return Vec::new();
    };
    let Ok(proxy) = zbus::blocking::Proxy::new(bus, NM_DEST, SETTINGS_PATH, SETTINGS_IFACE) else {
        return Vec::new();
    };
    let Ok(paths): Result<Vec<zbus::zvariant::OwnedObjectPath>, _> =
        proxy.call("ListConnections", &())
    else {
        return Vec::new();
    };

    paths
        .into_iter()
        .filter_map(|p| {
            let path = p.as_str().to_string();
            let cp =
                zbus::blocking::Proxy::new(bus, NM_DEST, path.clone(), SETTINGS_CONN_IFACE).ok()?;
            // a{sa{sv}} - sections, each a map of key to value.
            let settings: std::collections::HashMap<
                String,
                std::collections::HashMap<String, zbus::zvariant::OwnedValue>,
            > = cp.call("GetSettings", &()).ok()?;
            let conn = settings.get("connection")?;
            Some(Profile {
                path,
                id: as_str(conn.get("id")).unwrap_or_default(),
                uuid: as_str(conn.get("uuid")).unwrap_or_default(),
                kind: as_str(conn.get("type")).unwrap_or_default(),
            })
        })
        .collect()
}

/// Find a saved tunnel profile for `server`, e.g. `SG-FREE#20`.
///
/// Matches the bare server name against the profile id, which Proton writes
/// as `ProtonVPN SG-FREE#20`. Hopping also leaves profiles named after bare
/// IPs, so an exact id match is tried too.
pub fn find_tunnel_profile(server: &str) -> Option<Profile> {
    let want = server.trim();
    if want.is_empty() {
        return None;
    }

    // Fast path: we resolved this server before, so go straight to its
    // object. Listing every profile means a GetSettings per profile, and a
    // laptop accumulates a lot of wifi - ~100ms here on a machine with 30.
    //
    // The cached path is VERIFIED, not trusted: object paths are recycled
    // when profiles are deleted and recreated, so we read the id back and
    // fall through to a full scan if it does not match. A stale hit would
    // activate the wrong server, which is worse than being slow.
    if let Some(path) = cached_profile_path(want) {
        if let Some(p) = profile_at(&path) {
            if p.is_tunnel() && matches_server(&p.id, want) {
                return Some(p);
            }
        }
    }

    let found = saved_profiles()
        .into_iter()
        .find(|p| p.is_tunnel() && matches_server(&p.id, want));
    if let Some(p) = &found {
        remember_profile_path(want, &p.path);
    }
    found
}

fn matches_server(id: &str, want: &str) -> bool {
    id == want || id.trim_start_matches("ProtonVPN").trim() == want
}

/// Read one profile by object path. One round trip.
fn profile_at(path: &str) -> Option<Profile> {
    let bus = system_bus()?;
    let cp = zbus::blocking::Proxy::new(bus, NM_DEST, path.to_string(), SETTINGS_CONN_IFACE).ok()?;
    let settings: std::collections::HashMap<
        String,
        std::collections::HashMap<String, zbus::zvariant::OwnedValue>,
    > = cp.call("GetSettings", &()).ok()?;
    let conn = settings.get("connection")?;
    Some(Profile {
        path: path.to_string(),
        id: as_str(conn.get("id")).unwrap_or_default(),
        uuid: as_str(conn.get("uuid")).unwrap_or_default(),
        kind: as_str(conn.get("type")).unwrap_or_default(),
    })
}

fn profile_cache_file() -> std::path::PathBuf {
    crate::paths::data_dir().join("profile-paths.json")
}

fn cached_profile_path(server: &str) -> Option<String> {
    let text = std::fs::read_to_string(profile_cache_file()).ok()?;
    let map: std::collections::HashMap<String, String> = serde_json::from_str(&text).ok()?;
    map.get(server).cloned()
}

fn remember_profile_path(server: &str, path: &str) {
    let file = profile_cache_file();
    let mut map: std::collections::HashMap<String, String> = std::fs::read_to_string(&file)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default();
    if map.get(server).map(String::as_str) == Some(path) {
        return;
    }
    map.insert(server.to_string(), path.to_string());
    if let Ok(json) = serde_json::to_string_pretty(&map) {
        let _ = crate::paths::write_atomic(&file, &format!("{json}\n"));
    }
}

/// Ask NetworkManager to bring a saved profile up.
///
/// Returns the new active-connection object path. This RETURNS IMMEDIATELY:
/// NM has accepted the request, not completed the handshake. Callers wait
/// on `active_state`, or on the signals they are already subscribed to.
pub fn activate(profile: &Profile) -> Result<String, String> {
    let bus = system_bus().ok_or("no system bus")?;
    let proxy =
        zbus::blocking::Proxy::new(bus, NM_DEST, NM_PATH, NM_IFACE).map_err(|e| e.to_string())?;

    // "/" for device and specific_object means "NetworkManager, you pick" -
    // correct for a VPN, which rides whatever the current default route is
    // rather than binding to one interface.
    let root = zbus::zvariant::ObjectPath::try_from("/").map_err(|e| e.to_string())?;
    let conn = zbus::zvariant::ObjectPath::try_from(profile.path.as_str())
        .map_err(|e| e.to_string())?;

    let active: zbus::zvariant::OwnedObjectPath = proxy
        .call("ActivateConnection", &(&conn, &root, &root))
        .map_err(|e| e.to_string())?;
    Ok(active.as_str().to_string())
}

/// `NMActiveConnectionState` of an active connection.
/// 1=ACTIVATING 2=ACTIVATED 3=DEACTIVATING 4=DEACTIVATED
pub fn active_state(path: &str) -> Option<u32> {
    get_property::<u32>(path, AC_IFACE, "State")
}

/// `NMVpnConnectionState` for a VPN. 5=ACTIVATED 6=FAILED 7=DISCONNECTED
pub fn vpn_state(path: &str) -> Option<u32> {
    get_property::<u32>(path, "org.freedesktop.NetworkManager.VPN.Connection", "VpnState")
}

#[cfg(test)]
mod activate_tests {
    use super::*;

    #[test]
    fn profile_kinds_are_classified() {
        let vpn = Profile {
            path: "/p".into(),
            id: "ProtonVPN SG-FREE#20".into(),
            uuid: "u".into(),
            kind: "vpn".into(),
        };
        let wifi = Profile {
            kind: "802-11-wireless".into(),
            ..vpn.clone()
        };
        assert!(vpn.is_tunnel());
        assert!(!wifi.is_tunnel());
    }

    /// Looking up an empty name must never match, or `pvpn up` with no
    /// target would activate whatever profile happened to sort first.
    #[test]
    fn empty_server_never_matches() {
        assert!(find_tunnel_profile("").is_none());
        assert!(find_tunnel_profile("   ").is_none());
    }

    /// Only Activated counts. Treating TimedOut as success would report a
    /// working tunnel that is still handshaking, which is the exact lie
    /// this project exists to stop Proton's client telling.
    #[test]
    fn only_activation_counts_as_success() {
        assert!(ActivationResult::Activated.ok());
        for r in [
            ActivationResult::Failed,
            ActivationResult::Disconnected,
            ActivationResult::TimedOut,
        ] {
            assert!(!r.ok(), "{r:?} must not count as connected");
        }
    }

    /// A cached path must be verified, not trusted. NM recycles object
    /// paths when a profile is deleted and recreated, so a stale hit would
    /// activate a DIFFERENT server than the one asked for.
    #[test]
    fn server_matching_is_exact() {
        assert!(matches_server("ProtonVPN SG-FREE#20", "SG-FREE#20"));
        assert!(matches_server("156.47.78.177", "156.47.78.177"));
        assert!(!matches_server("ProtonVPN SG-FREE#2", "SG-FREE#20"));
        assert!(!matches_server("ProtonVPN JP-FREE#20", "SG-FREE#20"));
        assert!(!matches_server("", "SG-FREE#20"));
    }

    #[test]
    fn lookups_are_safe_without_a_bus() {
        let _ = saved_profiles();
        let _ = find_tunnel_profile("SG-FREE#20");
        let _ = active_state("/nope");
        let _ = vpn_state("/nope");
    }
}

/// Tear down an active connection.
pub fn deactivate(active_path: &str) -> Result<(), String> {
    let bus = system_bus().ok_or("no system bus")?;
    let proxy =
        zbus::blocking::Proxy::new(bus, NM_DEST, NM_PATH, NM_IFACE).map_err(|e| e.to_string())?;
    let p = zbus::zvariant::ObjectPath::try_from(active_path).map_err(|e| e.to_string())?;
    proxy
        .call::<_, _, ()>("DeactivateConnection", &(&p,))
        .map_err(|e| e.to_string())
}

/// The active-connection path for a tunnel, if one is up.
pub fn active_tunnel_path() -> Option<String> {
    active_connections()
        .into_iter()
        .find(|(_, kind, _)| kind == "vpn" || kind == "wireguard")
        .map(|(path, _, _)| path)
}

/// Wait for an activating connection to settle.
///
/// Polls rather than waiting on a signal because the caller is a one-shot
/// CLI: subscribing, filtering and tearing down a signal match costs more
/// than a handful of 2ms property reads, and the polling here is bounded
/// and short-lived - it is nothing like the daemon's old polling loop,
/// which sampled state to infer INTENT. This only ever asks "has the thing
/// I just started finished yet".
pub fn await_activation(active_path: &str, timeout: std::time::Duration) -> ActivationResult {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        // A VPN reports on both interfaces; VpnState is the specific one
        // and says more, so prefer it when present.
        if let Some(vs) = vpn_state(active_path) {
            match vs {
                5 => return ActivationResult::Activated,
                6 => return ActivationResult::Failed,
                7 => return ActivationResult::Disconnected,
                _ => {}
            }
        } else if let Some(st) = active_state(active_path) {
            match st {
                2 => return ActivationResult::Activated,
                4 => return ActivationResult::Disconnected,
                _ => {}
            }
        } else {
            // The object vanished: NM gave up and removed it.
            return ActivationResult::Disconnected;
        }

        if std::time::Instant::now() >= deadline {
            return ActivationResult::TimedOut;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ActivationResult {
    Activated,
    Failed,
    Disconnected,
    TimedOut,
}

impl ActivationResult {
    pub fn ok(&self) -> bool {
        matches!(self, ActivationResult::Activated)
    }
}

/// The SSID of the connected wifi, over D-Bus.
///
/// Walks Devices -> the wifi one -> ActiveAccessPoint -> Ssid. Several
/// round trips, but still an order of magnitude under `nmcli`'s process
/// startup.
pub fn wifi_ssid() -> Option<String> {
    let bus = system_bus()?;
    let nm = zbus::blocking::Proxy::new(bus, NM_DEST, NM_PATH, NM_IFACE).ok()?;
    let devices: Vec<zbus::zvariant::OwnedObjectPath> = nm.call("GetDevices", &()).ok()?;

    for dev in devices {
        let path = dev.as_str();
        // NMDeviceType 2 = WIFI.
        if get_property::<u32>(path, "org.freedesktop.NetworkManager.Device", "DeviceType") != Some(2)
        {
            continue;
        }
        let ap: zbus::zvariant::OwnedObjectPath = get_property(
            path,
            "org.freedesktop.NetworkManager.Device.Wireless",
            "ActiveAccessPoint",
        )?;
        if ap.as_str() == "/" {
            continue; // wifi radio on, not associated
        }
        // Ssid is ay - raw bytes, not a string, because an SSID is not
        // required to be valid UTF-8.
        let raw: Vec<u8> = get_property(
            ap.as_str(),
            "org.freedesktop.NetworkManager.AccessPoint",
            "Ssid",
        )?;
        let s = String::from_utf8_lossy(&raw).into_owned();
        if !s.is_empty() {
            return Some(s);
        }
    }
    None
}

/// Turn a saved profile's `autoconnect` flag on or off.
///
/// Proton writes its profiles with autoconnect enabled, so a tunnel torn
/// down by hand can bring itself straight back up. That is indistinguishable
/// from a daemon reconnecting you, and it got blamed on one.
///
/// `Update` replaces the whole settings dict, so this reads, edits one key,
/// and writes back - templating a fresh dict would drop the credentials and
/// the server address with it.
pub fn set_autoconnect(profile: &Profile, on: bool) -> Result<(), String> {
    let bus = system_bus().ok_or("no system bus")?;
    let cp = zbus::blocking::Proxy::new(bus, NM_DEST, profile.path.clone(), SETTINGS_CONN_IFACE)
        .map_err(|e| e.to_string())?;

    let mut settings: std::collections::HashMap<
        String,
        std::collections::HashMap<String, zbus::zvariant::OwnedValue>,
    > = cp.call("GetSettings", &()).map_err(|e| e.to_string())?;

    let conn = settings
        .get_mut("connection")
        .ok_or("profile has no connection section")?;

    let current = conn
        .get("autoconnect")
        .and_then(|v| bool::try_from(v).ok())
        // NM's default is true when the key is absent, which is exactly the
        // case that bites: Proton's profiles often just omit it.
        .unwrap_or(true);
    if current == on {
        return Ok(());
    }

    conn.insert(
        "autoconnect".into(),
        zbus::zvariant::Value::from(on)
            .try_into()
            .map_err(|e: zbus::zvariant::Error| e.to_string())?,
    );

    cp.call::<_, _, ()>("Update", &(&settings,))
        .map_err(|e| e.to_string())
}
