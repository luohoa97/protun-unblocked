//! The daemon's published view of the world.
//!
//! Written by `pvpnd`, read by `pvpn status` and the GUI. It lives in the
//! runtime directory so it cannot survive a reboot claiming a tunnel is up.
//!
//! This was hand-rolled JSON in three places before, which is exactly how
//! two readers end up disagreeing about a field name. One struct now, and
//! serde does the rest.

use serde::{Deserialize, Serialize};

use crate::{intent::now_secs, paths, Intent};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonState {
    /// NetworkManager has an active vpn/wireguard profile.
    pub connected: bool,
    /// Traffic actually passed on the last probe. This and `connected`
    /// disagreeing is the interesting case, and the reason this daemon
    /// exists: protun keeps a tunnel "activated" while carrying nothing.
    pub traffic: bool,
    /// What the user last asked for.
    pub intent: String,
    /// Human-readable summary of the last decision.
    pub note: String,
    /// Seconds since the epoch.
    pub updated: u64,
    /// Which probe target answered, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
    /// Round-trip of the successful probe, in milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<u64>,
    /// Consecutive failed health checks.
    #[serde(default)]
    pub strikes: u64,
    /// Reconnect attempts since the daemon started.
    #[serde(default)]
    pub reconnects: u64,
}

impl DaemonState {
    pub fn new(connected: bool, traffic: bool, intent: Intent, note: impl Into<String>) -> Self {
        Self {
            connected,
            traffic,
            intent: intent.as_str().to_string(),
            note: note.into(),
            updated: now_secs(),
            via: None,
            rtt_ms: None,
            strikes: 0,
            reconnects: 0,
        }
    }

    /// Read what the daemon last published.
    ///
    /// `None` covers both "no daemon" and "unreadable state", which the
    /// caller must present as "unknown" rather than as "not connected" —
    /// they are different, and conflating them is how a status command
    /// starts lying.
    pub fn load() -> Option<Self> {
        let text = std::fs::read_to_string(paths::state_file()).ok()?;
        serde_json::from_str(&text).ok()
    }

    pub fn save(&self) -> std::io::Result<()> {
        let json = serde_json::to_string(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        paths::write_atomic(&paths::state_file(), &format!("{json}\n"))
    }

    /// How long ago this was written. Used to decide whether a daemon is
    /// actually alive, rather than trusting a file it left behind.
    pub fn age_secs(&self) -> u64 {
        now_secs().saturating_sub(self.updated)
    }

    /// Is this state recent enough to believe?
    ///
    /// A state file whose daemon died is worse than no state file: it keeps
    /// asserting whatever was true when the process stopped.
    pub fn is_fresh(&self, watch_interval: u64) -> bool {
        // Three ticks of slack. One tick is too tight — a probe that takes
        // its full timeout legitimately delays the next write.
        self.age_secs() <= watch_interval.saturating_mul(3).max(30)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_json() {
        let s = DaemonState::new(true, true, Intent::Up, "healthy");
        let text = serde_json::to_string(&s).unwrap();
        let back: DaemonState = serde_json::from_str(&text).unwrap();
        assert!(back.connected);
        assert_eq!(back.intent, "up");
        assert_eq!(back.note, "healthy");
    }

    /// The GUI and `pvpn status` parse this. Renaming a field silently
    /// breaks them, so the wire names are pinned here.
    #[test]
    fn wire_field_names_are_stable() {
        let s = DaemonState::new(false, false, Intent::Down, "idle");
        let text = serde_json::to_string(&s).unwrap();
        for field in ["connected", "traffic", "intent", "note", "updated"] {
            assert!(text.contains(&format!("\"{field}\"")), "missing {field}");
        }
    }

    /// Old state files predate the newer fields. They must still load, or
    /// an upgrade makes `pvpn status` fail until the daemon rewrites.
    #[test]
    fn older_state_files_still_load() {
        let old = r#"{"connected":false,"traffic":false,"intent":"down","note":"idle","updated":1}"#;
        let s: DaemonState = serde_json::from_str(old).unwrap();
        assert_eq!(s.intent, "down");
        assert_eq!(s.strikes, 0);
        assert!(s.via.is_none());
    }

    /// A daemon that died leaves its last claim behind. Believing it is how
    /// a status command starts lying.
    #[test]
    fn stale_state_is_not_fresh() {
        let mut s = DaemonState::new(true, true, Intent::Up, "healthy");
        s.updated = now_secs().saturating_sub(3600);
        assert!(!s.is_fresh(20));

        let fresh = DaemonState::new(true, true, Intent::Up, "healthy");
        assert!(fresh.is_fresh(20));
    }
}
