//! Settings, read from whichever of the two formats is present.
//!
//! There are two because this project is mid-port. The shell front-end
//! reads and writes `~/.config/pvpn/config` as plain `KEY=value`, and it
//! will keep doing so until the last of it is gone. The Rust side prefers
//! `~/.config/pvpn/config.toml`.
//!
//! Both are supported rather than one being migrated, because a migration
//! that runs while the old front-end is still installed loses settings for
//! anyone who has both. When both files exist, TOML wins and the legacy
//! file is left untouched - so downgrading still works.
//!
//! Environment variables override both, for one-off tuning without editing
//! a file.

use serde::{Deserialize, Serialize};

use crate::paths;

/// Everything tunable, with the defaults that were measured rather than
/// guessed. The comment on each is why it is that number.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Connect down a measured ranking instead of Proton's server-side
    /// `Score`. From Sydney, Proton's top pick answers in 260ms while a
    /// server it never suggests answers in 99ms.
    pub auto_best_server: bool,

    /// Seconds to wait for a tunnel to come up at all.
    pub connect_timeout_secs: u64,

    /// Grace period for traffic to start AFTER the tunnel is up, and the
    /// most important number here. Time-to-first-packet has been measured
    /// at 12s, >20s and >45s on hostile networks. Every tunnel written off
    /// as dead turned out to be alive moments later, and discarding one
    /// costs a full reconnect that often lands on the same server. Running
    /// out of this does NOT tear the tunnel down.
    pub settle_secs: u64,

    /// How long a server stays on the blocked list before it is retried.
    pub blocked_retry_after_hours: u64,

    /// Optional country filter for ranking, e.g. "JP".
    pub country: Option<String>,

    /// Put Flatpak apps back on the tunnel when a proxy override has taken
    /// them off it.
    pub fix_apps: bool,

    // --- daemon ---
    /// Seconds between health checks.
    pub watch_interval: u64,

    /// Seconds a single traffic probe may take.
    pub probe_timeout: u64,

    /// Consecutive dead probes before acting. Not 1: a single failed probe
    /// is normal on flaky wifi, and reconnecting on it would tear down
    /// working tunnels constantly.
    pub strikes: u64,

    /// Whether the daemon repairs a broken tunnel at all. Turning this off
    /// leaves it observing and reporting, which is useful when you are
    /// debugging the network itself.
    pub autoreconnect: bool,

    /// Confirm traffic actually flows before calling a connect a success.
    ///
    /// ON by default. Without it, "connected" means only that
    /// NetworkManager brought a tunnel up - which is exactly the state this
    /// whole project exists to catch, because protun keeps a tunnel
    /// "activated" while carrying nothing. Crediting a server for that
    /// teaches the ranking the wrong thing.
    pub verify: bool,

    /// Seconds to wait for first traffic before calling a connect
    /// unproven.
    ///
    /// NOT settle_secs. That is 90 and governs when to give up on a tunnel
    /// entirely; running out of it never tears one down. This is the much
    /// shorter window for deciding whether to CREDIT the server, so a
    /// connect does not sit for a minute and a half before returning.
    pub verify_secs: u64,

    /// How many proven servers this network needs before `pvpn up` stops
    /// measuring and just uses what it learned.
    ///
    /// Three is enough to have a first choice and two fallbacks. Set it
    /// higher to keep measuring for longer, or to 0 to always trust the
    /// memory once it has anything at all.
    pub trust_after_servers: u64,

    /// Seconds before a reconnect attempt is killed. A hung `pvpn up` with
    /// no limit wedges the daemon indefinitely, and systemd cannot tell
    /// because the process is still alive.
    pub reconnect_timeout: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            auto_best_server: true,
            connect_timeout_secs: 30,
            settle_secs: 90,
            blocked_retry_after_hours: 24,
            country: None,
            fix_apps: true,
            watch_interval: 20,
            probe_timeout: 5,
            strikes: 3,
            autoreconnect: true,
            reconnect_timeout: 120,
            trust_after_servers: 3,
            verify: true,
            verify_secs: 20,
        }
    }
}

impl Config {
    /// Load from TOML if present, else the legacy `KEY=value` file, then
    /// apply environment overrides.
    ///
    /// Never fails: an unreadable or malformed config yields defaults plus
    /// a warning, because refusing to start leaves you with no VPN tooling
    /// at all over a typo.
    pub fn load() -> Self {
        let mut cfg = Self::from_toml().unwrap_or_else(|| Self::from_legacy());
        cfg.apply_env();
        cfg.clamp();
        cfg
    }

    fn from_toml() -> Option<Self> {
        let path = paths::config_dir().join("config.toml");
        let text = std::fs::read_to_string(&path).ok()?;
        match toml::from_str::<Self>(&text) {
            Ok(c) => Some(c),
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "config.toml is malformed; using defaults");
                Some(Self::default())
            }
        }
    }

    /// The shell front-end's format: `KEY=value`, `#` comments, optional
    /// quotes. Parsed by hand rather than with a pattern, so an unexpected
    /// line is skipped instead of matched loosely.
    fn from_legacy() -> Self {
        let mut cfg = Self::default();
        let path = paths::config_file();
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(_) => return cfg,
        };
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((k, v)) = line.split_once('=') else {
                continue;
            };
            let (k, v) = (k.trim(), v.trim().trim_matches('"'));
            cfg.set_legacy(k, v);
        }
        cfg
    }

    fn set_legacy(&mut self, key: &str, value: &str) {
        match key {
            "auto_best_server" => self.auto_best_server = truthy(value, self.auto_best_server),
            "connect_timeout_secs" => num(value, &mut self.connect_timeout_secs),
            "settle_secs" => num(value, &mut self.settle_secs),
            "blocked_retry_after_hours" => num(value, &mut self.blocked_retry_after_hours),
            "country" => {
                if !value.is_empty() {
                    self.country = Some(value.to_string())
                }
            }
            "fix_apps" => self.fix_apps = truthy(value, self.fix_apps),
            "watch_interval" => num(value, &mut self.watch_interval),
            "probe_timeout" => num(value, &mut self.probe_timeout),
            "strikes" => num(value, &mut self.strikes),
            "autoreconnect" => self.autoreconnect = truthy(value, self.autoreconnect),
            "reconnect_timeout" => num(value, &mut self.reconnect_timeout),
            "trust_after_servers" => num(value, &mut self.trust_after_servers),
            "verify" => self.verify = truthy(value, self.verify),
            "verify_secs" => num(value, &mut self.verify_secs),
            // Unknown keys are ignored, not rejected. Old installs carry
            // settings from removed features, and refusing to load over one
            // of them would be a worse failure than ignoring it.
            _ => {}
        }
    }

    fn apply_env(&mut self) {
        if let Ok(v) = std::env::var("PVPN_BEST") {
            self.auto_best_server = truthy(&v, self.auto_best_server);
        }
        if let Ok(v) = std::env::var("PVPN_TIMEOUT") {
            num(&v, &mut self.connect_timeout_secs);
        }
        if let Ok(v) = std::env::var("PVPN_SETTLE") {
            num(&v, &mut self.settle_secs);
        }
        if let Ok(v) = std::env::var("PVPN_BEST_COUNTRY") {
            if !v.is_empty() {
                self.country = Some(v);
            }
        }
        if let Ok(v) = std::env::var("PVPN_VERIFY") {
            self.verify = truthy(&v, self.verify);
        }
        if let Ok(v) = std::env::var("PVPN_FIX_APPS") {
            self.fix_apps = truthy(&v, self.fix_apps);
        }
    }

    /// Keep every value inside a range where the program still behaves.
    ///
    /// A `watch_interval` of 0 would spin a core; a `probe_timeout` of 600
    /// would stall the daemon for ten minutes per tick. Clamping rather
    /// than rejecting means a bad number degrades to a usable one.
    fn clamp(&mut self) {
        self.watch_interval = self.watch_interval.clamp(5, 600);
        self.probe_timeout = self.probe_timeout.clamp(1, 30);
        self.strikes = self.strikes.clamp(1, 20);
        self.reconnect_timeout = self.reconnect_timeout.clamp(30, 900);
        self.trust_after_servers = self.trust_after_servers.min(20);
        self.verify_secs = self.verify_secs.clamp(3, 120);
        self.connect_timeout_secs = self.connect_timeout_secs.clamp(5, 600);
        self.settle_secs = self.settle_secs.clamp(0, 600);
    }
}

fn truthy(v: &str, default: bool) -> bool {
    match v.trim().to_ascii_lowercase().as_str() {
        "1" | "on" | "yes" | "true" => true,
        "0" | "off" | "no" | "false" => false,
        _ => default,
    }
}

fn num(v: &str, slot: &mut u64) {
    if let Ok(n) = v.trim().parse() {
        *slot = n;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_keys_parse() {
        let mut c = Config::default();
        c.set_legacy("watch_interval", "45");
        c.set_legacy("autoreconnect", "off");
        c.set_legacy("country", "JP");
        assert_eq!(c.watch_interval, 45);
        assert!(!c.autoreconnect);
        assert_eq!(c.country.as_deref(), Some("JP"));
    }

    /// An old install carries keys from features that no longer exist.
    /// Refusing to load over one of them would strand the user with no
    /// working config at all.
    #[test]
    fn unknown_legacy_keys_are_ignored_not_fatal() {
        let mut c = Config::default();
        let before = c.watch_interval;
        c.set_legacy("some_removed_feature", "whatever");
        assert_eq!(c.watch_interval, before);
    }

    /// Garbage must not silently become 0 - a zero interval would spin a
    /// core. The previous value survives instead.
    #[test]
    fn malformed_numbers_keep_the_previous_value() {
        let mut c = Config::default();
        c.set_legacy("watch_interval", "not-a-number");
        assert_eq!(c.watch_interval, Config::default().watch_interval);
    }

    #[test]
    fn clamping_keeps_the_daemon_out_of_pathological_settings() {
        let mut c = Config {
            watch_interval: 0,
            probe_timeout: 9999,
            strikes: 0,
            reconnect_timeout: 1,
            ..Config::default()
        };
        c.clamp();
        assert_eq!(c.watch_interval, 5);
        assert_eq!(c.probe_timeout, 30);
        assert_eq!(c.strikes, 1);
        assert_eq!(c.reconnect_timeout, 30);
    }

    #[test]
    fn toml_round_trips() {
        let c = Config::default();
        let text = toml::to_string(&c).unwrap();
        let back: Config = toml::from_str(&text).unwrap();
        assert_eq!(back.watch_interval, c.watch_interval);
        assert_eq!(back.settle_secs, c.settle_secs);
    }
}
