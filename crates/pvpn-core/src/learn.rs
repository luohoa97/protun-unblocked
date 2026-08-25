//! What this network taught us.
//!
//! The two minutes you spend finding a server that works on a hostile
//! network should not be spent again tomorrow. So every measurement and
//! every connect outcome is written down, per network.
//!
//! WHY OUTCOMES AND NOT JUST LATENCY
//!
//! Ranking by handshake time alone is the obvious design and it is wrong
//! here, because the failure this tool exists for does not show up in a
//! handshake. Some filters terminate TLS on a local proxy: the handshake
//! completes fast — *faster* than the real server, because the proxy is one
//! hop away — and then the session is closed before any tunnel data moves.
//! Rank on that number and the filter's own proxy wins every time.
//!
//! So a server carries two independent things: how quickly it answers, and
//! whether connecting to it has actually worked *here*. Latency orders the
//! candidates; outcomes decide who is allowed in the list at all, and
//! penalise anything that has lied before.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{intent::now_secs, net, paths};

/// What we know about one server on one network.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerRecord {
    /// Measured TLS handshake time. `None` means never measured.
    pub latency_ms: Option<u64>,
    /// The handshake completed but the peer looked like an interceptor
    /// rather than the server we asked for. Fast and useless.
    pub intercepted: bool,
    /// Connects that produced a tunnel carrying traffic.
    pub ok: u32,
    /// Connects that did not.
    pub failed: u32,
    /// When this server was last put on the blocked list.
    pub blocked_at: Option<u64>,
    /// Consecutive block events, which lengthen the next block.
    pub block_strikes: u32,
    /// Why it was blocked, in words, for `pvpn blocked`.
    pub last_error: Option<String>,
    /// Best observed time from "activate" to "connected", in ms.
    ///
    /// THE number that actually predicts what a connect will cost you here,
    /// and it is not the handshake latency. On a filtered network protun
    /// retries a refused entry IP on a fixed 3-second backoff; one server
    /// was observed taking FIVE attempts and 22 seconds, while its TLS
    /// handshake time looked ordinary. Handshake latency cannot see that.
    /// This can, because it is the wall clock the user waited.
    ///
    /// Best rather than last, because a single bad round on a flaky network
    /// should not condemn a server that usually connects immediately.
    pub connect_ms: Option<u64>,
    /// Last time we touched this record at all.
    pub last_seen: u64,
}

impl ServerRecord {
    /// How long this server stays blocked, given how often it has failed.
    ///
    /// Doubling per strike, capped at 4x the base. Uncapped growth would
    /// permanently exile a server that had a bad afternoon, and this list
    /// is per-network — the same server may be perfect tomorrow on the same
    /// wifi once a filter rule changes.
    pub fn block_duration_secs(&self, base_hours: u64) -> u64 {
        let mult = 1u64 << self.block_strikes.min(2); // 1, 2, 4
        base_hours.saturating_mul(3600).saturating_mul(mult)
    }

    pub fn is_blocked(&self, base_hours: u64, now: u64) -> bool {
        match self.blocked_at {
            None => false,
            Some(at) => now.saturating_sub(at) < self.block_duration_secs(base_hours),
        }
    }

    /// Seconds until this server is retried, or `None` if it is not blocked.
    pub fn unblocks_in(&self, base_hours: u64, now: u64) -> Option<u64> {
        let at = self.blocked_at?;
        let dur = self.block_duration_secs(base_hours);
        let elapsed = now.saturating_sub(at);
        (elapsed < dur).then(|| dur - elapsed)
    }

    pub fn attempts(&self) -> u32 {
        self.ok + self.failed
    }

    /// Fraction of connects that worked. `None` when never tried, which is
    /// deliberately different from 0.0 — "unknown" and "always fails" must
    /// not rank the same.
    pub fn success_rate(&self) -> Option<f64> {
        (self.attempts() > 0).then(|| self.ok as f64 / self.attempts() as f64)
    }

    /// The number servers are ordered by. Lower is better.
    ///
    /// Latency is the base, then:
    ///
    ///   - Interception is disqualifying-ish: a huge penalty rather than
    ///     exclusion, so that on a network where *everything* is
    ///     intercepted there is still an ordering and `pvpn up` has
    ///     something to try.
    ///   - Failures multiply. A server that failed half its connects here
    ///     is treated as twice as slow, which is what actually matters:
    ///     expected time until you have a working tunnel, not time to a
    ///     handshake.
    ///   - Never-measured servers sort last but are not excluded.
    pub fn score(&self) -> f64 {
        // Time-to-connected wins outright when we have it, because it is
        // the only measurement that includes protun's retry loop. A server
        // whose handshake is quick but which takes five attempts to accept
        // a tunnel costs the user 22 seconds, and no handshake timing shows
        // that.
        let base = match (self.connect_ms, self.latency_ms) {
            (Some(ms), _) => ms as f64,
            // No connect on record: fall back to handshake latency, scaled
            // so the two are roughly comparable. A handshake is a few
            // hundred ms; a connect is a few seconds.
            (None, Some(ms)) => ms as f64 * 4.0,
            // Never measured at all: worse than any plausible measurement,
            // but finite, so it still ranks above a known-bad server.
            (None, None) => 40_000.0,
        };
        let intercept_penalty = if self.intercepted { 5_000.0 } else { 0.0 };
        let failure_multiplier = match self.success_rate() {
            // Never tried here. No evidence either way, so no adjustment.
            None => 1.0,
            // 1.0 at perfect, 3.0 at never-works.
            Some(rate) => 1.0 + 2.0 * (1.0 - rate),
        };
        base * failure_multiplier + intercept_penalty
    }
}

/// Everything learned about one network.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkMemory {
    /// The network this describes, for sanity when reading the file.
    pub network: String,
    /// Server name -> what we know. BTreeMap so the file is stable on disk
    /// and diffs are readable.
    pub servers: BTreeMap<String, ServerRecord>,
    pub updated: u64,
}

impl NetworkMemory {
    pub fn path_for(network: &str) -> std::path::PathBuf {
        paths::data_dir()
            .join("networks")
            .join(format!("{}.json", net::sanitise(network)))
    }

    /// Load what we know about the network we are on right now.
    pub fn load_current() -> Self {
        Self::load(&net::network_id())
    }

    pub fn load(network: &str) -> Self {
        let path = Self::path_for(network);
        match std::fs::read_to_string(&path) {
            Ok(text) => match serde_json::from_str::<Self>(&text) {
                Ok(m) => m,
                Err(e) => {
                    // A corrupt memory file must not stop you connecting.
                    // Starting over costs one slow connect; refusing to run
                    // costs you the tool.
                    tracing::warn!(path = %path.display(), error = %e,
                        "network memory is unreadable; starting fresh");
                    Self {
                        network: network.to_string(),
                        ..Default::default()
                    }
                }
            },
            Err(_) => Self {
                network: network.to_string(),
                ..Default::default()
            },
        }
    }

    pub fn save(&mut self) -> std::io::Result<()> {
        self.updated = now_secs();
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        paths::write_atomic(&Self::path_for(&self.network), &format!("{json}\n"))
    }

    fn entry(&mut self, server: &str) -> &mut ServerRecord {
        let rec = self.servers.entry(server.to_string()).or_default();
        rec.last_seen = now_secs();
        rec
    }

    /// Record a latency measurement.
    pub fn record_latency(&mut self, server: &str, ms: u64, intercepted: bool) {
        let rec = self.entry(server);
        rec.latency_ms = Some(ms);
        rec.intercepted = intercepted;
    }

    /// Record how long a successful connect actually took.
    pub fn record_connect_time(&mut self, server: &str, ms: u64) {
        let rec = self.entry(server);
        rec.connect_ms = Some(match rec.connect_ms {
            Some(best) => best.min(ms),
            None => ms,
        });
    }

    /// Record that connecting to this server produced a working tunnel.
    ///
    /// Success clears the block outright, and resets the strike count. A
    /// server that works is not on probation for what it did last week —
    /// keeping strikes would mean one good connect still left it one
    /// failure away from a 4x block.
    pub fn record_success(&mut self, server: &str) {
        let rec = self.entry(server);
        rec.ok += 1;
        rec.blocked_at = None;
        rec.block_strikes = 0;
        rec.last_error = None;
    }

    /// Record that connecting failed, and why.
    pub fn record_failure(&mut self, server: &str, why: impl Into<String>) {
        let rec = self.entry(server);
        rec.failed += 1;
        rec.blocked_at = Some(now_secs());
        rec.block_strikes = rec.block_strikes.saturating_add(1);
        rec.last_error = Some(why.into());
    }

    /// Servers worth trying, best first.
    ///
    /// `candidates` is the list Proton says exists; this filters and orders
    /// it. Blocked servers are dropped unless that would leave nothing, in
    /// which case the least-bad blocked server is returned rather than an
    /// empty list — being offline is worse than trying something that
    /// failed yesterday.
    pub fn rank(&self, candidates: &[String], base_hours: u64) -> Vec<String> {
        let now = now_secs();
        let mut usable: Vec<&String> = candidates
            .iter()
            .filter(|s| {
                self.servers
                    .get(*s)
                    .map(|r| !r.is_blocked(base_hours, now))
                    .unwrap_or(true)
            })
            .collect();

        if usable.is_empty() {
            tracing::warn!(
                "every candidate is blocked on this network; trying the least-bad anyway"
            );
            usable = candidates.iter().collect();
        }

        let score_of = |s: &String| {
            self.servers
                .get(s)
                .map(|r| r.score())
                // Unknown server: same treatment as unmeasured.
                .unwrap_or(10_000.0)
        };
        usable.sort_by(|a, b| {
            score_of(a)
                .partial_cmp(&score_of(b))
                // Scores are finite by construction, but a NaN here would
                // silently scramble the order rather than panicking, so
                // fall back to name order for determinism.
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.cmp(b))
        });
        usable.into_iter().cloned().collect()
    }

    /// Servers this network handled well, best first.
    pub fn fast(&self, base_hours: u64) -> Vec<(&String, &ServerRecord)> {
        let now = now_secs();
        let mut v: Vec<_> = self
            .servers
            .iter()
            .filter(|(_, r)| !r.is_blocked(base_hours, now) && r.latency_ms.is_some())
            .collect();
        v.sort_by(|(an, a), (bn, b)| {
            a.score()
                .partial_cmp(&b.score())
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| an.cmp(bn))
        });
        v
    }

    /// Servers currently blocked, and why.
    pub fn blocked(&self, base_hours: u64) -> Vec<(&String, &ServerRecord)> {
        let now = now_secs();
        let mut v: Vec<_> = self
            .servers
            .iter()
            .filter(|(_, r)| r.is_blocked(base_hours, now))
            .collect();
        v.sort_by_key(|(n, _)| n.as_str());
        v
    }

    /// Drop records nothing has touched in a long time.
    ///
    /// Without this the file grows forever on a laptop that visits many
    /// networks, and stale latency from six months ago is worse than no
    /// latency at all.
    pub fn prune(&mut self, max_age_days: u64) -> usize {
        let cutoff = now_secs().saturating_sub(max_age_days * 86_400);
        let before = self.servers.len();
        self.servers.retain(|_, r| r.last_seen >= cutoff);
        before - self.servers.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(latency: Option<u64>, ok: u32, failed: u32) -> ServerRecord {
        ServerRecord {
            latency_ms: latency,
            ok,
            failed,
            ..Default::default()
        }
    }

    /// THE point of this module. A transparent proxy answers faster than
    /// the real server — it is one hop away — so ranking on latency alone
    /// puts the filter's own interceptor first.
    #[test]
    fn a_fast_interceptor_loses_to_a_slower_real_server() {
        let mut fast_liar = rec(Some(20), 0, 0);
        fast_liar.intercepted = true;
        let honest = rec(Some(200), 0, 0);
        assert!(
            fast_liar.score() > honest.score(),
            "a 20ms interceptor must not outrank a 200ms real server"
        );
    }

    /// THE finding from the NetworkManager journal: a server whose TLS
    /// handshake is quick can still take five attempts and 22 seconds to
    /// accept a tunnel, because protun retries a refused entry IP on a
    /// fixed 3s backoff. Measured connect time must beat handshake latency
    /// whenever we have it, or ranking keeps choosing the slow one.
    #[test]
    fn measured_connect_time_beats_a_fast_handshake() {
        let mut quick_handshake_slow_connect = rec(Some(50), 5, 0);
        quick_handshake_slow_connect.connect_ms = Some(22_000);

        let mut slower_handshake_fast_connect = rec(Some(300), 5, 0);
        slower_handshake_fast_connect.connect_ms = Some(3_000);

        assert!(
            slower_handshake_fast_connect.score() < quick_handshake_slow_connect.score(),
            "the server that actually connects in 3s must win"
        );
    }

    /// Best, not last: one bad round on a flaky network must not condemn a
    /// server that usually connects immediately.
    #[test]
    fn connect_time_keeps_the_best_observation() {
        let mut m = NetworkMemory::default();
        m.record_connect_time("A", 12_000);
        m.record_connect_time("A", 2_500);
        m.record_connect_time("A", 9_000);
        assert_eq!(m.servers["A"].connect_ms, Some(2_500));
    }

    /// Expected time to a *working tunnel* is the thing being ordered, not
    /// time to a handshake.
    #[test]
    fn a_server_that_keeps_failing_ranks_below_a_slower_reliable_one() {
        let flaky = rec(Some(50), 1, 9); // fast, works 10% of the time
        let solid = rec(Some(120), 10, 0); // slower, always works
        assert!(flaky.score() > solid.score());
    }

    /// "Never tried" and "always fails" must not rank the same. Treating an
    /// unknown server as a failure would stop us ever discovering a good
    /// one on a new network.
    #[test]
    fn untried_is_not_the_same_as_failing() {
        let untried = rec(Some(100), 0, 0);
        let always_fails = rec(Some(100), 0, 5);
        assert!(untried.score() < always_fails.score());
        assert_eq!(untried.success_rate(), None);
        assert_eq!(always_fails.success_rate(), Some(0.0));
    }

    #[test]
    fn blocks_expire_and_lengthen_with_repeat_failures() {
        let now = now_secs();
        let mut r = ServerRecord::default();

        r.blocked_at = Some(now);
        r.block_strikes = 1;
        assert_eq!(r.block_duration_secs(24), 24 * 3600 * 2);

        r.block_strikes = 2;
        assert_eq!(r.block_duration_secs(24), 24 * 3600 * 4);

        // Capped: a bad afternoon must not exile a server forever.
        r.block_strikes = 99;
        assert_eq!(r.block_duration_secs(24), 24 * 3600 * 4);

        // And it does expire.
        r.block_strikes = 1;
        r.blocked_at = Some(now.saturating_sub(24 * 3600 * 2 + 1));
        assert!(!r.is_blocked(24, now));
    }

    #[test]
    fn success_clears_the_block_and_the_strikes() {
        let mut m = NetworkMemory::default();
        m.record_failure("SG#1", "timeout");
        m.record_failure("SG#1", "timeout");
        assert!(m.servers["SG#1"].is_blocked(24, now_secs()));
        assert_eq!(m.servers["SG#1"].block_strikes, 2);

        m.record_success("SG#1");
        let r = &m.servers["SG#1"];
        assert!(!r.is_blocked(24, now_secs()));
        assert_eq!(r.block_strikes, 0, "a working server is not on probation");
        assert!(r.last_error.is_none());
    }

    #[test]
    fn ranking_excludes_blocked_servers() {
        let mut m = NetworkMemory::default();
        m.record_latency("A", 10, false);
        m.record_latency("B", 50, false);
        m.record_failure("A", "refused");

        let order = m.rank(&["A".into(), "B".into()], 24);
        assert_eq!(order, vec!["B".to_string()], "A is blocked");
    }

    /// Being offline is worse than trying something that failed yesterday.
    #[test]
    fn ranking_never_returns_nothing() {
        let mut m = NetworkMemory::default();
        m.record_failure("A", "x");
        m.record_failure("B", "x");
        let order = m.rank(&["A".into(), "B".into()], 24);
        assert_eq!(order.len(), 2, "must fall back rather than strand the user");
    }

    #[test]
    fn ranking_is_deterministic_for_equal_scores() {
        let m = NetworkMemory::default();
        let c: Vec<String> = vec!["Z".into(), "A".into(), "M".into()];
        assert_eq!(m.rank(&c, 24), m.rank(&c, 24));
        // Unknown servers all score the same, so name order breaks the tie.
        assert_eq!(m.rank(&c, 24), vec!["A", "M", "Z"]);
    }

    #[test]
    fn pruning_drops_only_stale_records() {
        let mut m = NetworkMemory::default();
        m.record_latency("old", 10, false);
        m.record_latency("new", 10, false);
        m.servers.get_mut("old").unwrap().last_seen = now_secs() - 400 * 86_400;

        assert_eq!(m.prune(90), 1);
        assert!(m.servers.contains_key("new"));
        assert!(!m.servers.contains_key("old"));
    }

    #[test]
    fn memory_round_trips_through_json() {
        let mut m = NetworkMemory {
            network: "home-abc123".into(),
            ..Default::default()
        };
        m.record_latency("SG#1", 42, false);
        m.record_success("SG#1");
        let text = serde_json::to_string(&m).unwrap();
        let back: NetworkMemory = serde_json::from_str(&text).unwrap();
        assert_eq!(back.network, "home-abc123");
        assert_eq!(back.servers["SG#1"].latency_ms, Some(42));
        assert_eq!(back.servers["SG#1"].ok, 1);
    }

    /// An older file has fewer fields. It must still load, or an upgrade
    /// throws away everything the user's networks taught them.
    #[test]
    fn older_memory_files_still_load() {
        let old = r#"{"network":"x","servers":{"A":{"latency_ms":10}},"updated":1}"#;
        let m: NetworkMemory = serde_json::from_str(old).unwrap();
        assert_eq!(m.servers["A"].latency_ms, Some(10));
        assert_eq!(m.servers["A"].ok, 0);
    }
}
