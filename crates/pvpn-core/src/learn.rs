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

/// Estimated cost of a connect to a server we have measured but never
/// actually connected to, in milliseconds.
///
/// Sits between a good measured connect (~3s) and a bad one (~20s) on
/// purpose: a server proven fast should beat an unknown, and a server
/// proven slow should lose to trying an unknown.
const UNMEASURED_CONNECT_MS: f64 = 5_000.0;

/// Estimated cost for a server we know nothing about at all.
const UNKNOWN_CONNECT_MS: f64 = 15_000.0;

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
    /// Connects where the tunnel came up but traffic was never confirmed.
    ///
    /// Deliberately NOT counted as a failure on the first occurrence. Time
    /// to first packet has been measured at 12s, >20s and >45s on hostile
    /// networks, and every tunnel written off as dead turned out to be
    /// alive shortly after. So one unverified connect means "unproven", not
    /// "broken" - but a server that is repeatedly unprovable is not one to
    /// keep choosing.
    pub unverified: u32,

    /// Best observed time from "activate" to VERIFIED, in ms.
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
        // Everything below is an ESTIMATE OF CONNECT TIME IN MILLISECONDS.
        //
        // Getting that unit wrong is not cosmetic. The first version used
        // `latency * 4` as the fallback, which put unmeasured servers on a
        // completely different scale: a 10ms handshake scored 40, while a
        // server PROVEN to connect reliably in 2 seconds scored 2000. Every
        // unmeasured server therefore outranked every proven one, forever,
        // and the memory could never influence anything.
        let base = match (self.connect_ms, self.latency_ms) {
            // Measured. The real thing, no estimate needed.
            (Some(ms), _) => ms as f64,

            // Never connected here, but measured. Estimate: the floor a
            // good connect costs on these networks, plus a latency term.
            // Deliberately ABOVE a good measured connect (~3s) and BELOW a
            // bad one (~20s), so a proven-fast server wins and a
            // proven-slow one loses to trying something new.
            (None, Some(ms)) => UNMEASURED_CONNECT_MS + ms as f64 * 2.0,

            // Nothing known at all: worse than any plausible estimate, but
            // finite, so it still ranks above a known-bad server.
            (None, None) => UNKNOWN_CONNECT_MS,
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
    /// The last server that verifiably carried traffic here.
    ///
    /// Kept separately from the ranking because it answers a different
    /// question. Ranking asks "which server is best in general on this
    /// network". After a drop the better question is "which one was working
    /// thirty seconds ago" - that is the strongest evidence available, and
    /// it is about to be thrown away by a fresh ranking pass.
    pub last_good: Option<String>,
    pub updated: u64,
}

/// What OTHER sites on the same SSID have learned about a server.
///
/// WHY THIS EXISTS
///
/// A network id is `<ssid>-<hash(ssid|gateway-mac)>`, so it identifies a
/// SITE: this SSID, behind this gateway. That is right for latency, which
/// depends on where you physically are.
///
/// It is wrong for the blocked list. Blocking is a POLICY, and policy is
/// set for an organisation, not a gateway. `detnsw` is a whole state
/// education department: every school runs the same filter rules, but each
/// building has its own gateway. Keyed by site alone, walking to another
/// block throws away every blocked verdict and re-learns each one by
/// failing on it again - 22 seconds a time, and a scan to go with it.
///
/// Keying policy purely by SSID would fix that and break something else:
/// "eduroam" is thousands of unrelated networks, and pooling their verdicts
/// would have one university's filter condemn servers at another.
///
/// So a sibling site's experience is treated as EVIDENCE, not as a verdict.
/// A server the rest of this SSID refuses starts at a disadvantage and is
/// tried later - but it is never excluded, so a genuinely different network
/// sharing a name can still prove it works.
#[derive(Debug, Clone, Default)]
pub struct RealmPrior {
    /// Sites on this SSID where the server is currently blocked.
    pub refused_at: u32,
    /// Sites on this SSID where it has connected successfully.
    pub worked_at: u32,
}

impl RealmPrior {
    /// Multiplier applied to a server's score. 1.0 is no opinion.
    ///
    /// Deliberately bounded. Sibling evidence is weaker than our own - it
    /// came from a different gateway, possibly a different building - so it
    /// can nudge the ordering and must never dominate it.
    pub fn weight(&self) -> f64 {
        if self.refused_at == 0 && self.worked_at == 0 {
            return 1.0;
        }
        let total = (self.refused_at + self.worked_at) as f64;
        let refused = self.refused_at as f64 / total;
        // 0.8 when every sibling site connects fine, 1.6 when they all
        // refuse. Enough to reorder a list, not enough to bury a server our
        // own site has proven.
        0.8 + 0.8 * refused
    }
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

    /// The tunnel came up but nothing came through it in the time allowed.
    ///
    /// Blocks only on the second occurrence, for the reason on `unverified`:
    /// one slow settle is normal here, two is a pattern.
    pub fn record_unverified(&mut self, server: &str) -> bool {
        let rec = self.entry(server);
        rec.unverified = rec.unverified.saturating_add(1);
        if rec.unverified >= 2 {
            rec.failed += 1;
            rec.blocked_at = Some(now_secs());
            rec.block_strikes = rec.block_strikes.saturating_add(1);
            rec.last_error = Some("tunnel came up but never carried traffic".into());
            true
        } else {
            false
        }
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
        // A proven connect clears the doubt too, not just the block.
        rec.unverified = 0;
        self.last_good = Some(server.to_string());
    }

    /// Record that connecting failed, and why.
    pub fn record_failure(&mut self, server: &str, why: impl Into<String>) {
        let rec = self.entry(server);
        rec.failed += 1;
        rec.blocked_at = Some(now_secs());
        rec.block_strikes = rec.block_strikes.saturating_add(1);
        rec.last_error = Some(why.into());
    }

    /// Gather what other sites on the same SSID have learned.
    ///
    /// Sites share a filename prefix (`<ssid>-<hash>.json`), which is the
    /// whole reason the readable prefix is in the id at all.
    pub fn realm_priors(ssid: &str, this_network: &str, base_hours: u64)
        -> BTreeMap<String, RealmPrior>
    {
        let mut priors: BTreeMap<String, RealmPrior> = BTreeMap::new();
        let dir = paths::data_dir().join("networks");
        let Ok(entries) = std::fs::read_dir(&dir) else {
            return priors;
        };
        let prefix = format!("{}-", net::sanitise(ssid));
        let now = now_secs();

        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.starts_with(&prefix) || !name.ends_with(".json") {
                continue;
            }
            let network = name.trim_end_matches(".json");
            // Our own site is not a prior; it is the evidence itself.
            if network == net::sanitise(this_network) {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(entry.path()) else {
                continue;
            };
            let Ok(other) = serde_json::from_str::<Self>(&text) else {
                continue;
            };
            for (server, rec) in &other.servers {
                let p = priors.entry(server.clone()).or_default();
                if rec.is_blocked(base_hours, now) {
                    p.refused_at += 1;
                } else if rec.ok > 0 {
                    p.worked_at += 1;
                }
            }
        }
        priors
    }

    /// Servers worth trying, best first.
    ///
    /// `candidates` is the list Proton says exists; this filters and orders
    /// it. Blocked servers are dropped unless that would leave nothing, in
    /// which case the least-bad blocked server is returned rather than an
    /// empty list — being offline is worse than trying something that
    /// failed yesterday.
    pub fn rank(&self, candidates: &[String], base_hours: u64) -> Vec<String> {
        self.rank_with(candidates, base_hours, &BTreeMap::new())
    }

    /// `rank`, weighted by what sibling sites on this SSID have learned.
    pub fn rank_with(
        &self,
        candidates: &[String],
        base_hours: u64,
        priors: &BTreeMap<String, RealmPrior>,
    ) -> Vec<String> {
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
            let base = self
                .servers
                .get(s)
                .map(|r| r.score())
                // Unknown server: same treatment as unmeasured.
                .unwrap_or(10_000.0);
            base * priors.get(s).map(RealmPrior::weight).unwrap_or(1.0)
        };
        // Stable sort, and NO name tie-break.
        //
        // Sorting equal scores by name looked harmlessly deterministic and
        // was not: with an empty memory every server scores the same, so
        // the list came out alphabetical and `pvpn up` connected to
        // CA-FREE#... every time. That is where "it picks a random CA
        // server" came from - it was not random, it was the alphabet.
        //
        // `candidates` arrives already ordered by the scanner's measured
        // TLS latency. Rust's sort_by is stable, so leaving ties alone
        // preserves that order, which is exactly the right fallback: when
        // we know nothing extra, trust the measurement we just took.
        usable.sort_by(|a, b| {
            score_of(a)
                .partial_cmp(&score_of(b))
                // Scores are finite by construction; a NaN must not scramble
                // the order, so treat it as a tie and keep input order.
                .unwrap_or(std::cmp::Ordering::Equal)
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

    /// Servers with enough evidence to choose between without measuring.
    ///
    /// Once a network has taught us which servers actually connect, another
    /// scan adds nothing and costs a great deal. A scan is ~140 TLS
    /// handshakes into one provider's address space in a few seconds, from
    /// one client - by far the most distinctive thing this tool puts on the
    /// wire, and far more distinctive than the tunnel, which is a single
    /// long-lived TLS session on 443.
    ///
    /// Wanting that burst to be rare is not paranoia; it is the difference
    /// between an entry IP staying usable and getting blocklisted for
    /// everyone who shares it.
    pub fn confident_choices(&self, base_hours: u64) -> Vec<String> {
        let now = now_secs();
        let mut usable: Vec<(&String, &ServerRecord)> = self
            .servers
            .iter()
            .filter(|(_, r)| {
                // Evidence means a connect that WORKED here. Handshake
                // latency is not enough: it cannot see the retry loop that
                // makes a server cost 22 seconds.
                r.ok > 0 && r.connect_ms.is_some() && !r.is_blocked(base_hours, now)
            })
            .collect();
        usable.sort_by(|(an, a), (bn, b)| {
            a.score()
                .partial_cmp(&b.score())
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| an.cmp(bn))
        });
        usable.into_iter().map(|(n, _)| n.clone()).collect()
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

    /// With nothing learned, every server scores the same - and the order
    /// that survives must be the SCANNER'S, which is measured latency.
    ///
    /// Sorting ties by name instead made `pvpn up` pick CA-FREE#... every
    /// single time on a fresh network, because C sorts early. That was
    /// reported as "it connects to a random CA server"; it was not random.
    #[test]
    fn equal_scores_keep_the_scanners_order() {
        let m = NetworkMemory::default();
        let scanner_order: Vec<String> =
            vec!["SG-FREE#20".into(), "JP-FREE#3".into(), "CA-FREE#7".into()];
        assert_eq!(
            m.rank(&scanner_order, 24),
            scanner_order,
            "an empty memory must not reorder a measured list"
        );
        // Still deterministic, just not alphabetical.
        assert_eq!(m.rank(&scanner_order, 24), m.rank(&scanner_order, 24));
    }

    /// ...but real evidence still overrides the scanner's order.
    #[test]
    fn evidence_beats_scanner_order() {
        let mut m = NetworkMemory::default();
        let scanner_order: Vec<String> = vec!["untried-quick".into(), "proven".into()];
        m.record_latency("untried-quick", 10, false);
        m.record_latency("proven", 400, false);
        m.record_success("proven");
        m.record_connect_time("proven", 2_000);

        assert_eq!(
            m.rank(&scanner_order, 24)[0],
            "proven",
            "a server proven to connect in 2s must beat an untried one"
        );
    }

    /// The units must match, or the memory can never influence anything.
    ///
    /// The first scoring used `latency * 4` for unmeasured servers, mixing
    /// handshake milliseconds with full-connect milliseconds: a 10ms
    /// handshake scored 40 against 2000 for a server proven to connect in
    /// two seconds. Every unmeasured server outranked every proven one.
    #[test]
    fn measured_and_estimated_scores_share_a_scale() {
        let mut proven_fast = ServerRecord::default();
        proven_fast.connect_ms = Some(3_000);
        proven_fast.ok = 3;

        let mut proven_slow = ServerRecord::default();
        proven_slow.connect_ms = Some(20_000);
        proven_slow.ok = 3;

        let mut untried = ServerRecord::default();
        untried.latency_ms = Some(100);

        assert!(
            proven_fast.score() < untried.score(),
            "a proven-fast server must beat an untried one"
        );
        assert!(
            untried.score() < proven_slow.score(),
            "an untried server must beat one proven to take 20 seconds"
        );
    }

    /// Only servers that have actually connected here count as evidence.
    /// A handshake measurement is not enough to skip a scan, because it
    /// cannot see the retry loop that makes a connect cost 22 seconds.
    #[test]
    fn confidence_requires_a_working_connect_not_just_a_handshake() {
        let mut m = NetworkMemory::default();

        // Measured, never connected: not evidence.
        m.record_latency("measured-only", 50, false);

        // Connected, but we did not time it: not evidence either.
        m.record_success("no-timing");

        // The real thing.
        m.record_latency("proven", 300, false);
        m.record_success("proven");
        m.record_connect_time("proven", 3_000);

        assert_eq!(m.confident_choices(24), vec!["proven".to_string()]);
    }

    /// A blocked server is not a choice, however good its history.
    #[test]
    fn confidence_excludes_blocked_servers() {
        let mut m = NetworkMemory::default();
        m.record_success("A");
        m.record_connect_time("A", 2_000);
        assert_eq!(m.confident_choices(24).len(), 1);
        m.record_failure("A", "refused");
        assert!(m.confident_choices(24).is_empty());
    }

    /// Sibling evidence must reorder, never overrule. A server the rest of
    /// the SSID refuses should be tried LATER - but if this site has proven
    /// it works, it must still be reachable, or an "eduroam" name collision
    /// would let one network condemn servers on an unrelated one.
    #[test]
    fn sibling_evidence_reorders_but_does_not_exclude() {
        let mut m = NetworkMemory::default();
        m.record_latency("A", 100, false);
        m.record_latency("B", 100, false);

        let mut priors = BTreeMap::new();
        priors.insert(
            "A".to_string(),
            RealmPrior {
                refused_at: 3,
                worked_at: 0,
            },
        );
        priors.insert(
            "B".to_string(),
            RealmPrior {
                refused_at: 0,
                worked_at: 3,
            },
        );

        let order = m.rank_with(&["A".into(), "B".into()], 24, &priors);
        assert_eq!(order[0], "B", "the server siblings trust goes first");
        assert_eq!(order.len(), 2, "the other one is still offered");
    }

    /// The weight is bounded on purpose: sibling evidence came from a
    /// different gateway and is weaker than our own. It must be able to
    /// nudge an ordering, not bury a server this site has proven.
    #[test]
    fn sibling_weight_is_bounded() {
        let none = RealmPrior::default();
        assert_eq!(none.weight(), 1.0, "no evidence means no opinion");

        let all_bad = RealmPrior { refused_at: 99, worked_at: 0 };
        let all_good = RealmPrior { refused_at: 0, worked_at: 99 };
        assert!((all_bad.weight() - 1.6).abs() < 1e-9);
        assert!((all_good.weight() - 0.8).abs() < 1e-9);

        // Our own proven fast connect must still beat a slow server that
        // siblings happen to like.
        let mut proven_here = ServerRecord::default();
        proven_here.connect_ms = Some(3_000);
        proven_here.ok = 5;
        let mut slow = ServerRecord::default();
        slow.connect_ms = Some(20_000);
        slow.ok = 5;
        assert!(proven_here.score() * all_bad.weight() < slow.score() * all_good.weight());
    }

    /// One unverified connect is not evidence of a broken server - a slow
    /// settle is normal on these networks. Two is a pattern.
    #[test]
    fn unverified_blocks_only_on_the_second_occurrence() {
        let mut m = NetworkMemory::default();
        assert!(!m.record_unverified("A"), "first must not block");
        assert!(!m.servers["A"].is_blocked(24, now_secs()));

        assert!(m.record_unverified("A"), "second must block");
        assert!(m.servers["A"].is_blocked(24, now_secs()));
        assert!(m.servers["A"]
            .last_error
            .as_deref()
            .unwrap()
            .contains("never carried traffic"));
    }

    /// A server that later proves itself is fully rehabilitated - the doubt
    /// clears with the block, or one bad afternoon would leave it one
    /// wobble away from being blocked again forever.
    #[test]
    fn a_verified_connect_clears_previous_doubt() {
        let mut m = NetworkMemory::default();
        m.record_unverified("A");
        assert_eq!(m.servers["A"].unverified, 1);

        m.record_success("A");
        assert_eq!(m.servers["A"].unverified, 0);
        assert!(!m.servers["A"].is_blocked(24, now_secs()));
    }

    /// After a drop, the server that was working is the strongest evidence
    /// there is. Losing it means a reconnect re-ranks from scratch and can
    /// land somewhere the filter kills.
    #[test]
    fn a_verified_connect_is_remembered_as_last_good() {
        let mut m = NetworkMemory::default();
        assert_eq!(m.last_good, None);
        m.record_success("SG-FREE#20");
        assert_eq!(m.last_good.as_deref(), Some("SG-FREE#20"));

        // An unverified connect must NOT overwrite it - that is the whole
        // point of verifying.
        m.record_unverified("JP-FREE#3");
        assert_eq!(m.last_good.as_deref(), Some("SG-FREE#20"));
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
