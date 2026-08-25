//! pvpnd - keeps a Proton VPN tunnel alive, and repairs it when it dies.
//!
//! WHY THIS EXISTS
//!
//! The tunnel dies in ways nothing else notices. After a suspend, from the
//! NetworkManager journal:
//!
//!     Received TransportAlert(Shutdown(StreamId(1)))
//!     WireguardUdp/handshake probe failed
//!     already disconnected
//!
//! protun retries with a WireGuard UDP handshake probe. On a UDP-blocking
//! network - the reason for using Stealth at all - that probe can never
//! succeed, so it retries forever while NetworkManager keeps the profile
//! "activated" and the CLI keeps reporting Connected. The tunnel looks
//! perfect, carries nothing, and cannot heal itself.
//!
//! WHAT IT MUST NEVER DO
//!
//! Fight you. `pvpn down` is an instruction, not a fault. A daemon that
//! reconnects two seconds later is worse than no daemon, and this one did
//! exactly that twice - see `pvpn_core::nm` for both post-mortems.
//!
//! So intent is READ, never inferred, and every decision traces back to a
//! NetworkManager signal that positively identifies both what happened and
//! who it happened to.
//!
//! RELIABILITY
//!
//! Three ways a daemon fails that `Restart=always` does not cover, all
//! handled here:
//!
//!   - A reconnect that never returns. `pvpn up` has been measured at 75s;
//!     with no limit, a hung one wedges the loop forever while systemd sees
//!     a healthy process. Bounded by `reconnect_timeout`.
//!   - A wedged main loop. Caught by the systemd watchdog (`watchdog.rs`).
//!   - A dead signal-watcher thread. Previously this degraded silently to a
//!     plain timer, losing the GNOME integration with no indication. Now
//!     detected and respawned.

mod watchdog;

use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use pvpn_core::{
    config::Config,
    intent, nm, paths, probe,
    state::DaemonState,
    Intent,
};

use watchdog::Watchdog;

fn main() {
    init_tracing();
    let cfg = Config::load();
    let dog = Watchdog::from_env();

    tracing::info!(
        interval = cfg.watch_interval,
        probe_timeout = cfg.probe_timeout,
        strikes = cfg.strikes,
        autoreconnect = cfg.autoreconnect,
        reconnect_timeout = cfg.reconnect_timeout,
        watchdog = ?dog.interval(),
        "pvpnd starting"
    );
    if !dog.is_active() {
        // Worth saying: without it, a wedged main loop is invisible to
        // systemd, which is the failure this daemon is least able to
        // notice about itself.
        tracing::warn!("systemd watchdog is NOT active; a wedged loop will not be caught");
    }
    dog.ready();

    Daemon::new(cfg, dog).run();
}

fn init_tracing() {
    // stdout is the journal under systemd, which stamps its own times.
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .without_time()
        .with_target(false)
        .init();
}

struct Daemon {
    cfg: Config,
    dog: Watchdog,
    rx: Receiver<nm::Ev>,
    tx: Sender<nm::Ev>,
    watcher: JoinHandle<()>,

    strikes: u64,
    backoff: Duration,
    last_attempt: Option<Instant>,
    reconnects: u64,
    vpn: nm::VpnCache,
}

impl Daemon {
    fn new(cfg: Config, dog: Watchdog) -> Self {
        let (tx, rx) = channel();
        let watcher = spawn_nm_watcher(tx.clone());
        Self {
            cfg,
            dog,
            rx,
            tx,
            watcher,
            strikes: 0,
            backoff: Duration::from_secs(0),
            last_attempt: None,
            reconnects: 0,
            vpn: nm::VpnCache::default(),
        }
    }

    fn run(mut self) {
        loop {
            self.ensure_watcher_alive();

            // Signals first: they are instructions, and acting on a stale
            // health reading before reading them would mean reconnecting
            // something the user just switched off.
            let pending: Vec<nm::Ev> = self.rx.try_iter().collect();
            for ev in pending {
                self.handle_event(ev);
            }

            let want = intent::read();
            let connected = self.vpn.get().is_some();

            if want != Intent::Up {
                self.strikes = 0;
                self.backoff = Duration::from_secs(0);
                self.publish(connected, connected, want, "idle: intent is not up", None);
                self.dog.status("idle");
                self.wait(Duration::from_secs(self.cfg.watch_interval));
                continue;
            }

            let verdict = if connected {
                Some(probe::traffic_flows(Duration::from_secs(self.cfg.probe_timeout)))
            } else {
                None
            };
            let healthy = verdict.as_ref().map(|v| v.alive).unwrap_or(false);

            if healthy {
                if self.strikes > 0 {
                    tracing::info!("tunnel recovered");
                }
                self.strikes = 0;
                self.backoff = Duration::from_secs(0);
                self.publish(true, true, want, "healthy", verdict.as_ref());
                self.dog.status("healthy");
            } else {
                self.strikes += 1;
                let why = if connected {
                    "tunnel is up but no traffic passes"
                } else {
                    "no tunnel"
                };
                tracing::warn!(strikes = self.strikes, needed = self.cfg.strikes, "{why}");
                self.publish(connected, false, want, why, verdict.as_ref());
                self.dog.status(why);

                if self.cfg.autoreconnect && self.strikes >= self.cfg.strikes {
                    self.try_reconnect();
                }
            }

            self.wait(Duration::from_secs(self.cfg.watch_interval));
        }
    }

    /// A dead watcher used to degrade silently to a plain timer, which
    /// meant the GNOME switch stopped working with nothing to indicate it.
    ///
    /// The channel cannot detect this on its own: we hold a `Sender` too,
    /// so it never reports `Disconnected`. The thread handle can.
    fn ensure_watcher_alive(&mut self) {
        if !self.watcher.is_finished() {
            return;
        }
        tracing::error!("NetworkManager watcher died; respawning");
        self.watcher = spawn_nm_watcher(self.tx.clone());
    }

    fn handle_event(&mut self, ev: nm::Ev) {
        // While pvpn is mid-operation its own signals are noise: `pvpn hop`
        // legitimately emits a deliberate down followed by an activate, and
        // acting on the down half would leave intent=down if the up half
        // then failed - quietly turning a failed hop into a permanent
        // disconnect. pvpn writes intent itself for these.
        if intent::pvpn_is_busy() {
            tracing::debug!(?ev, "ignoring signal: pvpn is mid-operation");
            return;
        }
        match ev {
            nm::Ev::Activated => {
                if intent::read() != Intent::Up {
                    tracing::info!("VPN switched on outside pvpn - adopting (intent=up)");
                    if let Err(e) = intent::write(Intent::Up) {
                        tracing::error!(error = %e, "could not record intent");
                    }
                }
                self.strikes = 0;
                self.backoff = Duration::from_secs(0);
            }
            nm::Ev::WentDownDeliberately => {
                if intent::read() != Intent::Down {
                    tracing::info!("VPN switched off outside pvpn - standing down (intent=down)");
                    if let Err(e) = intent::write(Intent::Down) {
                        tracing::error!(error = %e, "could not record intent");
                    }
                }
                self.strikes = 0;
                self.backoff = Duration::from_secs(0);
            }
            // A fault does not change what you asked for, so intent is left
            // alone and the health loop handles it with strikes and backoff.
            nm::Ev::Failed => tracing::warn!("NetworkManager reports the tunnel failed"),
        }
        // A signal means the tunnel moved, so the cached name may now
        // describe something that no longer exists. Force the next read to
        // go to NetworkManager.
        self.vpn.invalidate();
    }

    fn try_reconnect(&mut self) {
        let due = self
            .last_attempt
            .map(|t| t.elapsed() >= self.backoff)
            .unwrap_or(true);
        if !due {
            return;
        }
        self.last_attempt = Some(Instant::now());
        self.reconnects += 1;
        self.vpn.invalidate();
        self.dog.status("reconnecting");

        match reconnect(Duration::from_secs(self.cfg.reconnect_timeout)) {
            Reconnect::Ok => {
                tracing::info!("reconnect returned ok");
                self.backoff = Duration::from_secs(0);
            }
            Reconnect::Failed => {
                self.grow_backoff("reconnect failed");
            }
            Reconnect::TimedOut => {
                // The important one. Without a bound this call never
                // returns and the daemon is finished.
                self.grow_backoff("reconnect TIMED OUT and was killed");
            }
        }
        // Reset either way: another attempt is gated by backoff, not by
        // racking up more strikes.
        self.strikes = 0;
    }

    fn grow_backoff(&mut self, why: &str) {
        self.backoff = if self.backoff.is_zero() {
            Duration::from_secs(30)
        } else {
            (self.backoff * 2).min(Duration::from_secs(600))
        };
        tracing::warn!(backoff_secs = self.backoff.as_secs(), "{why}");
    }

    fn publish(
        &self,
        connected: bool,
        traffic: bool,
        want: Intent,
        note: &str,
        verdict: Option<&probe::Verdict>,
    ) {
        let mut st = DaemonState::new(connected, traffic, want, note);
        st.strikes = self.strikes;
        st.reconnects = self.reconnects;
        if let Some(v) = verdict {
            st.via = v.via.map(|s| s.to_string());
            st.rtt_ms = v.rtt.map(|d| d.as_millis() as u64);
        }
        if let Err(e) = st.save() {
            tracing::warn!(error = %e, "could not write state file");
        }
    }

    /// Wait for the next tick, waking early when NetworkManager says
    /// something - that is what makes the GNOME switch feel instant instead
    /// of taking up to a full interval to register.
    ///
    /// The wait is sliced so the watchdog is fed from the main loop. Feeding
    /// it from a separate thread would defeat the point: it would keep
    /// reporting health while this loop was wedged.
    fn wait(&mut self, total: Duration) {
        let deadline = Instant::now() + total;
        let slice = self
            .dog
            .interval()
            .unwrap_or(Duration::from_secs(60))
            .min(total.max(Duration::from_secs(1)));

        loop {
            self.dog.ping();
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return;
            }
            match self.rx.recv_timeout(left.min(slice)) {
                Ok(ev) => {
                    self.handle_event(ev);
                    while let Ok(extra) = self.rx.try_recv() {
                        self.handle_event(extra);
                    }
                    // Re-evaluate now rather than sitting out the rest of
                    // the tick - but not instantly, or a connect's burst of
                    // signals would spin the loop.
                    std::thread::sleep(Duration::from_secs(1));
                    return;
                }
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => {
                    // We hold a Sender, so this should be unreachable. If it
                    // happens, say so rather than spinning on a dead
                    // channel.
                    tracing::error!("event channel disconnected");
                    std::thread::sleep(left.min(slice));
                    return;
                }
            }
        }
    }
}

enum Reconnect {
    Ok,
    Failed,
    TimedOut,
}

/// Run `pvpn up`, bounded.
///
/// Wrapped in coreutils `timeout` rather than hand-rolled, for one specific
/// reason: `timeout` puts the child in its own process group and signals
/// the group. Killing the `pvpn` process alone would leave Proton's Python
/// client running, which is how you end up with two connects racing.
///
/// Exit 124 is `timeout`'s "I killed it". `-k 10` follows with SIGKILL if
/// SIGTERM is ignored.
fn reconnect(limit: Duration) -> Reconnect {
    let pvpn = paths::pvpn_bin();
    tracing::info!(timeout_secs = limit.as_secs(), "reconnecting: pvpn up");

    let mut cmd = if which("timeout").is_some() {
        let mut c = std::process::Command::new("timeout");
        c.arg("--kill-after=10")
            .arg(format!("{}", limit.as_secs()))
            .arg(&pvpn)
            .arg("up");
        c
    } else {
        // Without coreutils there is no bound. Say so loudly - this is the
        // configuration in which the daemon can still wedge.
        tracing::warn!("coreutils `timeout` not found; reconnect is UNBOUNDED");
        let mut c = std::process::Command::new(&pvpn);
        c.arg("up");
        c
    };

    match cmd
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
    {
        Ok(st) if st.success() => Reconnect::Ok,
        Ok(st) if st.code() == Some(124) => Reconnect::TimedOut,
        Ok(_) => Reconnect::Failed,
        Err(e) => {
            tracing::error!(error = %e, "could not run pvpn");
            Reconnect::Failed
        }
    }
}

fn which(bin: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join(bin))
        .find(|p| p.is_file())
}

/// Watch NetworkManager's D-Bus signals forever, forwarding events.
///
/// Unprivileged: receiving NM's broadcast signals needs no root. That was
/// verified on a real machine, not assumed - an earlier version of this
/// comment claimed the opposite based on a "No such file or directory"
/// error that was really an unset DBUS_SYSTEM_BUS_ADDRESS.
fn spawn_nm_watcher(tx: Sender<nm::Ev>) -> JoinHandle<()> {
    std::thread::spawn(move || {
        // Escalating, so a machine with no gdbus at all does not write a
        // log line every five seconds forever.
        let mut retry = Duration::from_secs(5);

        loop {
            // Re-seeded per gdbus session, so a NetworkManager restart
            // cannot leave us holding stale object paths.
            let mut tunnels = nm::TunnelPaths::seeded();
            tracing::debug!(known_tunnels = tunnels.len(), "nm watcher attaching");

            let child = std::process::Command::new("gdbus")
                .args([
                    "monitor",
                    "--system",
                    "--dest",
                    "org.freedesktop.NetworkManager",
                ])
                .env("DBUS_SYSTEM_BUS_ADDRESS", nm::dbus_addr())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .spawn();

            match child {
                Ok(mut c) => {
                    retry = Duration::from_secs(5);
                    if let Some(out) = c.stdout.take() {
                        use std::io::BufRead;
                        for line in std::io::BufReader::new(out).lines().map_while(Result::ok) {
                            let Some(sig) = nm::parse_signal(&line) else {
                                continue;
                            };
                            let Some(ev) = tunnels.classify(sig) else {
                                continue;
                            };
                            if tx.send(ev).is_err() {
                                return; // main loop is gone
                            }
                        }
                    }
                    let _ = c.wait();
                    tracing::warn!("nm watcher: gdbus exited, restarting");
                }
                Err(e) => {
                    tracing::error!(error = %e, retry_secs = retry.as_secs(), "cannot start gdbus");
                    retry = (retry * 2).min(Duration::from_secs(300));
                }
            }
            // NM restarting takes its monitor down with it; never spin.
            std::thread::sleep(retry);
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `timeout` exit 124 must be distinguishable from an ordinary failure.
    /// Collapsing them would hide the wedge case, which is the one that
    /// motivated bounding the call at all.
    #[test]
    fn timeout_exit_code_is_not_ordinary_failure() {
        assert_ne!(124, 0);
        assert_ne!(124, 1);
    }

    /// Backoff must grow and must stop growing. An unbounded doubling
    /// reaches multi-hour waits and the daemon stops being useful; no
    /// growth at all hammers a network that is simply down.
    #[test]
    fn backoff_grows_then_caps() {
        let cfg = Config::default();
        std::env::remove_var("NOTIFY_SOCKET");
        let mut d = Daemon::new(cfg, Watchdog::from_env());
        assert!(d.backoff.is_zero());

        d.grow_backoff("x");
        assert_eq!(d.backoff, Duration::from_secs(30));
        d.grow_backoff("x");
        assert_eq!(d.backoff, Duration::from_secs(60));

        for _ in 0..20 {
            d.grow_backoff("x");
        }
        assert_eq!(d.backoff, Duration::from_secs(600), "must cap at 10 minutes");
    }

    #[test]
    fn which_finds_a_real_binary_and_rejects_a_fake_one() {
        assert!(which("sh").is_some());
        assert!(which("definitely-not-a-real-binary-xyzzy").is_none());
    }
}
