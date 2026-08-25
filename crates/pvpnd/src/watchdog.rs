//! systemd watchdog, spoken directly rather than through libsystemd.
//!
//! WHY
//!
//! `Restart=always` only helps if the process *dies*. The failure this
//! guards is worse than a crash: the daemon is alive, systemd is satisfied,
//! and nothing is happening. A `pvpn up` that never returns does exactly
//! that — the health loop stops, signals queue, and the tunnel stays broken
//! indefinitely while `systemctl status` says `active (running)`.
//!
//! The protocol is a single datagram to `$NOTIFY_SOCKET`, so implementing
//! it is a dozen lines and adds no dependency:
//!
//!   - `READY=1`      once, at startup
//!   - `WATCHDOG=1`   at least every `WATCHDOG_USEC/2`
//!   - `STATUS=...`   optional, shown by `systemctl status`
//!
//! A leading `@` in the socket path means the abstract namespace, encoded
//! as a leading NUL byte. Getting that wrong is a silent no-op rather than
//! an error, which is why it is handled explicitly below.

use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;
use std::time::Duration;

pub struct Watchdog {
    sock: Option<UnixDatagram>,
    addr: Option<PathBuf>,
    /// How often we must ping. `None` when systemd did not ask for a
    /// watchdog, in which case pinging is harmless but pointless.
    interval: Option<Duration>,
}

impl Watchdog {
    /// Read the environment systemd set for us.
    ///
    /// Everything here degrades to "no watchdog" rather than failing: the
    /// daemon must run identically when started by hand from a shell, where
    /// none of these variables exist.
    pub fn from_env() -> Self {
        Self::from_parts(
            std::env::var("NOTIFY_SOCKET").ok(),
            std::env::var("WATCHDOG_USEC").ok().and_then(|v| v.parse().ok()),
        )
    }

    /// The same logic, with the environment passed in.
    ///
    /// Split out so it can be tested without setting process-global env
    /// vars — three tests doing that in parallel raced each other, which
    /// made the suite fail intermittently and for a reason that had
    /// nothing to do with the code under test.
    pub fn from_parts(notify_socket: Option<String>, watchdog_usec: Option<u64>) -> Self {
        let addr = notify_socket.map(|s| {
            if let Some(rest) = s.strip_prefix('@') {
                // Abstract namespace: the leading NUL is the encoding, not
                // a typo.
                PathBuf::from(format!("\0{rest}"))
            } else {
                PathBuf::from(s)
            }
        });

        let interval = watchdog_usec
            .filter(|us| *us > 0)
            // Ping at a third of the deadline, not a half. A half leaves no
            // room for a tick that runs slightly long, and a missed ping is
            // a SIGABRT.
            .map(|us| Duration::from_micros(us / 3));

        let sock = if addr.is_some() {
            UnixDatagram::unbound().ok()
        } else {
            None
        };

        Self {
            sock,
            addr,
            interval,
        }
    }

    /// How often `ping` must be called, if systemd is watching.
    pub fn interval(&self) -> Option<Duration> {
        self.interval
    }

    pub fn is_active(&self) -> bool {
        self.interval.is_some() && self.sock.is_some()
    }

    fn send(&self, msg: &str) {
        let (Some(sock), Some(addr)) = (&self.sock, &self.addr) else {
            return;
        };
        // Failure is ignored on purpose. A daemon that dies because it
        // could not tell systemd it was alive has inverted the point of
        // the exercise.
        let _ = sock.send_to(msg.as_bytes(), addr);
    }

    pub fn ready(&self) {
        self.send("READY=1");
    }

    pub fn ping(&self) {
        if self.interval.is_some() {
            self.send("WATCHDOG=1");
        }
    }

    /// One line shown by `systemctl status`.
    pub fn status(&self, text: &str) {
        self.send(&format!("STATUS={text}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Started from a shell there is no NOTIFY_SOCKET, and everything must
    /// still work — silently.
    #[test]
    fn absent_environment_yields_an_inert_watchdog() {
        let w = Watchdog::from_parts(None, None);
        assert!(!w.is_active());
        assert_eq!(w.interval(), None);
        // Must not panic.
        w.ready();
        w.ping();
        w.status("test");
    }

    /// A leading '@' is the abstract namespace and encodes as a NUL. Get
    /// this wrong and every notification silently goes nowhere.
    #[test]
    fn abstract_sockets_are_nul_prefixed() {
        let w = Watchdog::from_parts(Some("@/org/freedesktop/systemd1/notify".into()), None);
        let addr = w.addr.as_ref().unwrap().to_string_lossy().into_owned();
        assert!(addr.starts_with('\0'), "abstract socket must start with NUL");
    }

    #[test]
    fn ordinary_socket_paths_are_untouched() {
        let w = Watchdog::from_parts(Some("/run/user/1000/systemd/notify".into()), None);
        assert_eq!(
            w.addr.as_ref().unwrap().to_string_lossy(),
            "/run/user/1000/systemd/notify"
        );
    }

    /// Pinging at half the deadline leaves no slack for a tick that runs
    /// long, and a missed ping is a SIGABRT. A third does.
    #[test]
    fn ping_interval_leaves_slack() {
        let w = Watchdog::from_parts(Some("/run/nowhere".into()), Some(300_000_000));
        let iv = w.interval().unwrap();
        assert_eq!(iv, Duration::from_secs(100));
        assert!(iv < Duration::from_secs(150), "must be under half the deadline");
    }

    #[test]
    fn zero_watchdog_usec_means_disabled() {
        let w = Watchdog::from_parts(Some("/run/nowhere".into()), Some(0));
        assert_eq!(w.interval(), None);
        assert!(!w.is_active());
    }

    /// A watchdog deadline with no socket to answer on is not active, and
    /// pinging it must be a no-op rather than a panic.
    #[test]
    fn watchdog_without_a_socket_is_inert() {
        let w = Watchdog::from_parts(None, Some(300_000_000));
        assert!(!w.is_active());
        w.ping();
    }
}
