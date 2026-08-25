//! Is traffic ACTUALLY passing?
//!
//! This is the question the whole daemon turns on, and getting it wrong in
//! either direction is expensive:
//!
//!   - A false "dead" tears down a working tunnel and reconnects, which on
//!     a hostile network can cost two minutes and often lands on the same
//!     server.
//!   - A false "alive" leaves you exposed, believing you are tunnelled
//!     while every packet leaves in the clear.
//!
//! Deliberately raw sockets rather than shelling out to curl: this runs
//! every few seconds forever, and spawning a process each time is the kind
//! of thing that makes a daemon unwelcome.
//!
//! IPv4 only, and no proxy: a tunnel can advertise IPv6 DNS while
//! installing no IPv6 route, and honouring `$HTTPS_PROXY` would measure the
//! proxy rather than the tunnel.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

/// Where to probe.
///
/// More than one target on purpose. The previous version probed a single
/// host, which made every reachability decision depend on that host being
/// up and unblocked — on a network that filters, which is the entire
/// premise of this tool, that is a single point of failure that produces
/// false "dead" verdicts and reconnect storms.
///
/// The first two are IP literals so they need no DNS. A resolver with no
/// route behind it blocks for seconds per attempt with no timeout we can
/// set from here, and that stall shows up as the daemon going unresponsive.
/// The hostname target is kept last because resolving it is itself
/// meaningful evidence — but it is never the only evidence.
const TARGETS: &[Target] = &[
    Target::Ip(Ipv4Addr::new(1, 1, 1, 1), 80, "cloudflare"),
    Target::Ip(Ipv4Addr::new(8, 8, 8, 8), 80, "google-dns"),
    Target::Host("connectivitycheck.gstatic.com", 80, "gstatic"),
];

enum Target {
    Ip(Ipv4Addr, u16, &'static str),
    Host(&'static str, u16, &'static str),
}

impl Target {
    fn label(&self) -> &'static str {
        match self {
            Target::Ip(_, _, l) | Target::Host(_, _, l) => l,
        }
    }

    fn host_header(&self) -> String {
        match self {
            Target::Ip(ip, _, _) => ip.to_string(),
            Target::Host(h, _, _) => (*h).to_string(),
        }
    }

    /// Resolve to a v4 socket address. IP literals skip the resolver
    /// entirely, which is the point of having them.
    fn resolve(&self, _timeout: Duration) -> Option<SocketAddr> {
        match self {
            Target::Ip(ip, port, _) => Some(SocketAddr::new(IpAddr::V4(*ip), *port)),
            Target::Host(host, port, _) => (*host, *port)
                .to_socket_addrs()
                .ok()?
                .find(|a| a.is_ipv4()),
        }
    }
}

/// The verdict, with enough detail to log something useful.
#[derive(Debug, Clone)]
pub struct Verdict {
    pub alive: bool,
    /// Which target answered, if any.
    pub via: Option<&'static str>,
    /// How long the successful probe took, for ranking and for spotting a
    /// tunnel that works but is unusably slow.
    pub rtt: Option<Duration>,
    /// Targets that were tried and did not answer.
    pub failed: Vec<&'static str>,
}

/// Probe until something answers.
///
/// ANY target answering means traffic flows — that is the claim being
/// tested, and one working path proves it. Requiring all of them would make
/// the check strictly more fragile than the thing it is checking.
pub fn traffic_flows(timeout: Duration) -> Verdict {
    let mut failed = Vec::new();
    for target in TARGETS {
        let started = Instant::now();
        match probe_one(target, timeout) {
            true => {
                return Verdict {
                    alive: true,
                    via: Some(target.label()),
                    rtt: Some(started.elapsed()),
                    failed,
                }
            }
            false => failed.push(target.label()),
        }
    }
    Verdict {
        alive: false,
        via: None,
        rtt: None,
        failed,
    }
}

/// One target: connect, send a minimal HTTP request, require an HTTP reply.
///
/// The HTTP round trip matters. A bare TCP connect succeeding is not proof
/// of anything on a filtered network — a captive portal or a transparent
/// proxy will happily accept the connection and then serve you its own
/// page. Requiring bytes that begin with `HTTP/` is a weak check, but it is
/// strictly stronger than a connect, and it costs one round trip.
fn probe_one(target: &Target, timeout: Duration) -> bool {
    let Some(addr) = target.resolve(timeout) else {
        return false;
    };
    let Ok(mut sock) = TcpStream::connect_timeout(&addr, timeout) else {
        return false;
    };
    let _ = sock.set_read_timeout(Some(timeout));
    let _ = sock.set_write_timeout(Some(timeout));

    let req = format!(
        "GET /generate_204 HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        target.host_header()
    );
    if sock.write_all(req.as_bytes()).is_err() {
        return false;
    }
    let mut buf = [0u8; 16];
    match sock.read(&mut buf) {
        Ok(n) if n > 0 => buf.starts_with(b"HTTP/"),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every target must be distinctly labelled, because the labels end up
    /// in the journal and an ambiguous one makes a failure report useless.
    #[test]
    fn targets_are_distinctly_labelled() {
        let mut seen = std::collections::HashSet::new();
        for t in TARGETS {
            assert!(seen.insert(t.label()), "duplicate label {}", t.label());
        }
        assert!(TARGETS.len() >= 2, "a single target is a single point of failure");
    }

    /// At least one target must need no DNS. A resolver with no route
    /// behind it blocks for seconds with no timeout settable from here, and
    /// that stall is indistinguishable from the daemon hanging.
    #[test]
    fn at_least_one_target_avoids_dns() {
        assert!(TARGETS.iter().any(|t| matches!(t, Target::Ip(..))));
    }

    /// IP literals must resolve without touching the resolver, and must do
    /// it instantly.
    #[test]
    fn ip_targets_resolve_offline() {
        let t = Target::Ip(Ipv4Addr::new(1, 1, 1, 1), 80, "x");
        let started = Instant::now();
        let addr = t.resolve(Duration::from_secs(1)).unwrap();
        assert!(started.elapsed() < Duration::from_millis(50));
        assert_eq!(addr.port(), 80);
        assert!(addr.is_ipv4());
    }

    #[test]
    fn host_header_matches_the_target() {
        assert_eq!(
            Target::Ip(Ipv4Addr::new(1, 1, 1, 1), 80, "x").host_header(),
            "1.1.1.1"
        );
        assert_eq!(Target::Host("example.com", 80, "x").host_header(), "example.com");
    }
}
