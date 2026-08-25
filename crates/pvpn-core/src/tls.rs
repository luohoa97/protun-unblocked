//! Timing a server, and noticing when you are not talking to it.
//!
//! The idea of ranking by TLS rather than TCP, and of treating a network
//! that terminates TLS as a distinct case from one that drops packets,
//! comes from dixonSolutions/protun-unblocked (MIT) — commits `215a4c5`
//! and `c873989` by dixonSolutions. The implementation here is new; the
//! insight is theirs and it is a good one. See NOTICE.md.
//!
//! WHY TCP TIMING IS NOT ENOUGH
//!
//! A TCP connect measures the path to *something* listening on that port.
//! On a filtered network that something is often not the server: a
//! transparent proxy accepts the connection locally, which makes it the
//! fastest "server" in any TCP-timed ranking. Ranking on that number
//! actively selects for the thing that will not work.
//!
//! A full TLS handshake is harder to fake. The proxy must either present a
//! certificate that fails verification — which we can see — or pass the
//! connection through, in which case the timing is real.
//!
//! WHAT THIS CANNOT TELL YOU
//!
//! A network running a proxy whose CA is installed in the system trust
//! store verifies cleanly, and this will call it healthy. That is a
//! managed-device scenario and no client-side check can see through it.
//! Said plainly here so the limitation is not mistaken for a bug.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Handshake completed and the session stayed open.
    Healthy,
    /// Could not even open a TCP connection.
    Unreachable,
    /// TCP opened, TLS did not complete.
    HandshakeFailed,
    /// The certificate did not verify. On a network that is otherwise
    /// working, this is a middlebox presenting its own certificate.
    CertificateRejected,
    /// The handshake completed and the peer then closed the session
    /// without carrying anything. This is the shape of a filter that
    /// terminates TLS to inspect it and then refuses the tunnel.
    ClosedImmediately,
}

impl Outcome {
    /// Does this outcome mean "you are not talking to the server you asked
    /// for"?
    pub fn is_interception(&self) -> bool {
        matches!(self, Outcome::CertificateRejected | Outcome::ClosedImmediately)
    }

    pub fn usable(&self) -> bool {
        matches!(self, Outcome::Healthy)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Outcome::Healthy => "ok",
            Outcome::Unreachable => "unreachable",
            Outcome::HandshakeFailed => "tls handshake failed",
            Outcome::CertificateRejected => "certificate rejected (intercepted)",
            Outcome::ClosedImmediately => "closed after handshake (intercepted)",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Probe {
    pub outcome: Outcome,
    /// Time to complete the TLS handshake. Present even for some failures,
    /// because how fast something rejected you is itself informative.
    pub handshake: Option<Duration>,
    pub detail: Option<String>,
}

impl Probe {
    pub fn ms(&self) -> Option<u64> {
        self.handshake.map(|d| d.as_millis() as u64)
    }
}

/// Time a TLS handshake to `host:port`, and judge who answered.
pub fn probe(host: &str, port: u16, timeout: Duration) -> Probe {
    let started = Instant::now();

    let Some(addr) = (host, port)
        .to_socket_addrs()
        .ok()
        .and_then(|mut it| it.find(|a| a.is_ipv4()))
    else {
        return Probe {
            outcome: Outcome::Unreachable,
            handshake: None,
            detail: Some("DNS did not resolve".into()),
        };
    };

    let sock = match TcpStream::connect_timeout(&addr, timeout) {
        Ok(s) => s,
        Err(e) => {
            return Probe {
                outcome: Outcome::Unreachable,
                handshake: None,
                detail: Some(e.to_string()),
            }
        }
    };
    let _ = sock.set_read_timeout(Some(timeout));
    let _ = sock.set_write_timeout(Some(timeout));

    // Verification stays ON. Turning it off would make every measurement
    // succeed and delete the signal this function exists to produce.
    let connector = match native_tls::TlsConnector::new() {
        Ok(c) => c,
        Err(e) => {
            return Probe {
                outcome: Outcome::HandshakeFailed,
                handshake: None,
                detail: Some(format!("no TLS backend: {e}")),
            }
        }
    };

    let mut stream = match connector.connect(host, sock) {
        Ok(s) => s,
        Err(e) => {
            let msg = e.to_string();
            // native-tls does not give a typed "cert invalid", so the
            // message is inspected. Matching loosely here is safe in a way
            // it is not elsewhere: the fallback is HandshakeFailed, which
            // is also a failure — a missed match costs detail, not
            // correctness.
            let lower = msg.to_ascii_lowercase();
            let outcome = if lower.contains("certificate")
                || lower.contains("cert verify")
                || lower.contains("self signed")
                || lower.contains("unknown ca")
                || lower.contains("hostname mismatch")
            {
                Outcome::CertificateRejected
            } else {
                Outcome::HandshakeFailed
            };
            return Probe {
                outcome,
                handshake: Some(started.elapsed()),
                detail: Some(msg),
            };
        }
    };

    let handshake = started.elapsed();

    // The handshake completed. Now find out whether the session survives
    // carrying anything, because "completes then closes" is exactly the
    // filter behaviour that a handshake-only measurement rewards.
    //
    // A minimal HTTP request is enough: we do not care about the response
    // body, only whether the peer stays long enough to send one.
    let req = format!("HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    if stream.write_all(req.as_bytes()).is_err() {
        return Probe {
            outcome: Outcome::ClosedImmediately,
            handshake: Some(handshake),
            detail: Some("peer closed before accepting a request".into()),
        };
    }

    let mut buf = [0u8; 16];
    match stream.read(&mut buf) {
        Ok(0) => Probe {
            outcome: Outcome::ClosedImmediately,
            handshake: Some(handshake),
            detail: Some("peer closed without replying".into()),
        },
        Ok(_) => Probe {
            outcome: Outcome::Healthy,
            handshake: Some(handshake),
            detail: None,
        },
        Err(e) => Probe {
            outcome: Outcome::ClosedImmediately,
            handshake: Some(handshake),
            detail: Some(e.to_string()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two interception outcomes must be reported as interception, and
    /// a plain unreachable host must NOT be — a network that drops packets
    /// is a different problem with a different answer, and conflating them
    /// sends the user chasing the wrong one.
    #[test]
    fn only_interception_outcomes_count_as_interception() {
        assert!(Outcome::CertificateRejected.is_interception());
        assert!(Outcome::ClosedImmediately.is_interception());
        assert!(!Outcome::Unreachable.is_interception());
        assert!(!Outcome::HandshakeFailed.is_interception());
        assert!(!Outcome::Healthy.is_interception());
    }

    #[test]
    fn only_healthy_is_usable() {
        assert!(Outcome::Healthy.usable());
        for o in [
            Outcome::Unreachable,
            Outcome::HandshakeFailed,
            Outcome::CertificateRejected,
            Outcome::ClosedImmediately,
        ] {
            assert!(!o.usable(), "{o:?} must not be usable");
        }
    }

    /// An address that nothing listens on must come back promptly as
    /// Unreachable rather than hanging or being called intercepted.
    #[test]
    fn unreachable_host_is_reported_not_guessed() {
        // 127.0.0.1 on a port nothing binds: refused immediately, no DNS,
        // no network needed, so this is safe in a sandbox.
        let p = probe("127.0.0.1", 1, Duration::from_millis(500));
        assert_eq!(p.outcome, Outcome::Unreachable);
        assert!(!p.outcome.is_interception());
        assert!(p.detail.is_some());
    }

    #[test]
    fn outcome_strings_are_distinct() {
        let all = [
            Outcome::Healthy,
            Outcome::Unreachable,
            Outcome::HandshakeFailed,
            Outcome::CertificateRejected,
            Outcome::ClosedImmediately,
        ];
        let mut seen = std::collections::HashSet::new();
        for o in all {
            assert!(seen.insert(o.as_str()), "duplicate label {}", o.as_str());
        }
    }
}
