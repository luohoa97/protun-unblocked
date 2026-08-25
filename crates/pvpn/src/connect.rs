//! `pvpn up`, `pvpn hop`, `pvpn down`.
//!
//! The ordering here is not incidental; most of it is a scar.
//!
//!   - **Intent is written before anything else touches the tunnel.** If a
//!     disconnect is slow, pvpnd must already know you meant it, or it sees
//!     a dying tunnel, calls it a fault, and reconnects you.
//!
//!   - **The busy marker is held for the whole operation.** A connect has a
//!     real window where NetworkManager shows no VPN at all — the old one
//!     is gone, the new one has not arrived — which is indistinguishable
//!     from you switching it off.
//!
//!   - **Routing is restored on every failure path.** `protonvpn connect`
//!     installs a full-tunnel route the moment it *starts*, so an abandoned
//!     connect blackholes the machine.
//!
//!   - **A slow tunnel is not a dead tunnel.** Time to first packet has
//!     been measured at 12s, >20s and >45s. Every tunnel written off as
//!     dead turned out to be alive shortly after, and discarding one costs
//!     a full reconnect that often lands on the same server. So running out
//!     of settle time does NOT tear it down.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use pvpn_core::{
    config::Config,
    intent::{self, BusyGuard},
    learn::NetworkMemory,
    net, paths, probe, proton, Intent,
};

pub struct UpArgs {
    pub filter: Option<String>,
    pub protocol: Option<String>,
    pub exclude: Vec<String>,
    /// "anywhere but the server I am on".
    pub hop: bool,
    pub rescan: bool,
    pub no_scan: bool,
    /// Wait and confirm traffic before returning. Off by default: `up`
    /// should return when the tunnel exists, and `pvpn status` answers
    /// "is it carrying anything" in about 0.3s.
    pub verify: bool,
    pub attempts: usize,
}

impl Default for UpArgs {
    fn default() -> Self {
        Self {
            filter: None,
            protocol: None,
            exclude: Vec::new(),
            hop: false,
            rescan: false,
            no_scan: false,
            verify: false,
            attempts: 3,
        }
    }
}

pub fn cmd_down(cfg: &Config) -> Result<u8> {
    let _busy = BusyGuard::acquire();

    // FIRST. Everything else in this function can be slow, and pvpnd must
    // not spend that time thinking a fault is in progress.
    intent::write(Intent::Down).context("recording intent")?;

    let was_on = proton::current_server();
    proton::disconnect();

    if proton::restore(Duration::from_secs(cfg.probe_timeout)) {
        match was_on {
            Some(s) => println!("Disconnected from {s}. Internet is working."),
            None => println!("Disconnected. Internet is working."),
        }
        Ok(0)
    } else {
        eprintln!("Disconnected, but the network still looks down.");
        eprintln!("Try:  nmcli con up <your-wifi>");
        Ok(1)
    }
}

pub fn cmd_up(cfg: &Config, mut args: UpArgs) -> Result<u8> {
    let _busy = BusyGuard::acquire();

    if args.hop {
        match proton::current_server() {
            Some(here) => {
                println!("Currently on: {here}");
                args.exclude.push(here);
            }
            None => eprintln!("Not connected - hop has nothing to move away from."),
        }
    }

    let switching = args.hop || !args.exclude.is_empty();

    if proton::is_connected() {
        if switching {
            // Switching does NOT need a disconnect first: `protonvpn
            // connect` replaces the tunnel in place. Tearing down first
            // would drop you to the bare network in between — slower, and a
            // moment of unprotected traffic.
            println!("Switching server without disconnecting first.");
        } else if probe::traffic_flows(Duration::from_secs(cfg.probe_timeout)).alive {
            println!("Already connected.");
            return Ok(0);
        } else {
            // Claims connected, nothing passes. The post-resume case:
            // protun's reconnect probes UDP, which this network blocks, so
            // it cannot recover on its own.
            eprintln!("Connected, but no traffic is passing - stale tunnel. Rebuilding...");
            proton::restore(Duration::from_secs(cfg.probe_timeout));
            std::thread::sleep(Duration::from_secs(2));
        }
    }

    // Stealth by default, explicit choice wins.
    //
    // Deliberately NOT seeded from settings.json. The right protocol is a
    // property of the NETWORK, not a preference: Stealth is correct on a
    // filtered network and wrong on an open one. settings.json is sticky,
    // so connecting once at school would otherwise pin protun-tls for every
    // connect at home, where it stalls on rekey timeouts.
    let proto = match &args.protocol {
        Some(p) => p.clone(),
        None if proton::protocol_available("protun-tls") => "protun-tls".into(),
        None => proton::current_protocol().unwrap_or_else(|| "protun-tls".into()),
    };
    if let Err(e) = proton::set_protocol(&proto) {
        eprintln!("pvpn: could not set protocol: {e:#}");
    }

    intent::write(Intent::Up).context("recording intent")?;

    let network = net::network_id();
    let mut memory = NetworkMemory::load(&network);

    let targets = if args.no_scan {
        Vec::new()
    } else {
        let candidates = scan_candidates(cfg, &args, &network)?;
        let ranked = memory.rank(&candidates, cfg.blocked_retry_after_hours);
        ranked
            .into_iter()
            .filter(|t| !args.exclude.iter().any(|x| x == t))
            .collect()
    };

    if targets.is_empty() && !args.no_scan {
        if args.filter.is_some() {
            anyhow::bail!("nothing matched that filter. Try: pvpn scan");
        }
        if switching {
            anyhow::bail!("no other server available to move to");
        }
    }

    if let Some(first) = targets.first() {
        println!("Best pick: {first}");
        if !proton::steering_available() {
            eprintln!("WARNING: server steering is unavailable - the shim at");
            eprintln!("  {} is stale or missing, so Proton", proton::shim_dir().display());
            eprintln!("  will choose the server, not you. Fix with: ./setup.sh");
        }
    }

    let attempts = if targets.is_empty() {
        args.attempts
    } else {
        targets.len().min(args.attempts)
    };

    println!(
        "Connecting via {proto} - your internet will stall for up to {}s.",
        cfg.connect_timeout_secs
    );
    println!("(that is normal: the route moves into the tunnel before it is up)");

    for n in 0..attempts {
        let target = targets.get(n);
        if n > 0 {
            println!("Attempt {}/{attempts} - reconnecting...", n + 1);
            proton::disconnect();
            std::thread::sleep(Duration::from_secs(2));
        }
        if let Some(t) = target {
            if n > 0 {
                println!("  next by rank: {t}");
            }
        }

        let started = Instant::now();
        let output = run_connect(cfg, target.map(|s| s.as_str()));

        match output {
            ConnectResult::Connected => {
                let where_ = proton::current_server();
                let elapsed = started.elapsed();
                if let Some(t) = target {
                    memory.record_success(t);
                }
                let _ = memory.save();

                match &where_ {
                    Some(s) => println!("Connected to {s} via {proto} in {:.0}s.", elapsed.as_secs_f64()),
                    None => println!("Connected via {proto} in {:.0}s.", elapsed.as_secs_f64()),
                }

                if args.verify {
                    print!("  checking traffic...");
                    let _ = std::io::Write::flush(&mut std::io::stdout());
                    if settled(cfg) {
                        println!(" flowing.");
                    } else {
                        println!();
                        eprintln!(
                            "No traffic yet after {}s. KEEPING the tunnel: in testing",
                            cfg.settle_secs
                        );
                        eprintln!("these have come good shortly afterwards.");
                        eprintln!("  check with: pvpn status   |   give up with: pvpn down");
                    }
                }
                return Ok(0);
            }
            ConnectResult::Failed { detail, kind } => {
                eprintln!("Could not connect via {proto}: {detail}");
                if let Some(t) = target {
                    memory.record_failure(t, detail.clone());
                }
                match kind {
                    proton::Failure::BackendMissing => {
                        eprintln!("Backend missing for {proto}. Run: pvpn protocols");
                        break;
                    }
                    proton::Failure::Refused => break,
                    proton::Failure::Retryable => {}
                }
            }
        }
    }

    let _ = memory.save();
    eprintln!("Restoring your normal connection...");
    if proton::restore(Duration::from_secs(cfg.probe_timeout)) {
        eprintln!("Internet restored.");
    } else {
        eprintln!("Internet still down - try: pvpn down");
    }
    Ok(1)
}

enum ConnectResult {
    Connected,
    Failed {
        detail: String,
        kind: proton::Failure,
    },
}

/// One connect attempt, bounded and steered.
///
/// `PVPN_ONLY` is how the server is chosen: free accounts refuse
/// `--country`, `--random` and by-id, so hiding the other servers in
/// Proton's own cache (via our sitecustomize shim) is the only lever there
/// is.
fn run_connect(cfg: &Config, target: Option<&str>) -> ConnectResult {
    let mut cmd = Command::new("timeout");
    cmd.arg("--kill-after=10")
        .arg(cfg.connect_timeout_secs.to_string())
        .arg("protonvpn")
        .arg("connect")
        .env("PYTHONPATH", proton::shim_dir())
        .env("PVPN_DEBUG", "0")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(t) = target {
        cmd.env("PVPN_ONLY", t);
    }

    let out = match cmd.output() {
        Ok(o) => o,
        Err(e) => {
            return ConnectResult::Failed {
                detail: format!("could not run protonvpn: {e}"),
                kind: proton::Failure::Retryable,
            }
        }
    };

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    if out.status.success() && proton::is_connected() {
        return ConnectResult::Connected;
    }

    let detail = if out.status.code() == Some(124) {
        format!("timed out after {}s", cfg.connect_timeout_secs)
    } else {
        first_useful_line(&combined).unwrap_or_else(|| "refused".into())
    };

    ConnectResult::Failed {
        detail,
        kind: proton::classify_failure(&combined),
    }
}

/// Pull one line worth showing a human out of Proton's output.
fn first_useful_line(text: &str) -> Option<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .find(|l| {
            let lower = l.to_ascii_lowercase();
            lower.contains("error")
                || lower.contains("failed")
                || lower.contains("not available")
                || lower.contains("unexpected")
                || lower.contains("missing")
        })
        .map(|l| l.to_string())
}

/// Wait up to `settle_secs` for traffic, without ever tearing the tunnel
/// down when it runs out.
fn settled(cfg: &Config) -> bool {
    let deadline = Instant::now() + Duration::from_secs(cfg.settle_secs);
    while Instant::now() < deadline {
        if probe::traffic_flows(Duration::from_secs(cfg.probe_timeout)).alive {
            return true;
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    false
}

/// Candidate servers, from the scanner, cached per network.
///
/// The scanner is `lib/pvpn-scan.py` and stays Python: it probes ~70
/// servers concurrently by TLS handshake, and it already encodes why TCP
/// timing is worthless here (a middlebox completes the TCP handshake
/// locally and reports 1.6ms to a US server from Australia). Rewriting a
/// working, well-reasoned measurement tool would be motion, not progress.
fn scan_candidates(cfg: &Config, args: &UpArgs, network: &str) -> Result<Vec<String>> {
    let scanner = proton::shim_dir().join("pvpn-scan.py");
    if !scanner.is_file() {
        eprintln!("scanner missing at {} - re-run setup.sh", scanner.display());
        return Ok(Vec::new());
    }

    let key = net::sanitise(&format!(
        "{}@{}",
        args.filter.as_deref().unwrap_or("_any"),
        network
    ));
    let cache = paths::data_dir().join("scan").join(format!("{key}.json"));

    if !args.rescan {
        if let Some(names) = read_fresh_cache(&cache, 60) {
            eprintln!("  using a recent scan of this network (--rescan to redo)");
            return Ok(names);
        }
    }

    eprintln!("Ranking servers by TLS handshake time...");
    let mut cmd = Command::new("/usr/bin/python3");
    cmd.arg(&scanner);
    if let Some(f) = &args.filter {
        cmd.arg(f);
    }
    cmd.arg("--json")
        .env("PYTHONPATH", proton::shim_dir())
        .stderr(Stdio::inherit());

    let out = cmd.output().context("running the scanner")?;
    if !out.status.success() {
        eprintln!("scanner failed; Proton will choose the server");
        return Ok(Vec::new());
    }

    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let names = parse_scan(&text);

    if !names.is_empty() {
        let _ = paths::write_atomic(&cache, &text);
        // Fold the measurements into what we know about this network, so a
        // later `pvpn fast` reflects them and ranking has latency to work
        // with.
        let mut memory = NetworkMemory::load(network);
        for entry in parse_scan_full(&text) {
            memory.record_latency(&entry.0, entry.1, entry.2);
        }
        let _ = memory.save();
    }
    let _ = cfg;
    Ok(names)
}

fn read_fresh_cache(path: &std::path::Path, max_age_mins: u64) -> Option<Vec<String>> {
    let meta = std::fs::metadata(path).ok()?;
    let age = meta.modified().ok()?.elapsed().ok()?;
    if age > Duration::from_secs(max_age_mins * 60) {
        return None;
    }
    let text = std::fs::read_to_string(path).ok()?;
    let names = parse_scan(&text);
    (!names.is_empty()).then_some(names)
}

/// Server names from the scanner's JSON, in the order it ranked them.
pub fn parse_scan(text: &str) -> Vec<String> {
    parse_scan_full(text).into_iter().map(|(n, _, _)| n).collect()
}

/// `(name, latency_ms, intercepted)` from the scanner's JSON.
///
/// Tolerant on purpose: a row without a name is skipped rather than
/// failing the parse, and a missing latency becomes a large number rather
/// than an error. A scanner that grows a field must not break connecting.
pub fn parse_scan_full(text: &str) -> Vec<(String, u64, bool)> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(text) else {
        return Vec::new();
    };
    let Some(rows) = v.as_array() else {
        return Vec::new();
    };
    rows.iter()
        .filter_map(|r| {
            let name = r.get("name")?.as_str()?.to_string();
            let ms = r
                .get("ms")
                .or_else(|| r.get("latency_ms"))
                .or_else(|| r.get("latency"))
                .and_then(|x| x.as_f64())
                .map(|f| f as u64)
                .unwrap_or(10_000);
            let intercepted = r
                .get("intercepted")
                .and_then(|x| x.as_bool())
                .unwrap_or(false);
            Some((name, ms, intercepted))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_json_parses_names_in_order() {
        let text = r#"[
            {"name":"SG-FREE#20","ms":99},
            {"name":"JP-FREE#3","ms":140}
        ]"#;
        assert_eq!(parse_scan(text), vec!["SG-FREE#20", "JP-FREE#3"]);
    }

    /// A scanner that grows or renames a field must not break connecting.
    /// Missing latency degrades to "unmeasured", not to an error.
    #[test]
    fn scan_json_is_parsed_tolerantly() {
        let text = r#"[
            {"name":"A"},
            {"name":"B","latency_ms":50,"something_new":1},
            {"no_name":true}
        ]"#;
        let full = parse_scan_full(text);
        assert_eq!(full.len(), 2, "the row without a name is skipped");
        assert_eq!(full[0].1, 10_000);
        assert_eq!(full[1].1, 50);
    }

    #[test]
    fn malformed_scan_output_yields_nothing_not_a_panic() {
        assert!(parse_scan("not json").is_empty());
        assert!(parse_scan("").is_empty());
        assert!(parse_scan("{\"not\":\"an array\"}").is_empty());
    }

    #[test]
    fn useful_line_picks_the_error_not_the_banner() {
        let out = "Proton VPN CLI v4\nConnecting...\nError: server not available on the free plan\n";
        assert_eq!(
            first_useful_line(out).as_deref(),
            Some("Error: server not available on the free plan")
        );
    }

    #[test]
    fn useful_line_is_none_when_nothing_looks_like_an_error() {
        assert_eq!(first_useful_line("all fine here\n"), None);
    }
}
