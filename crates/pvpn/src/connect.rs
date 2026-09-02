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
    dbus,
    intent::{self, BusyGuard},
    learn::NetworkMemory,
    net, paths, probe, proton, Intent,
};

pub struct UpArgs {
    /// Servers named outright with `-s/--server`.
    ///
    /// Kept apart from `filter` because naming a server is an ANSWER, not a
    /// search: there is nothing to rank, and measuring a list of one just
    /// to sort it costs a Python start plus two TLS handshakes for no
    /// information. `pvpn up --server SG-FREE#20` used to print
    /// "probing 1 servers, 2 samples each" before connecting to the only
    /// candidate it had.
    pub explicit: Vec<String>,
    /// Try this server FIRST, then fall back to the ranking.
    ///
    /// Different from `explicit`, which means "this one and nothing else".
    /// This is a preference with a safety net, and it exists for the
    /// daemon: after a drop, the server that was working thirty seconds ago
    /// is the strongest evidence available. Reconnecting by re-ranking from
    /// scratch throws that away and can land on one the filter kills.
    pub prefer: Option<String>,
    pub filter: Option<String>,
    pub protocol: Option<String>,
    pub exclude: Vec<String>,
    /// "anywhere but the server I am on".
    pub hop: bool,
    pub rescan: bool,
    pub no_scan: bool,
    /// Confirm traffic actually flows before crediting the server.
    ///
    /// ON by default. It costs `verify_secs` on a tunnel that is slow to
    /// settle, and it buys the only thing that makes the ranking
    /// trustworthy: without it a server is credited for a tunnel that came
    /// up carrying nothing.
    pub verify: bool,
    pub attempts: usize,
}

impl Default for UpArgs {
    fn default() -> Self {
        Self {
            explicit: Vec::new(),
            prefer: None,
            filter: None,
            protocol: None,
            exclude: Vec::new(),
            hop: false,
            rescan: false,
            no_scan: false,
            verify: true,
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

/// Where the wall clock went.
///
/// Printed after every connect, not hidden behind a flag. "Why did that
/// take twelve seconds" is the single most common question about this
/// tool, and answering it should not require re-running with -v or asking
/// someone to read the source.
#[derive(Default)]
struct Timing {
    phases: Vec<(&'static str, Duration)>,
    started: Option<Instant>,
}

impl Timing {
    fn new() -> Self {
        Self {
            phases: Vec::new(),
            started: Some(Instant::now()),
        }
    }

    fn mark<T>(&mut self, name: &'static str, f: impl FnOnce() -> T) -> T {
        let t = Instant::now();
        let v = f();
        self.phases.push((name, t.elapsed()));
        v
    }

    fn record(&mut self, name: &'static str, d: Duration) {
        self.phases.push((name, d));
    }

    fn report(&self) {
        let total = self.started.map(|s| s.elapsed()).unwrap_or_default();
        // Only the parts worth looking at. Sub-5ms phases are noise and
        // burying the slow one in a list of them helps nobody.
        let interesting: Vec<_> = self
            .phases
            .iter()
            .filter(|(_, d)| *d >= Duration::from_millis(5))
            .collect();
        eprintln!();
        eprint!("  took {:.2}s", total.as_secs_f64());
        if interesting.is_empty() {
            eprintln!();
            return;
        }
        eprintln!(
            "  ({})",
            interesting
                .iter()
                .map(|(n, d)| format!("{n} {:.2}s", d.as_secs_f64()))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
}

pub fn cmd_up(cfg: &Config, mut args: UpArgs) -> Result<u8> {
    let _busy = BusyGuard::acquire();
    let mut timing = Timing::new();

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

    if timing.mark("check-connected", proton::is_connected) {
        if switching {
            // Switching does NOT need a disconnect first: `protonvpn
            // connect` replaces the tunnel in place. Tearing down first
            // would drop you to the bare network in between — slower, and a
            // moment of unprotected traffic.
            println!("Switching server without disconnecting first.");
        } else if timing
            .mark("probe", || {
                probe::traffic_flows(Duration::from_secs(cfg.probe_timeout))
            })
            .alive
        {
            println!("Already connected.");
            timing.report();
            return Ok(0);
        } else {
            // Claims connected, nothing passes. The post-resume case:
            // protun's reconnect probes UDP, which this network blocks, so
            // it cannot recover on its own.
            eprintln!("Connected, but no traffic is passing - stale tunnel. Rebuilding...");
            // restore() waits up to 10s for traffic to come back, then can
            // bounce the wifi. It is the slowest thing on this path by an
            // order of magnitude, so it is timed separately - "took 12s"
            // usually means it was this, not the connect.
            let recovered = timing.mark("restore", || {
                proton::restore(Duration::from_secs(cfg.probe_timeout))
            });
            // The old flat 2-second settle is gone. restore() polls until
            // traffic actually flows, so when it succeeds the routes are
            // demonstrably back and there is nothing left to wait for -
            // sleeping anyway just billed the user two seconds to prove
            // something already proven. Only the failure case still gets a
            // pause, and a shorter one.
            if !recovered {
                std::thread::sleep(Duration::from_millis(750));
            }
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

    let network = timing.mark("network-id", net::network_id);
    let mut memory = NetworkMemory::load(&network);

    let mut confident: Vec<String> = Vec::new();
    let mut targets = if !args.explicit.is_empty() {
        // Named outright: nothing to measure, nothing to choose.
        args.explicit.clone()
    } else if args.no_scan {
        Vec::new()
    } else if !args.rescan && {
        let known = memory.confident_choices(cfg.blocked_retry_after_hours);
        if known.len() >= cfg.trust_after_servers as usize {
            // Quietest possible connect: no measurement at all, just what
            // this network has already proven. A scan is ~140 TLS
            // handshakes into one provider's address space in a few
            // seconds - by far the most distinctive thing this tool emits,
            // and the thing most likely to get an entry IP blocklisted for
            // everyone sharing it.
            eprintln!(
                "  using what this network taught us ({} servers, --rescan to remeasure)",
                known.len()
            );
            confident = known;
            true
        } else {
            false
        }
    } {
        confident
            .into_iter()
            .filter(|t| !args.exclude.iter().any(|x| x == t))
            .collect()
    } else {
        let candidates =
            timing.mark("scan", || scan_candidates(cfg, &args, &network, &mut memory))?;
        // Weight by what other sites on this SSID have learned. On a
        // department-wide network like a school, the filter policy is the
        // same everywhere but each building has its own gateway - so a
        // server refused in the next block is worth knowing about here.
        let priors = match net::wifi_ssid() {
            Some(ssid) => NetworkMemory::realm_priors(
                &ssid,
                &network,
                cfg.blocked_retry_after_hours,
            ),
            None => Default::default(),
        };
        if !priors.is_empty() {
            tracing::debug!(servers = priors.len(), "applying evidence from sibling sites");
        }
        let ranked = memory.rank_with(&candidates, cfg.blocked_retry_after_hours, &priors);
        ranked
            .into_iter()
            .filter(|t| !args.exclude.iter().any(|x| x == t))
            .collect()
    };

    targets = with_preferred(targets, args.prefer.as_deref(), &args.exclude);

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

        // Fast path first: a saved NM profile means no Python at all.
        let fast = target.and_then(|t| fast_activate(cfg, t));
        let via_fast_path = fast.is_some();
        let output = match fast {
            Some(r) => {
                timing.record("activate", started.elapsed());
                r
            }
            None => {
                let t = Instant::now();
                let r = run_connect(cfg, target.map(|s| s.as_str()));
                timing.record("protonvpn-connect", t.elapsed());
                r
            }
        };

        match output {
            ConnectResult::Connected => {
                let where_ = proton::current_server();

                // Verification decides what we LEARN, which is the whole
                // point of doing it. Before this, a server was credited the
                // moment NetworkManager brought a tunnel up - and a tunnel
                // that is up while carrying nothing is the exact failure
                // this project exists to catch. The ranking was being
                // taught by the thing it is supposed to detect.
                let verified = if args.verify {
                    print!("  waiting for traffic...");
                    let _ = std::io::Write::flush(&mut std::io::stdout());
                    let when = timing.mark("verify", || {
                        settled(Duration::from_secs(cfg.verify_secs))
                    });
                    match when {
                        Some(d) => println!(" flowing after {:.1}s.", d.as_secs_f64()),
                        None => println!(" nothing yet."),
                    }
                    Some(when.is_some())
                } else {
                    // Even waiving verification, one short probe is nearly
                    // free and stops us claiming "Connected" for a tunnel
                    // that is demonstrably carrying nothing yet.
                    let flowing = timing.mark("quick-probe", || {
                        probe::traffic_flows(SETTLE_PROBE).alive
                    });
                    if !flowing {
                        eprintln!("  (tunnel is up; traffic not flowing yet - not verified)");
                    }
                    None
                };

                let elapsed = started.elapsed();
                match (target, verified) {
                    // Proven: credit it, and time it to VERIFIED rather
                    // than to "tunnel exists", because that is when it
                    // actually became usable.
                    (Some(t), Some(true)) | (Some(t), None) => {
                        memory.record_success(t);
                        memory.record_connect_time(t, elapsed.as_millis() as u64);
                    }
                    // Came up, carried nothing. Not credited, and not
                    // condemned on a single occurrence either.
                    (Some(t), Some(false)) => {
                        if memory.record_unverified(t) {
                            eprintln!("  {t} has now failed to carry traffic twice here.");
                            eprintln!("  Blocked for now; `pvpn up` will pick another.");
                        }
                    }
                    (None, _) => {}
                }
                let _ = memory.save();

                match &where_ {
                    Some(s) => println!("Connected to {s} via {proto} in {:.1}s.", elapsed.as_secs_f64()),
                    None => println!("Connected via {proto} in {:.1}s.", elapsed.as_secs_f64()),
                }
                if !via_fast_path {
                    println!(
                        "  (first connect to this server - the next one skips Proton's client)"
                    );
                }

                if verified == Some(false) {
                    // The tunnel is KEPT. Time to first packet has been
                    // measured at 12s, >20s and >45s here, and every tunnel
                    // written off as dead came good shortly after. Throwing
                    // it away costs a full reconnect that often lands on
                    // the same server.
                    eprintln!();
                    eprintln!(
                        "No traffic within {}s. KEEPING the tunnel: these have come good",
                        cfg.verify_secs
                    );
                    eprintln!("shortly afterwards in testing, and pvpnd will repair it if not.");
                    eprintln!("  check with: pvpn status   |   give up with: pvpn down");
                }

                timing.report();
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
    timing.report();
    eprintln!("Restoring your normal connection...");
    if proton::restore(Duration::from_secs(cfg.probe_timeout)) {
        eprintln!("Internet restored.");
    } else {
        eprintln!("Internet still down - try: pvpn down");
    }
    Ok(1)
}

/// Bring up a server we have connected to before, without Proton's client.
///
/// THE reason `pvpn up` stopped taking tens of seconds.
///
/// Proton's client does not build the tunnel itself - it writes a
/// NetworkManager profile and asks NM to activate it, and those profiles
/// persist. So for any server already used once, the whole Python stack is
/// unnecessary: `protonvpn connect` costs ~10s, of which 2.0s is the
/// interpreter starting before it does anything, while NM's
/// ActivateConnection is a single method call.
///
/// Returns `None` when there is no saved profile, which is not a failure -
/// it means "this server is new here, go the long way once".
fn fast_activate(cfg: &Config, server: &str) -> Option<ConnectResult> {
    let profile = dbus::find_tunnel_profile(server)?;
    tracing::debug!(id = %profile.id, uuid = %profile.uuid, "found a saved profile");

    // Switching tunnels: NM will not sensibly run two at once, and leaving
    // the old one up makes the new activation fail rather than replace it.
    if let Some(active) = dbus::active_tunnel_path() {
        if dbus::connection_id(&active).as_deref() != Some(profile.id.as_str()) {
            let _ = dbus::deactivate(&active);
        } else {
            // Already on exactly this server.
            return Some(ConnectResult::Connected);
        }
    }

    let started = std::time::Instant::now();
    let active = match dbus::activate(&profile) {
        Ok(p) => p,
        Err(e) => {
            // Fall back rather than fail: a profile that NM refuses to
            // activate (stale credentials, changed plugin) is exactly what
            // the slow path exists to rebuild.
            tracing::warn!(error = %e, "direct activation refused; falling back to the client");
            return None;
        }
    };
    tracing::debug!(?active, "activation accepted in {:?}", started.elapsed());

    match dbus::await_activation(&active, Duration::from_secs(cfg.connect_timeout_secs)) {
        r if r.ok() => Some(ConnectResult::Connected),
        pvpn_core::dbus::ActivationResult::TimedOut => Some(ConnectResult::Failed {
            detail: format!("timed out after {}s", cfg.connect_timeout_secs),
            kind: proton::Failure::Retryable,
        }),
        other => {
            // NM tried and refused. That can mean stale credentials, which
            // the client CAN fix, so hand it over rather than reporting a
            // dead server.
            tracing::warn!(?other, "saved profile failed; falling back to the client");
            None
        }
    }
}

/// Put the preferred server at the head of the list, keeping the ranking
/// behind it as the fallback.
///
/// One invocation, two tiers: try what was working, then try what is best.
/// A preference that is excluded (`--not`, or a hop moving away from it) is
/// ignored rather than honoured - otherwise `pvpn hop` would keep choosing
/// the server it was asked to leave.
fn with_preferred(
    mut targets: Vec<String>,
    prefer: Option<&str>,
    exclude: &[String],
) -> Vec<String> {
    let Some(pref) = prefer else {
        return targets;
    };
    if exclude.iter().any(|x| x == pref) {
        return targets;
    }
    targets.retain(|t| t != pref);
    targets.insert(0, pref.to_string());
    targets
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
/// How long a single probe may take while we are waiting for a tunnel to
/// come alive.
///
/// Deliberately NOT `probe_timeout` (5s). Those are different questions.
/// `probe_timeout` governs "is this established tunnel dead", where being
/// patient avoids tearing down a working connection over one slow packet.
/// Here we are asking "has it started yet", over and over, and a working
/// tunnel answers in ~250ms. Waiting five seconds for each NO just blinds
/// us between attempts.
const SETTLE_PROBE: Duration = Duration::from_millis(900);

/// How often to ask.
const SETTLE_POLL: Duration = Duration::from_millis(150);

/// Wait for the tunnel to actually carry traffic, and return the moment it
/// does.
///
/// WHY THIS MATTERS MORE THAN IT LOOKS
///
/// NetworkManager reports ACTIVATED when the tunnel OBJECT exists. That is
/// not the same as usable: protun's inner WireGuard handshake can still be
/// pending, and until it completes every packet is dropped while the route
/// already points into the tunnel. So `up` returning on ACTIVATED reports
/// "Connected" for a tunnel that carries nothing for another ten seconds -
/// which is exactly what it felt like from the outside.
///
/// The old loop made that worse rather than better. Each attempt used the
/// full 5s probe_timeout, so a failed check cost ~6.5s including the sleep,
/// and in a 20-second window there was time for THREE looks. Traffic that
/// started flowing at t=2s went unnoticed until t=6.5s. Most of the wait
/// was polling resolution, not the tunnel.
///
/// Short probes, polled tightly: now it notices within ~150ms of the first
/// packet getting through.
fn settled(window: Duration) -> Option<Duration> {
    let started = Instant::now();
    let deadline = started + window;
    loop {
        if probe::traffic_flows(SETTLE_PROBE).alive {
            return Some(started.elapsed());
        }
        if Instant::now() + SETTLE_POLL >= deadline {
            return None;
        }
        std::thread::sleep(SETTLE_POLL);
    }
}

/// Candidate servers, from the scanner, cached per network.
///
/// The scanner is `lib/pvpn-scan.py` and stays Python: it probes ~70
/// servers concurrently by TLS handshake, and it already encodes why TCP
/// timing is worthless here (a middlebox completes the TCP handshake
/// locally and reports 1.6ms to a US server from Australia). Rewriting a
/// working, well-reasoned measurement tool would be motion, not progress.
fn scan_candidates(
    cfg: &Config,
    args: &UpArgs,
    network: &str,
    memory: &mut NetworkMemory,
) -> Result<Vec<String>> {
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

    // Re-measure automatically when the cache would only tell us things we
    // have already learned are wrong.
    //
    // A cached scan is a list of latencies. If every server it names is now
    // BLOCKED here, reusing it just re-picks servers we know do not work -
    // which is what "up doesn't auto rescan" looked like from the outside.
    // Evidence that contradicts the cache invalidates it.
    let stale_by_evidence = {
        let cached = read_fresh_cache(&cache, cfg.scan_ttl_mins)
            .map(|t| parse_scan(&t))
            .unwrap_or_default();
        !cached.is_empty()
            && cached.iter().all(|s| {
                memory
                    .servers
                    .get(s)
                    .map(|r| r.is_blocked(cfg.blocked_retry_after_hours, pvpn_core::intent::now_secs()))
                    .unwrap_or(false)
            })
    };
    if stale_by_evidence {
        eprintln!("  every server in the last scan is blocked here - re-measuring");
    }

    if !args.rescan && !stale_by_evidence {
        if let Some(text) = read_fresh_cache(&cache, cfg.scan_ttl_mins) {
            let names = parse_scan(&text);
            if !names.is_empty() {
                eprintln!("  using a recent scan of this network (--rescan to redo)");
                // Fold the CACHED measurements in too. Previously a cache
                // hit returned names only, so a network whose scan was
                // still fresh taught the ranking nothing at all - it went
                // straight back to having no latencies to sort by.
                record_scan(memory, &text);
                return Ok(names);
            }
        }
    }

    eprintln!("Ranking servers by TLS handshake time...");
    let mut cmd = Command::new("/usr/bin/python3");
    cmd.arg(&scanner);
    if let Some(f) = &args.filter {
        cmd.arg(f);
    }
    cmd.arg("--json")
        // Deliberately gentle. The scanner's default was 24 concurrent
        // probes; across ~70 candidates at 2 samples each that is ~140 TLS
        // handshakes into one provider's address space in a few seconds,
        // from a single client. That burst is far more distinctive than the
        // tunnel it is choosing - a tunnel is one long-lived TLS session on
        // 443 and looks like any other HTTPS connection.
        //
        // Six at a time takes longer and is worth it: the whole point of
        // the memory is that this runs rarely, so its speed matters much
        // less than what it looks like when it does.
        .arg("--workers")
        .arg("6")
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
        // Into the CALLER'S memory, not a private copy.
        //
        // This was the bug behind "it doesn't use the learnt network at
        // all". scan_candidates used to load its own NetworkMemory, record
        // the latencies and save - while cmd_up held a separate copy loaded
        // BEFORE the scan. The ranking then ran against that stale copy
        // (no latencies at all), and cmd_up's own save at the end
        // overwrote the file, erasing every measurement the scan had just
        // taken. Every scan learned, and was wiped, on every single `up`.
        record_scan(memory, &text);
    }
    let _ = (cfg, network);
    Ok(names)
}

/// Fold a scanner JSON result into what we know about this network.
fn record_scan(memory: &mut NetworkMemory, text: &str) {
    for (name, ms, intercepted) in parse_scan_full(text) {
        memory.record_latency(&name, ms, intercepted);
    }
}

/// The cached scan, if it is recent enough to trust.
///
/// Returns the raw JSON, not just the names: the latencies in it are the
/// whole reason the file exists, and a caller that only gets names cannot
/// teach the ranking anything.
fn read_fresh_cache(path: &std::path::Path, max_age_mins: u64) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    let age = meta.modified().ok()?.elapsed().ok()?;
    if age > Duration::from_secs(max_age_mins * 60) {
        return None;
    }
    let text = std::fs::read_to_string(path).ok()?;
    (!parse_scan(&text).is_empty()).then_some(text)
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

    /// After a drop, the server that was working is the strongest evidence
    /// there is - but it must not become the ONLY option, or a server that
    /// died for good would strand the reconnect.
    #[test]
    fn preferred_goes_first_and_the_ranking_survives_as_fallback() {
        let ranked = vec!["A".to_string(), "B".to_string(), "C".to_string()];
        let out = with_preferred(ranked.clone(), Some("B"), &[]);
        assert_eq!(out, vec!["B", "A", "C"], "preferred first, no duplicate");
        assert_eq!(out.len(), 3, "the fallbacks are still there");

        // A server not in the ranking is still tried first.
        let out = with_preferred(ranked.clone(), Some("Z"), &[]);
        assert_eq!(out[0], "Z");
        assert_eq!(out.len(), 4);
    }

    /// `pvpn hop` excludes the server it is leaving. Honouring a preference
    /// for it anyway would make hop reconnect to exactly what it was told
    /// to move away from.
    #[test]
    fn an_excluded_server_is_never_preferred() {
        let ranked = vec!["A".to_string(), "B".to_string()];
        let out = with_preferred(ranked.clone(), Some("A"), &["A".to_string()]);
        assert_eq!(out, ranked, "exclusion wins over preference");
    }

    #[test]
    fn no_preference_leaves_the_ranking_alone() {
        let ranked = vec!["A".to_string(), "B".to_string()];
        assert_eq!(with_preferred(ranked.clone(), None, &[]), ranked);
    }

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
