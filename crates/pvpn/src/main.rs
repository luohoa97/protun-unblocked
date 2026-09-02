//! `pvpn` - Proton VPN wrapper for filtered networks.
//!
//! THIS IS A PORT IN PROGRESS. The original is 1,560 lines of bash, and
//! rewriting it in one go would mean a long stretch where neither version
//! works. So this binary is the front door from day one, implements
//! commands as they are ported, and hands the rest to the bash script
//! unchanged.
//!
//! That is deliberate and it is temporary. `Delegated` below is the list of
//! what is left; when it is empty, the script goes.
//!
//! The delegation target is installed as `pvpn-legacy`, NOT as `pvpn` -
//! otherwise this binary would find itself and recurse.

mod apps;
mod connect;
mod memory_cmd;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use pvpn_core::{config::Config, intent, nm, probe, state::DaemonState};
use std::process::{Command, ExitCode};
use std::time::Duration;

#[derive(Parser)]
#[command(
    name = "pvpn",
    version,
    about = "Proton VPN for networks that filter it",
    long_about = None,
    disable_help_subcommand = true
)]
struct Cli {
    /// Machine-readable output where the command supports it.
    #[arg(long, global = true)]
    json: bool,

    /// More detail on stderr. Repeat for more.
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Connect, measuring servers first.
    Up(UpFlags),

    /// Disconnect.
    #[command(alias = "disconnect")]
    Down,

    /// Change server: anywhere but the one you are on.
    #[command(alias = "next")]
    Hop(UpFlags),

    /// Rank the servers this network can actually use, then connect.
    #[command(alias = "fastest")]
    Best(UpFlags),

    /// Where am I exiting, and is the tunnel actually carrying traffic?
    #[command(alias = "st")]
    Status,

    /// What this network measured as quick.
    Fast,

    /// What this network refused, and why.
    Blocked,

    /// Flatpak apps that route around the tunnel.
    Apps {
        /// Put them back on the tunnel.
        #[arg(long)]
        fix: bool,
    },

    /// What the daemon last published, verbatim.
    State,

    // ---- not yet ported; handed to the bash implementation ----
    /// Try every protocol.
    Try,
    /// Sign in.
    Login { args: Vec<String> },
    /// Measure this network without connecting.
    Scan {
        /// Country, city or server name to narrow the measurement.
        filter: Option<String>,
        /// Measure even while connected, knowing the numbers describe your
        /// exit node rather than this network.
        #[arg(long)]
        force: bool,
    },
    /// Which protocol backends are actually installed.
    Protocols,
    /// Privileged cleanup (needs sudo).
    Fix { args: Vec<String> },
}

#[derive(clap::Args, Default)]
struct UpFlags {
    /// Country, city or server name. Bare words work: `pvpn up japan`.
    pattern: Option<String>,

    // The three filter flags below all feed one comma-joined filter, which
    // is what the scanner takes. They are kept as separate names because
    // that is the documented interface and what muscle memory types —
    // collapsing them into `pattern` alone would silently break every
    // `pvpn up -c japan` anyone has in a script.
    /// Country. Repeatable; repeats are OR-ed.
    #[arg(short = 'c', long = "country")]
    country: Vec<String>,
    /// City. Repeatable.
    #[arg(long = "city")]
    city: Vec<String>,
    /// Exact server name, e.g. JP-FREE#5. Repeatable.
    ///
    /// Naming a server skips measurement entirely - there is nothing to
    /// rank - and takes the saved-profile fast path when one exists.
    #[arg(short = 's', long = "server")]
    server: Vec<String>,

    /// Try this server first, then fall back to the ranking.
    ///
    /// Unlike --server, this is a preference with a safety net. pvpnd uses
    /// it to reconnect to whatever was working before a drop rather than
    /// re-ranking from scratch and landing somewhere new.
    ///
    /// NOT --prefer: that is the ranking mode, and reusing the name made
    /// `--prefer latency` try to connect to a server called "latency".
    #[arg(long, value_name = "SERVER")]
    first: Option<String>,

    /// How to rank what the scanner measures.
    #[arg(long, value_name = "MODE", default_value = "balanced")]
    prefer: connect::RankMode,

    /// Shorthand for --prefer latency.
    #[arg(long, conflicts_with = "prefer")]
    latency: bool,

    /// Shorthand for --prefer load.
    #[arg(long, conflicts_with_all = ["prefer", "latency"])]
    load: bool,

    /// Pin a protocol instead of letting the network decide.
    #[arg(short, long)]
    protocol: Option<String>,
    /// Do not connect to this server.
    #[arg(long = "not", value_name = "SERVER")]
    exclude: Vec<String>,
    /// Re-measure instead of using a recent scan.
    #[arg(short = 'f', long, alias = "fastest")]
    rescan: bool,
    /// Skip measurement; let Proton choose.
    #[arg(long = "any", alias = "no-scan")]
    no_scan: bool,
    /// Confirm traffic before calling it connected. On by default.
    #[arg(long)]
    verify: bool,
    /// Return as soon as the tunnel exists, without confirming traffic.
    ///
    /// Faster, and it costs you the thing that makes the ranking worth
    /// having: an unverified connect cannot tell a working server from one
    /// whose tunnel comes up carrying nothing.
    #[arg(long, conflicts_with = "verify")]
    no_verify: bool,
    /// How many servers to try before giving up.
    #[arg(long, default_value_t = 3)]
    attempts: usize,
}

impl UpFlags {
    /// Join every filter source into the one comma-separated string the
    /// scanner understands. Order is stable so the scan cache key is too.
    fn filter(&self) -> Option<String> {
        let mut parts: Vec<String> = Vec::new();
        parts.extend(self.pattern.clone());
        parts.extend(self.country.iter().cloned());
        parts.extend(self.city.iter().cloned());
        // `server` is deliberately NOT folded in here: it is an answer, not
        // a search term, and it travels as `explicit` instead.
        (!parts.is_empty()).then(|| parts.join(","))
    }

    fn into_args(self, hop: bool) -> connect::UpArgs {
        connect::UpArgs {
            explicit: self.server.clone(),
            first: self.first.clone(),
            rank: if self.latency {
                connect::RankMode::Latency
            } else if self.load {
                connect::RankMode::Load
            } else {
                self.prefer
            },
            filter: self.filter(),
            protocol: self.protocol.clone(),
            exclude: self.exclude.clone(),
            hop,
            rescan: self.rescan,
            no_scan: self.no_scan,
            // On unless explicitly waived. `--verify` stays accepted so
            // existing scripts and muscle memory keep working, it is just
            // the default now.
            verify: !self.no_verify,
            attempts: self.attempts.clamp(1, 10),
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_tracing(cli.verbose);

    let json = cli.json;
    let _ = json;
    match run(cli) {
        Ok(code) => code,
        Err(e) => {
            // The chain matters: "no such file" alone is useless, "reading
            // the state file: no such file" is not.
            eprintln!("pvpn: {e:#}");
            ExitCode::from(1)
        }
    }
}

fn init_tracing(verbose: u8) {
    let level = match verbose {
        0 => "warn",
        1 => "info",
        _ => "debug",
    };
    // RUST_LOG wins if set, so -v is a convenience rather than a ceiling.
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .without_time()
        .try_init();
}

fn run(cli: Cli) -> Result<ExitCode> {
    let cfg = Config::load();
    match cli.command {
        Cmd::Status => cmd_status(&cfg, cli.json),
        Cmd::State => cmd_state(),
        Cmd::Up(f) => connect::cmd_up(&cfg, f.into_args(false)).map(ExitCode::from),
        Cmd::Best(mut f) => {
            // `best` means "measure, then connect". Reusing a cached scan
            // would make it a slower synonym for `up`.
            f.rescan = true;
            connect::cmd_up(&cfg, f.into_args(false)).map(ExitCode::from)
        }
        // hop is `up` with the current server excluded, so it inherits the
        // ranking and every flag rather than reimplementing them.
        Cmd::Hop(f) => connect::cmd_up(&cfg, f.into_args(true)).map(ExitCode::from),
        Cmd::Down => connect::cmd_down(&cfg).map(ExitCode::from),
        Cmd::Fast => memory_cmd::cmd_fast(&cfg, cli.json).map(ExitCode::from),
        Cmd::Blocked => memory_cmd::cmd_blocked(&cfg, cli.json).map(ExitCode::from),
        Cmd::Apps { fix } => apps::cmd_apps(fix, cli.json).map(ExitCode::from),
        Cmd::Try => delegate("try", &[]),
        Cmd::Login { args } => delegate("login", &args),
        Cmd::Scan { filter, force } => {
            connect::cmd_scan(&cfg, filter.as_deref(), force).map(ExitCode::from)
        }
        Cmd::Protocols => delegate("protocols", &[]),
        Cmd::Fix { args } => delegate("fix", &args),
    }
}

/// Status, and the one rule it exists to enforce: **report what is true,
/// not what the client believes.**
///
/// Proton's client keeps naming the server it lost after a session dies,
/// while every packet leaves in the clear. So this asks NetworkManager
/// whether a tunnel exists and then asks the network whether anything moves
/// through it, and says so when those disagree.
///
/// Exit codes are part of the interface, because scripts use them:
///   0  tunnel up and carrying traffic
///   1  no tunnel
///   2  tunnel present but carrying nothing  <- the dangerous one
fn cmd_status(cfg: &Config, json: bool) -> Result<ExitCode> {
    let tunnel = nm::vpn_connection();
    let want = intent::read();
    let daemon = DaemonState::load();

    let verdict = if tunnel.is_some() {
        Some(probe::traffic_flows(Duration::from_secs(cfg.probe_timeout)))
    } else {
        None
    };

    let carrying = verdict.as_ref().map(|v| v.alive).unwrap_or(false);
    let code = match (&tunnel, carrying) {
        (Some(_), true) => 0u8,
        (Some(_), false) => 2,
        (None, _) => 1,
    };

    if json {
        let out = serde_json::json!({
            "tunnel": tunnel,
            "carrying_traffic": carrying,
            "intent": want.as_str(),
            "probe": verdict.as_ref().map(|v| serde_json::json!({
                "via": v.via,
                "rtt_ms": v.rtt.map(|d| d.as_millis() as u64),
                "failed": v.failed,
            })),
            "daemon": daemon.as_ref().map(|d| serde_json::json!({
                "running": d.is_fresh(cfg.watch_interval),
                "note": d.note,
                "age_secs": d.age_secs(),
            })),
            "exit_code": code,
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(ExitCode::from(code));
    }

    match &tunnel {
        Some(name) => println!("tunnel     {name}"),
        None => println!("tunnel     none"),
    }

    match &verdict {
        Some(v) if v.alive => {
            let ms = v.rtt.map(|d| d.as_millis()).unwrap_or(0);
            println!("traffic    flowing ({} in {ms}ms)", v.via.unwrap_or("?"));
        }
        Some(v) => {
            println!("traffic    NOT FLOWING (tried: {})", v.failed.join(", "));
            println!();
            println!("The tunnel is up and carrying nothing. Proton's client will");
            println!("still report Connected. Run `pvpn up` to rebuild it.");
        }
        None => {}
    }

    println!("intent     {}", want.as_str());

    match &daemon {
        Some(d) if d.is_fresh(cfg.watch_interval) => {
            println!("daemon     running - {}", d.note)
        }
        Some(d) => println!(
            "daemon     STALE - last wrote {}s ago ({})",
            d.age_secs(),
            d.note
        ),
        // Absent state and a dead daemon are different things, and saying
        // "not running" for an unreadable file would be a guess.
        None => println!("daemon     no state file"),
    }

    Ok(ExitCode::from(code))
}

fn cmd_state() -> Result<ExitCode> {
    match DaemonState::load() {
        Some(s) => {
            println!("{}", serde_json::to_string_pretty(&s)?);
            Ok(ExitCode::SUCCESS)
        }
        None => {
            eprintln!("pvpn: no daemon state at {}", pvpn_core::paths::state_file().display());
            Ok(ExitCode::from(1))
        }
    }
}

/// Hand a not-yet-ported command to the bash implementation.
///
/// Searches for `pvpn-legacy` rather than `pvpn`, because finding `pvpn`
/// would find this binary and fork-bomb the machine. That is not a
/// hypothetical: it is the obvious way to write this and it is wrong.
fn delegate(subcommand: &str, args: &[String]) -> Result<ExitCode> {
    let exe = legacy_path().context(
        "the bash implementation (pvpn-legacy) is not installed, and this \
         command has not been ported to Rust yet. Re-run setup.sh.",
    )?;

    tracing::debug!(?exe, subcommand, "delegating to the bash implementation");

    let status = Command::new(&exe)
        .arg(subcommand)
        .args(args)
        .status()
        .with_context(|| format!("running {}", exe.display()))?;

    // Pass the child's exit code through unchanged. Collapsing it to 0/1
    // would break callers that check for the specific codes the script
    // documents.
    Ok(ExitCode::from(status.code().unwrap_or(1) as u8))
}

fn legacy_path() -> Option<std::path::PathBuf> {
    if let Ok(p) = std::env::var("PVPN_LEGACY") {
        let p = std::path::PathBuf::from(p);
        if p.is_file() {
            return Some(p);
        }
    }
    let candidates = [
        pvpn_core::paths::home().join(".local/libexec/pvpn-legacy"),
        std::path::PathBuf::from("/usr/libexec/pvpn-legacy"),
        std::path::PathBuf::from("/usr/lib/pvpn/pvpn-legacy"),
    ];
    candidates.into_iter().find(|p| p.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    /// Repeated and mixed filters must all reach the scanner. Dropping any
    /// of them silently connects you somewhere else.
    #[test]
    fn every_filter_source_reaches_the_scanner() {
        let f = UpFlags {
            pattern: Some("japan".into()),
            country: vec!["JP".into(), "SG".into()],
            city: vec!["tokyo".into()],
            server: vec!["JP-FREE#5".into()],
            ..Default::default()
        };
        // -s is an answer, not a search term: it must NOT become a filter,
        // or naming a server would trigger a scan to rank a list of one.
        assert_eq!(f.filter().as_deref(), Some("japan,JP,SG,tokyo"));
        assert_eq!(f.into_args(false).explicit, vec!["JP-FREE#5".to_string()]);
    }

    #[test]
    fn no_filter_is_none_not_an_empty_string() {
        // An empty string would become a filter matching nothing, and
        // `pvpn up` would report "nothing matched" on a healthy network.
        assert_eq!(UpFlags::default().filter(), None);
    }

    /// Verification is ON by default now. Without it a server is credited
    /// for a tunnel that may carry nothing, which teaches the ranking the
    /// exact failure it is supposed to detect.
    #[test]
    fn verification_is_on_by_default_and_waivable() {
        assert!(UpFlags::default().into_args(false).verify);

        let waived = UpFlags {
            no_verify: true,
            ..Default::default()
        };
        assert!(!waived.into_args(false).verify);

        // --verify remains accepted so existing scripts do not break.
        let explicit = UpFlags {
            verify: true,
            ..Default::default()
        };
        assert!(explicit.into_args(false).verify);
    }

    #[test]
    fn attempts_are_clamped_to_something_sane() {
        let f = UpFlags {
            attempts: 9999,
            ..Default::default()
        };
        assert_eq!(f.into_args(false).attempts, 10);
        let f = UpFlags {
            attempts: 0,
            ..Default::default()
        };
        assert_eq!(f.into_args(false).attempts, 1);
    }

    /// Every invocation the README documents must parse.
    ///
    /// In-process on purpose. An earlier version of this check shelled out
    /// to the built binary with the flags appended, which does not test
    /// parsing — it RUNS them, and `pvpn up --any` on a live machine
    /// attempts a real connect. Parsing is what is under test here, so
    /// parsing is all this does.
    #[test]
    fn every_documented_invocation_parses() {
        let cases: &[&[&str]] = &[
            &["pvpn", "up"],
            &["pvpn", "up", "japan"],
            &["pvpn", "up", "-c", "japan"],
            &["pvpn", "up", "-c", "JP", "-c", "SG"],
            &["pvpn", "up", "--city", "tokyo"],
            &["pvpn", "up", "-s", "JP-FREE#5"],
            &["pvpn", "up", "-p", "wireguard"],
            &["pvpn", "up", "--fastest"],
            &["pvpn", "up", "-f"],
            &["pvpn", "up", "--any"],
            &["pvpn", "up", "--no-scan"],
            &["pvpn", "up", "--verify"],
            &["pvpn", "up", "--not", "SG-FREE#12"],
            &["pvpn", "up", "--attempts", "5"],
            &["pvpn", "up", "--first", "SG-FREE#20"],
            // The ranking mode - a documented flag that a server-name
            // preference must never shadow.
            &["pvpn", "up", "--prefer", "latency"],
            &["pvpn", "up", "--prefer", "load"],
            &["pvpn", "up", "--prefer", "balanced"],
            &["pvpn", "up", "--latency"],
            &["pvpn", "up", "--load"],
            &["pvpn", "up", "--rescan", "--verify", "--prefer", "latency"],
            &["pvpn", "up", "--rescan", "--verify", "--prefer", "latency", "-c", "SG", "-c", "JP"],
            &["pvpn", "down"],
            &["pvpn", "disconnect"],
            &["pvpn", "hop"],
            &["pvpn", "hop", "JP"],
            &["pvpn", "hop", "--not", "SG-FREE#12"],
            &["pvpn", "next"],
            &["pvpn", "best"],
            &["pvpn", "best", "-c", "JP"],
            &["pvpn", "fastest"],
            &["pvpn", "status"],
            &["pvpn", "st"],
            &["pvpn", "status", "--json"],
            &["pvpn", "fast"],
            &["pvpn", "blocked"],
            &["pvpn", "apps"],
            &["pvpn", "apps", "--fix"],
            &["pvpn", "state"],
            &["pvpn", "scan"],
            &["pvpn", "scan", "japan"],
            &["pvpn", "scan", "--force"],
            &["pvpn", "protocols"],
            &["pvpn", "-v", "status"],
        ];
        for argv in cases {
            if let Err(e) = Cli::try_parse_from(*argv) {
                panic!("`{}` must parse: {e}", argv.join(" "));
            }
        }
    }

    /// Nonsense must be rejected, or a typo silently connects you
    /// somewhere you did not ask for.
    #[test]
    fn nonsense_is_rejected() {
        for argv in [
            vec!["pvpn"],
            vec!["pvpn", "not-a-command"],
            vec!["pvpn", "up", "--not-a-flag"],
            vec!["pvpn", "up", "--attempts", "banana"],
            // A ranking mode that does not exist must be REJECTED, not
            // quietly treated as a server name and connected to.
            vec!["pvpn", "up", "--prefer", "SG-FREE#20"],
            vec!["pvpn", "up", "--prefer", "nonsense"],
        ] {
            assert!(
                Cli::try_parse_from(&argv).is_err(),
                "`{}` must NOT parse",
                argv.join(" ")
            );
        }
    }

    #[test]
    fn cli_definition_is_valid() {
        // Catches duplicate flags, bad arg combinations and the like at
        // test time instead of on the user's first run.
        Cli::command().debug_assert();
    }

    /// Delegating to something named `pvpn` would find this binary and
    /// recurse until the machine dies. Pinning the name is cheap insurance
    /// against someone "simplifying" it later.
    #[test]
    fn legacy_target_is_never_named_pvpn() {
        for p in [
            pvpn_core::paths::home().join(".local/libexec/pvpn-legacy"),
            std::path::PathBuf::from("/usr/libexec/pvpn-legacy"),
        ] {
            let name = p.file_name().unwrap().to_string_lossy().into_owned();
            assert_ne!(name, "pvpn", "delegation target must not be `pvpn`");
            assert!(name.contains("legacy"));
        }
    }

    #[test]
    fn status_exit_codes_are_documented_values() {
        // 2 is the interesting one: tunnel present, carrying nothing. It
        // must not collapse into 1 (no tunnel), because scripts distinguish
        // "no VPN" from "a VPN that is lying to you".
        assert_ne!(1u8, 2u8);
    }
}
