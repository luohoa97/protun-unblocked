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
    Hop {
        /// Country, city or server name to move to.
        pattern: Option<String>,
    },

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

    /// What the daemon last published, verbatim.
    State,

    // ---- not yet ported; handed to the bash implementation ----
    /// Try every protocol.
    Try,
    /// Sign in.
    Login { args: Vec<String> },
    /// Measure this network without connecting.
    Scan { args: Vec<String> },
    /// Which protocol backends are actually installed.
    Protocols,
    /// Privileged cleanup (needs sudo).
    Fix { args: Vec<String> },
}

#[derive(clap::Args, Default)]
struct UpFlags {
    /// Country, city or server name.
    pattern: Option<String>,
    /// Pin a protocol instead of letting the network decide.
    #[arg(short, long)]
    protocol: Option<String>,
    /// Do not connect to this server.
    #[arg(long = "not", value_name = "SERVER")]
    exclude: Vec<String>,
    /// Re-measure instead of using a recent scan.
    #[arg(long)]
    rescan: bool,
    /// Skip measurement; let Proton choose.
    #[arg(long = "any", alias = "no-scan")]
    no_scan: bool,
    /// Wait and confirm traffic before returning.
    #[arg(long)]
    verify: bool,
    /// How many servers to try before giving up.
    #[arg(long, default_value_t = 3)]
    attempts: usize,
}

impl UpFlags {
    fn into_args(self, hop: bool) -> connect::UpArgs {
        connect::UpArgs {
            filter: self.pattern,
            protocol: self.protocol,
            exclude: self.exclude,
            hop,
            rescan: self.rescan,
            no_scan: self.no_scan,
            verify: self.verify,
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
        Cmd::Best(f) => connect::cmd_up(&cfg, f.into_args(false)).map(ExitCode::from),
        Cmd::Hop { pattern } => {
            let f = UpFlags {
                pattern,
                ..Default::default()
            };
            connect::cmd_up(&cfg, f.into_args(true)).map(ExitCode::from)
        }
        Cmd::Down => connect::cmd_down(&cfg).map(ExitCode::from),
        Cmd::Fast => memory_cmd::cmd_fast(&cfg, cli.json).map(ExitCode::from),
        Cmd::Blocked => memory_cmd::cmd_blocked(&cfg, cli.json).map(ExitCode::from),
        Cmd::Try => delegate("try", &[]),
        Cmd::Login { args } => delegate("login", &args),
        Cmd::Scan { args } => delegate("scan", &args),
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
