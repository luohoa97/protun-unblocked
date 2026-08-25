//! `pvpn fast` and `pvpn blocked` — what this network taught us.
//!
//! Both exist because the answer to "why did it pick that server" should
//! not require reading a JSON file. A tool that learns silently is a tool
//! you cannot debug when it learns something wrong.

use anyhow::Result;
use pvpn_core::{config::Config, learn::NetworkMemory, net};

pub fn cmd_fast(cfg: &Config, json: bool) -> Result<u8> {
    let network = net::network_id();
    let memory = NetworkMemory::load(&network);
    let rows = memory.fast(cfg.blocked_retry_after_hours);

    if json {
        let out: Vec<_> = rows
            .iter()
            .map(|(name, r)| {
                serde_json::json!({
                    "server": name,
                    "latency_ms": r.latency_ms,
                    "ok": r.ok,
                    "failed": r.failed,
                    "success_rate": r.success_rate(),
                    "score": r.score(),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(0);
    }

    if rows.is_empty() {
        println!("Nothing measured on this network yet ({network}).");
        println!("Run:  pvpn best     (or just `pvpn up`, which measures first)");
        return Ok(0);
    }

    println!("Measured on {network}:\n");
    println!("  {:<18} {:>7}  {:>9}  {}", "SERVER", "TLS", "CONNECTS", "");
    for (name, r) in rows {
        let latency = r
            .latency_ms
            .map(|ms| format!("{ms}ms"))
            .unwrap_or_else(|| "-".into());
        // "connects" is the column that separates this from a plain
        // latency table, and it is the one that actually predicts whether
        // a connect will work here.
        let connects = match r.attempts() {
            0 => "untried".to_string(),
            _ => format!("{}/{}", r.ok, r.attempts()),
        };
        let flag = if r.intercepted { "  intercepted" } else { "" };
        println!("  {name:<18} {latency:>7}  {connects:>9}{flag}");
    }
    Ok(0)
}

pub fn cmd_blocked(cfg: &Config, json: bool) -> Result<u8> {
    let network = net::network_id();
    let memory = NetworkMemory::load(&network);
    let now = pvpn_core::intent::now_secs();
    let rows = memory.blocked(cfg.blocked_retry_after_hours);

    if json {
        let out: Vec<_> = rows
            .iter()
            .map(|(name, r)| {
                serde_json::json!({
                    "server": name,
                    "why": r.last_error,
                    "strikes": r.block_strikes,
                    "retry_in_secs": r.unblocks_in(cfg.blocked_retry_after_hours, now),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(0);
    }

    if rows.is_empty() {
        println!("Nothing blocked on this network ({network}).");
        return Ok(0);
    }

    println!("Blocked on {network}:\n");
    for (name, r) in rows {
        let retry = r
            .unblocks_in(cfg.blocked_retry_after_hours, now)
            .map(human_duration)
            .unwrap_or_else(|| "now".into());
        println!("  {name}");
        println!(
            "      {}",
            r.last_error.as_deref().unwrap_or("failed to connect")
        );
        println!("      retry in {retry}  (strike {})", r.block_strikes);
    }
    Ok(0)
}

/// Round durations for humans. Nobody needs "retry in 84291 seconds".
fn human_duration(secs: u64) -> String {
    if secs < 90 {
        format!("{secs}s")
    } else if secs < 5400 {
        format!("{}m", (secs + 30) / 60)
    } else if secs < 172_800 {
        format!("{}h", (secs + 1800) / 3600)
    } else {
        format!("{}d", (secs + 43_200) / 86_400)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_read_naturally() {
        assert_eq!(human_duration(30), "30s");
        assert_eq!(human_duration(300), "5m");
        assert_eq!(human_duration(7200), "2h");
        assert_eq!(human_duration(86_400 * 3), "3d");
    }

    /// The boundaries are where rounding produces silly output like "90m"
    /// or "0h", so they are pinned.
    #[test]
    fn duration_boundaries_do_not_produce_nonsense() {
        assert_eq!(human_duration(89), "89s");
        assert_eq!(human_duration(90), "2m");
        assert_eq!(human_duration(5399), "90m");
        assert_eq!(human_duration(5400), "2h");
        assert!(!human_duration(0).is_empty());
    }
}
