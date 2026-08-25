//! Read-only: how often does a TLS session to a VPN entry IP survive?
//! Connects to port 443 and speaks TLS. Changes nothing.
use std::time::{Duration, Instant};
fn main() {
    let host = std::env::args().nth(1).unwrap_or("103.216.221.74".into());
    let n: usize = std::env::args().nth(2).and_then(|s| s.parse().ok()).unwrap_or(6);
    println!("probing {host}:443 x{n}\n");
    let mut ok = 0;
    for i in 1..=n {
        let t = Instant::now();
        let p = pvpn_core::tls::probe(&host, 443, Duration::from_secs(5));
        if p.outcome.usable() { ok += 1; }
        println!(
            "  {i}. {:<34} {:>6}ms  {}",
            p.outcome.as_str(),
            t.elapsed().as_millis(),
            p.detail.as_deref().unwrap_or("")
        );
        std::thread::sleep(Duration::from_millis(300));
    }
    println!("\n  {ok}/{n} sessions survived");
}
