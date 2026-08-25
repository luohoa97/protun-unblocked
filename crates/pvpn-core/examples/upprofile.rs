//! Times every phase of `pvpn up` EXCEPT the activation. Read-only:
//! it connects nothing and disconnects nothing.
use std::time::Instant;

macro_rules! phase {
    ($name:expr, $body:expr) => {{
        let t = Instant::now();
        let v = $body;
        println!("  {:<34} {:>8.1}ms", $name, t.elapsed().as_secs_f64() * 1000.0);
        v
    }};
}

fn main() {
    let total = Instant::now();
    println!("phases of `pvpn up --server SG-FREE#20`:\n");

    let _ = phase!("Config::load()", pvpn_core::config::Config::load());
    let _ = phase!("proton::is_connected()  [dbus]", pvpn_core::proton::is_connected());
    let _ = phase!("proton::protocol_available()", pvpn_core::proton::protocol_available("protun-tls"));
    let _ = phase!("proton::current_protocol()", pvpn_core::proton::current_protocol());
    let _ = phase!("proton::steering_available()", pvpn_core::proton::steering_available());
    let _ = phase!("intent::read()", pvpn_core::intent::read());
    let net = phase!("net::network_id()", pvpn_core::net::network_id());
    let _ = phase!("NetworkMemory::load()", pvpn_core::learn::NetworkMemory::load(&net));
    let _ = phase!("dbus::find_tunnel_profile()", pvpn_core::dbus::find_tunnel_profile("SG-FREE#20"));

    println!("\n  {:<34} {:>8.1}ms", "TOTAL (excl. activation)", total.elapsed().as_secs_f64() * 1000.0);
    println!("\n  for comparison:");
    let t = Instant::now();
    let _ = std::process::Command::new("protonvpn").arg("--help").output();
    println!("  {:<34} {:>8.1}ms", "protonvpn --help (startup only)", t.elapsed().as_secs_f64() * 1000.0);
}
