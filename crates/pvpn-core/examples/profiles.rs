//! Read-only: what saved profiles exist, and how fast we can find one.
//! Activates NOTHING.
use std::time::Instant;
fn main() {
    let t = Instant::now();
    let ps = pvpn_core::dbus::saved_profiles();
    println!("saved profiles ({:?}):", t.elapsed());
    for p in &ps {
        println!("  {:<28} {:<12} {}", p.id, p.kind, if p.is_tunnel() { "TUNNEL" } else { "" });
    }
    for want in ["SG-FREE#20", "156.47.78.177", "JP-FREE#999"] {
        let t = Instant::now();
        let hit = pvpn_core::dbus::find_tunnel_profile(want);
        println!("\nlookup {want:<16} -> {:?}  ({:?})", hit.map(|p| p.id), t.elapsed());
    }
}
