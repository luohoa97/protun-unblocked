//! Read-only benchmark: what NetworkManager says, and how fast.
//! Touches nothing - property reads only.
use std::time::Instant;

fn main() {
    println!("dbus available: {}", pvpn_core::dbus::available());

    let t = Instant::now();
    let paths = pvpn_core::dbus::active_connection_paths();
    println!("active connections ({:?}):", t.elapsed());
    for p in &paths {
        println!(
            "  {p}  type={:?}  id={:?}",
            pvpn_core::dbus::connection_type(p),
            pvpn_core::dbus::connection_id(p)
        );
    }

    // The hot path: what the daemon asks every tick.
    let t = Instant::now();
    let vpn = pvpn_core::dbus::vpn_connection();
    let dbus_us = t.elapsed().as_micros();
    println!("\ndbus  vpn_connection() -> {vpn:?}   {dbus_us}us");

    let t = Instant::now();
    let vpn2 = pvpn_core::nm::vpn_connection();
    let nmcli_us = t.elapsed().as_micros();
    println!("nmcli vpn_connection() -> {vpn2:?}   {nmcli_us}us");

    println!(
        "\nspeedup: {:.0}x   ({}ms -> {}ms)",
        nmcli_us as f64 / dbus_us.max(1) as f64,
        nmcli_us / 1000,
        dbus_us / 1000
    );
    println!("agree: {}", vpn == vpn2);
}
