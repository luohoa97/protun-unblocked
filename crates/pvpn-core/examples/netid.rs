fn main() {
    let ssid = pvpn_core::net::wifi_ssid();
    let gw = pvpn_core::net::default_gateway();
    let mac = gw.as_deref().and_then(pvpn_core::net::gateway_mac);
    println!("  ssid         {ssid:?}");
    println!("  gateway      {gw:?}");
    println!("  gateway mac  {mac:?}");
    println!("  network_id   {}", pvpn_core::net::network_id());
}
