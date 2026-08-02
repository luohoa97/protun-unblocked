# pvpn

A wrapper around Proton VPN's Linux CLI that makes it usable on networks
which filter it — school, corporate, or public wifi — without stranding you
without internet when a connect fails.

```
pvpn up        connect          pvpn status   where am I exiting?
pvpn down      disconnect       pvpn try      try every protocol
pvpn login     sign in          vpn-check     will a VPN work on this wifi?
```

## Why this exists

Proton's own client works fine on an open network. On a filtered one it has
three problems that make it feel broken rather than blocked:

**1. It hijacks your routing before the tunnel is up.** `protonvpn connect`
installs a full-tunnel route the moment it *starts* connecting. If the tunnel
never comes up, every packet blackholes until it gives up ~2 minutes later.
Your browser just hangs. `pvpn` wraps this so a failure, a timeout, or Ctrl-C
always restores your normal routing.

**2. It spends 30 seconds calling an API it cannot reach.** Where Proton's API
domains are DNS-blocked, `connect` still tries to refresh two of them first:

```
/vpn/v1/logicals      -> "No working transports found"   15.0s
/vpn/v2/clientconfig  -> "No working transports found"   15.0s
CONN.CONNECT:START -> Connected                           0.3s
```

The tunnel takes **0.3 seconds**. The other 30 are `AutoTransport.TRANSPORT_TIMEOUT
= 15`, hit twice. Both refreshes are optional — the client proceeds with cached
data — so `lib/sitecustomize.py` lowers that to 2s via `PYTHONPATH`. **Measured:
40s → 10s.** Nothing outside pvpn's own subprocesses is affected.

**3. Its health checks obey your proxy.** If you export `HTTPS_PROXY`/`ALL_PROXY`,
naive checks measure the proxy rather than the tunnel — and a proxy's circuits
break the instant the tunnel takes over routing, so a working VPN looks dead.
Every check here uses `curl --noproxy '*'`.

## Install

```bash
git clone https://github.com/luohoa97/protun-unblocked.git && cd protun-unblocked && ./setup.sh
```

Installs only under `$HOME`. `./setup.sh --uninstall` removes it. You need
`proton-vpn-cli` and NetworkManager; setup.sh checks and tells you what's
missing. `tor` + `torsocks` are needed only if Proton's API is blocked where
you are.

## Usage

```bash
vpn-check          # is a VPN even possible on this network?
pvpn login         # once
pvpn up            # connect
```

`vpn-check` reports whether Proton's servers are reachable, whether UDP can
leave, and whether DNS is hijacked — so you know if the problem is the network
before you spend time on the client.

## What it handles

- **Slow settling — the big one.** Time until a tunnel passes its first
  packet, measured on three servers: **12s**, **>20s**, **>45s**. Every single
  tunnel that got written off as dead turned out to be alive moments later. So
  `PVPN_SETTLE` is 90s, and — more importantly — **running out of it no longer
  tears the tunnel down.** It keeps the connection, tells you traffic hasn't
  started, and leaves `pvpn down` to you. Discarding a slow tunnel costs a full
  reconnect and often lands on the same server anyway.
- **No server selection on free.** `--country`, `--random` and by-ID are all
  refused, and reconnecting is not random: **six consecutive attempts returned
  US-FREE#15.** `pvpn hop` gets around this by temporarily marking unwanted
  servers offline in Proton's local cache, then restoring it. Verified: Dallas
  → Singapore, and Dallas → Tokyo with `pvpn hop JP`, each on the first try.
- **Stray kill-switch.** Proton creates `pvpnksintrf0` while connecting even
  with the kill switch off. An interrupted connect can leave it behind,
  blackholing everything. `pvpn down` removes it explicitly.
- **Blocked API for login.** `pvpn login` routes account traffic through Tor,
  with a shim that forces aiohttp onto its threaded resolver — torsocks cannot
  proxy the UDP that `aiodns` uses, so lookups fail without it.

## Tuning

| variable | default | meaning |
|---|---|---|
| `PVPN_TIMEOUT` | 30 | seconds to wait for a tunnel |
| `PVPN_SETTLE` | 90 | grace period for traffic to start (exits as soon as traffic flows) |
| `PVPN_ATTEMPTS` | 3 | connect attempts (new server each time) |
| `PVPN_API_TIMEOUT` | 2 | Proton API transport timeout |
| `PVPN_FAST` | 0 | blackhole the API in `/etc/hosts` for the connect (needs sudo) |

## Limits — read before filing a bug

- **If the network drops your VPN's packets, nothing here helps.** Run
  `vpn-check`; if it says VPNs are blocked by address, that's the answer, on
  any OS.
- Free tier gives no server choice, so latency is luck.
- UDP-blocking networks kill WireGuard and OpenVPN-UDP. Stealth (`protun-tls`)
  rides TCP/443 and is the protocol that tends to survive.
- `PVPN_FAST=1` is the least-tested path — it edits `/etc/hosts` and removes
  its own block on exit, but verify `/etc/hosts` if it's ever killed with -9.

## License

MIT — see [LICENSE](LICENSE).
