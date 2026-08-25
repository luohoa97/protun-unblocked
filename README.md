# pvpn

A wrapper around Proton VPN's Linux CLI that makes it usable on networks
which filter it — school, corporate, or public wifi — without stranding you
without internet when a connect fails.

```
pvpn up        connect          pvpn status   where am I exiting?
pvpn down      disconnect       pvpn fast     what this network liked
pvpn hop       change server    pvpn blocked  what it refused, and why
pvpn best      rank and connect pvpn apps     what skips the tunnel?
pvpn login     sign in          vpn-check     will a VPN work on this wifi?
```

Unlike a one-shot script, it **remembers what this network taught it** — a
per-network record of which servers were quick, which refused, and how many
connects to each actually worked here. And `pvpnd` keeps the tunnel alive
when it dies silently, which it does more often than you would think.

## Layout

Rust workspace. `pvpn up`, `down`, `hop`, `best`, `status`, `fast`,
`blocked`, `apps` and `state` are Rust; `login`, `scan`, `try`,
`protocols` and `fix` still delegate to the bash implementation, installed
alongside as `pvpn-legacy`, while they are ported.

```
crates/pvpn-core   paths, config, intent, NetworkManager, probing, memory
crates/pvpn        the CLI
crates/pvpnd       the daemon
crates/pvpn-gui    GTK4 GUI (outside the workspace; built on demand)
lib/*.py           the Proton shim and the server scanner, still Python
```

The scanner stays Python on purpose. It probes ~70 servers concurrently by
TLS handshake and already encodes why TCP timing is worthless here — it
measured 1.6ms to a US server from Australia, which is physically
impossible, because a middlebox was completing the TCP handshake locally.
Rewriting a working, well-reasoned measurement tool would be motion, not
progress.

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

## Two installs: stable and development

The image ships a stable copy in `/usr`, and `~/.local` shadows it because
`~/.local/bin` comes first on `PATH`. So you can hack on it without
rebuilding an image, and without losing a working VPN if the checkout breaks.

```bash
./setup.sh --dev      # symlink the checkout: edits are live, no reinstall
./setup.sh            # normal copy install
pvpn version          # which one is running, and from where
```

`pvpn version` exists because "which one am I running?" has a real answer
worth printing:

```
pvpn
  running : ~/.local/bin/pvpn
            -> ~/Projects/pvpn/bin/pvpn  (DEV symlink - edits are live)
  helpers : ~/.local/share/pvpn  (user)
  system  : /usr/bin/pvpn  (installed, shadowed by the above)
  source  : ~/Projects/pvpn @ 3da0534-dirty
```

`--dev` matters more than it looks: a plain install *copies* the scripts, so
the copy silently drifts the moment you edit the repo — which is a very good
way to spend an hour debugging a fix you already made.

To fall back to the system copy, remove the links (`rm ~/.local/bin/pvpn`) or
run `/usr/bin/pvpn` directly. `PVPN_SHIM=/usr/share/pvpn` forces the system
helpers independently of which script you run.

## GUI

A libadwaita front-end, in Rust:

```bash
./setup.sh --gui
```

It is a thin shell over the CLI, not a reimplementation — connect, hop,
scan-and-pick-a-server, live status. All the awkward behaviour (restoring
routing on failure, waiting out slow tunnels, steering server choice) stays in
one place, so both front-ends inherit it and neither can drift from the other.

Commands run on worker threads and report back over an async channel: a connect
can take tens of seconds, and the window must not freeze meanwhile. Controls
disable while one is in flight, because a second connect would fight over the
same routing table.

Optional and skipped by default — it needs `cargo`, `gtk4-devel` and
`libadwaita-devel`, and the first build compiles the gtk4/libadwaita crates
(~1 minute). The CLI is fully functional without it.

### Flatpak

```bash
cd gui && flatpak-builder --user --install --force-clean build flatpak/dev.pvpn.Gui.yml
flatpak run dev.pvpn.Gui
```

Be clear-eyed about what this sandbox does. The GUI is a front-end for a
**host** service: `pvpn` drives NetworkManager over D-Bus, reads
`~/.cache/Proton`, and runs `torsocks`. None of that works inside a sandbox,
so every command goes out through `flatpak-spawn --host`, which requires
`--talk-name=org.freedesktop.Flatpak` — an escape hatch that runs host
commands with your full user privileges.

So it packages the app; it does not contain it. You still get a pinned
GNOME 50 runtime, read-only `$HOME`, and one-command install and removal —
but it is not a security boundary, and pretending otherwise would be worse
than not shipping it.

If `flatpak-builder` fails at the export step with *"AppStream Compose
binary ... was not found"*, Homebrew's `appstreamcli` is shadowing the
system one. Prefix with `PATH=/usr/bin:/usr/sbin:$PATH`.

## Install

```bash
git clone https://github.com/luohoa97/protun-unblocked.git && cd protun-unblocked && ./setup.sh
```

`setup.sh` detects **apt** (Debian/Ubuntu) or **dnf** (Fedora), installs
`proton-vpn-cli` + Tor/NetworkManager deps, then installs `pvpn` under `$HOME`
and walks you through `vpn-check` → `pvpn login` → `pvpn up`.

If `repo.protonvpn.com` is blocked, the Proton repo package and apt/dnf
refreshes for that host go through Tor automatically (`socks5h://127.0.0.1:9050`).

```bash
./setup.sh --no-wizard   # install only, skip login prompts
./setup.sh --uninstall   # remove ~/.local pvpn files
```

## Usage

```bash
vpn-check                 # is a VPN even possible on this network?
pvpn login                # once
pvpn up                   # fastest server it can reach
pvpn up -c japan          # fastest in Japan
pvpn up -c JP -c SG       # across several countries
pvpn up --city tokyo      # by city
pvpn up -s JP-FREE#5      # one exact server
pvpn up -p wireguard      # force a protocol
pvpn up --fastest         # re-measure before choosing
pvpn up --any             # skip ranking, let Proton choose
```

Repeated filters are OR-ed. Bare words still work (`pvpn up japan`), and
`hop` takes the same flags. Full list: `pvpn up --help`.

**`up` does not wait to confirm traffic.** It returns once the tunnel is up.
Confirming meant sitting in a probe loop for up to `PVPN_SETTLE` seconds
*after* the tunnel already existed, for information `pvpn status` gives in
about 0.3s — and the tunnel was kept either way, since every one written off
as dead turned out to be merely slow. Pass `--verify` if you want the wait.

`up` is the whole interface. It ranks servers and connects to the best one,
falling down the list if one will not come up, so there is no separate
"connect" / "pick a country" / "find the fastest" to remember.

Why rank at all: free accounts get whatever server Proton hands out, which
ignores geography — from Australia this connection was assigned Miami,
Dallas and Houston on consecutive attempts. Proton refuses `--country`,
`--random` and by-ID on the free tier, so `pvpn` steers by hiding the other
servers in the client's own cache.

Rankings are **cached per network** (`wifi-<ssid>`, or the gateway on
wired). Latency is a property of the path, so a ranking measured at school
is meaningless at home, and reusing it would be worse than not caching.

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

## The GNOME VPN switch works too

GNOME's quick-settings VPN toggle talks to NetworkManager, not to pvpn — so
before, the two could deadlock. You flick the switch off, NetworkManager
tears the tunnel down, `pvpnd` still reads `intent=up`, and puts it straight
back. The switch appeared broken.

`pvpnd` now watches NetworkManager and treats it as a second place you can
say what you want:

| You do this | pvpn does this |
| --- | --- |
| Switch the VPN **on** in GNOME | Adopts it — `intent=up`, keeps it alive like any tunnel it started |
| Switch it **off** in GNOME | Stands down — `intent=down`, no reconnect |
| Tunnel actually breaks | Reconnects, as before |

The last two are the hard part, because "you turned it off" and "it broke"
look identical to anything that only checks whether traffic flows. pvpnd
subscribes to NetworkManager's **D-Bus signals**, so it is told the exact
transition and NetworkManager's own reason code:

| NM reason | Meaning |
| --- | --- |
| `USER_DISCONNECTED` (2) | you did it — stand down |
| `CONNECTION_REMOVED` (11) | profile deleted — stand down |
| `LOGIN_FAILED` (10), timeouts, anything else | a fault — reconnect |

**This has to be signals, not polling, and the first version got it wrong.**
Polling samples *state*, and state cannot distinguish "this tunnel is here"
from "this tunnel is 30ms from being gone". A poll landed in the gap between
`pvpn down` writing `intent=down` and NetworkManager finishing the teardown,
saw a live tunnel with `intent=down`, concluded you must have switched it on
from GNOME, and adopted it back to `intent=up`. Autoreconnect did the rest,
and **the VPN would not stay off**. A signal carries the transition *and* the
reason, so that gap does not exist and nothing has to be inferred.

**Signals alone were still not enough.** NetworkManager's
`Connection.Active.StateChanged` is emitted by *every* active connection —
your wifi, `virbr0`, `waydroid0`, even loopback — not just tunnels. Tearing a
tunnel out re-activates the wifi underneath it, so `pvpn down` was promptly
followed by the *wifi* announcing `ACTIVATED`, on the same interface and with
the same state number a tunnel uses. pvpnd read that as "the user switched the
VPN on", set `intent=up`, and put the tunnel back. Subscribing to the right
interface is only half of it — the **sender** has to be checked too. pvpnd now
asks NetworkManager the type of the connection that spoke, and remembers which
object paths are tunnels so it can still recognise them on the way out, when
the object is already gone and can no longer be asked.

While `pvpn` is mid-connect it drops a marker at
`$XDG_RUNTIME_DIR/pvpn.busy`. `pvpn hop` legitimately produces a deliberate
disconnect followed by an activate, and acting on the first half would leave
you disconnected if the second half failed. pvpn writes intent itself for its
own commands, so ignoring its signals loses nothing. The marker expires after
two minutes, so a crashed `pvpn` can't mute the daemon permanently.

Receiving NM's broadcast signals needs **no root** — verified on this
machine, contrary to what `gdbus monitor` implies when
`DBUS_SYSTEM_BUS_ADDRESS` is unset (it reports "No such file or directory",
which reads like a permissions problem and is not one). `pvpnd` runs as you.

## Picking a fast server

```bash
pvpn scan          # rank every free server by measured latency
pvpn scan JP       # only Japanese ones
pvpn best          # scan, then connect to the fastest
pvpn best SG       # fastest Singapore server
```

**Probing is parallel; connecting cannot be.** A connect rewrites the default
route, DNS and the kill-switch device, and there is one routing table per
machine — two connects would corrupt each other. So `scan` opens concurrent
TLS handshakes to every candidate and times them, then `best` makes a single
connect to the winner. **80 servers in 10 seconds.**

It times the **TLS handshake**, not TCP connect, and that distinction matters
on a filtered network. Measured from Australia:

| server | TCP connect | TLS handshake |
|---|---|---|
| JP-FREE#1 (Tokyo) | 2.3ms | 454ms |
| US-FREE#50 | 1.6ms | 756ms |
| NL-FREE#1 (Netherlands) | 2.0ms | 1464ms |

TCP claims 1.6ms to the United States — impossible; the middlebox answers the
handshake locally. A TLS handshake has to reach the real server, so it can't be
faked, and it orders correctly by distance.

Latency shown is ~2–3 round trips plus the server's crypto work — **comparable
between servers, not an absolute ping**. Server load inflates it, which is
desirable: a loaded server is a bad pick regardless of distance.

## Tuning

| variable | default | meaning |
|---|---|---|
| `PVPN_TIMEOUT` | 30 | seconds to wait for a tunnel |
| `PVPN_SETTLE` | 90 | grace period for traffic to start (exits as soon as traffic flows) |
| `PVPN_ATTEMPTS` | 3 | connect attempts |
| `PVPN_SCAN_ARGS` | — | extra args for `scan`, e.g. `--samples 3 --limit 200` |
| `PVPN_API_TIMEOUT` | 2 | Proton API transport timeout |
| `PVPN_FAST` | 0 | blackhole the API in `/etc/hosts` for the connect (needs sudo) |

## Limits — read before filing a bug

- **If the network drops your VPN's packets, nothing here helps.** Run
  `vpn-check`; if it says VPNs are blocked by address, that's the answer, on
  any OS.
- Free tier gives no server choice, so latency is luck.
- UDP-blocking networks kill WireGuard and OpenVPN-UDP. Note that a network
  can block these without doing any deep packet inspection - the one this was
  built against filters by destination and by DNS name, and 69/70 Proton
  servers complete an ordinary TLS handshake on it
  (TCP connects, TLS handshake dies). **Stealth (`protun-tls`) is the default**
  and the protocol that survives — needs `python3-proton-vpn-lib` +
  `proton-vpn-linux` (NM protun plugin; currently in Proton unstable).
- `PVPN_FAST=1` is the least-tested path — it edits `/etc/hosts` and removes
  its own block on exit, but verify `/etc/hosts` if it's ever killed with -9.

## License

**GPL-3.0-or-later** — see [LICENSE](LICENSE).

Parts of this came from
[dixonSolutions/protun-unblocked](https://github.com/dixonSolutions/protun-unblocked)
under MIT, which is GPL-compatible. What was taken, from where, and under
what terms is recorded in [NOTICE.md](NOTICE.md).

This is copyleft. If you distribute this code, or anything derived from it,
you must:

- release it under GPL-3.0-or-later as well — you cannot make it closed source
- provide the complete corresponding **source**
- keep the copyright notices intact
- state what you changed

Note that this applies to *distribution*. Running it privately, or modifying it
for your own use, carries no obligation.

Versions released before commit `f77ec1e` were published under MIT. That grant
cannot be revoked for those copies — anyone who took the code under MIT keeps
MIT terms for that version. The copyleft applies from this commit onward.
