# The bar

What "better" has to mean here, stated so it can be checked rather than
argued about. Every criterion below has a measurement. Anything that cannot
be measured is an opinion and does not belong on this list.

## The disagreement that matters

The other implementation of this idea
([dixonSolutions/protun-unblocked](https://github.com/dixonSolutions/protun-unblocked),
MIT) removed its daemon on purpose. Its reasoning, from its own README:

> There used to be a daemon that rebuilt the tunnel whenever it decided one
> was missing. On a network that fails every connect it does not fail with
> you, it fails at you.

That is a fair description of a real failure — and it is the exact failure
this project shipped twice. Both times the daemon reconnected something the
user had deliberately turned off.

**We disagree with the conclusion, not the diagnosis.** A tunnel that dies
silently at 3am and stays dead until you notice is not a better outcome than
one that repairs itself; it is the same outcome with the work moved onto
you. The problem was never that a daemon acts. It was that it acted on a
*guess* about what you wanted.

So the bet is: **keep the daemon, and make it structurally incapable of
overriding you.** Intent is written, never inferred. That is the thing to be
better at, and criteria 1–4 exist to prove it.

## Criteria

### 1. The daemon never overrides an explicit instruction

`pvpn down` stays down. The GNOME toggle stays off. A failed hop does not
become a permanent disconnect.

**Measure:** an adversarial replay suite. A scripted D-Bus signal stream is
fed to the real daemon under a fake `gdbus`, and intent is asserted after
each scenario. Must include, at minimum: deliberate down; wifi re-activating
after a teardown; `LOGIN_FAILED`; a bridge flapping; a hop mid-flight; NM
restarting; a tunnel that was up before the daemon started.

**Target:** every scenario passes, and each historical regression has a
scenario named after it. **Now:** 3 scenarios. Both shipped bugs covered.

### 2. Distinguishing "you turned it off" from "it broke"

Anything that only checks whether traffic flows cannot tell these apart, and
guessing is what caused both regressions.

**Measure:** decisions are made from NetworkManager's own reason codes, and
from the sender's object path — never from inference. No code path may
change intent without a signal that positively identifies both.

**Target:** zero inference. Unrecognised input is inert, and covered by a
test that asserts inertness rather than a guess.

### 3. Recovery without you present

The failure this exists for: protun retries a WireGuard handshake that a
UDP-blocking network will never answer, while NM still shows the tunnel
activated and the client still says Connected. It looks perfect and carries
nothing.

**Measure:** time from tunnel death to a working tunnel, with nobody
watching. Measured across suspend/resume, wifi change, and silent session
loss.

**Target:** under 90s for the common cases, and never an infinite retry
without backoff. **Theirs:** unbounded — it waits for you to notice.

### 4. Cost of being always-on

A daemon earns its place only if you cannot feel it. An earlier version of
this one burned **4h41m of CPU over 20h13m** (~23% of a core) by spawning
Proton's Python client every 20 seconds.

**Measure:** `systemctl --user show pvpnd -p CPUUsageNSec` over 24h of real
use.

**Target:** under 2 minutes of CPU per 24h. **Now:** 51s per 10h and the
remaining cost is one `nmcli` call per tick. **Theirs:** zero, by not
existing — a real advantage we must keep paying down, not dismiss.

### 5. Honest status

A client that lost its session keeps naming the server it lost while every
packet leaves in the clear.

**Measure:** `pvpn status` inspects the routing table and the real exit
address, not what the client believes, and exits non-zero when they
disagree.

**Target:** parity with theirs — they do this and it is correct.

### 6. Learning the network you are on

Which servers this network lets through, which it refuses, and why. Latency
alone is not it: a fast TLS handshake does not prove a server works, because
some filters terminate TLS locally and close the session before any tunnel
data moves.

**Measure:** a per-network fast/blocked record that survives reboots; blocks
that expire and back off on repeat failure; ranking that times TLS rather
than TCP; and detection of interception rather than treating it as success.

**Target:** match theirs, then exceed it by recording **connect outcomes**
and not just handshake latency — the only evidence that actually predicts
whether a server will work here.

**Now: done.** A correction to an earlier version of this document, which
said TLS-timed ranking was unimplemented here: `lib/pvpn-scan.py` has
always done it, and records the same reasoning independently (it measured
1.6ms to a US server from Australia over TCP, which is physically
impossible, and switched to TLS). What was genuinely missing was
*persistence* — measurements died with the process.

`pvpn-core::learn` now keeps a per-network record: measured latency,
whether the peer looked like an interceptor, and how many connects to that
server have actually worked *here*. Ranking multiplies latency by a failure
penalty, so a server that handshakes in 50ms and fails 9 connects in 10
sorts below one at 120ms that always works — because the thing being
ordered is expected time to a *working tunnel*, not to a handshake.
Untried is deliberately distinct from always-fails, or we would never
discover a good server on a new network.

### 7. Apps that quietly leave the tunnel

A leftover Flatpak proxy override takes an app off the VPN with nothing in
`pvpn status` showing it.

**Measure:** detect overrides, fix them, and verify by comparing an app's
real exit address against the host's.

**Target:** match theirs. **Now:** not implemented. **Theirs:**
implemented. *Ahead of us.*

### 8. Tests

**Measure:** line count is not the metric; *kinds* of test are. Unit tests
for parsers; adversarial replay for the daemon; end-to-end runs against
fakes for anything that shells out; fixtures for ranking so results are
deterministic.

**Target:** every bug fixed gets a test that fails without the fix. No
exceptions — both regressions here reached a user because nothing would
have caught them. **Theirs:** ~1,545 lines, including a Rust-vs-Python
differential test on shared fixtures. That differential idea is good and
worth taking.

### 9. Nothing fails silently

Every branch that cannot determine an answer says so in the journal and
does nothing, rather than picking the likely option.

**Measure:** no `unwrap_or(false)` or equivalent on a path that can change
intent or tear down a tunnel, without a log line on the failure path.

**Target:** zero silent fallbacks in decision paths.

### 10. Survives its own bugs

A wedged daemon is worse than a crashed one: systemd restarts a crash.

**Measure:** a hung `pvpn up` is killed by timeout; a wedged main loop is
caught by a systemd watchdog; a dead signal-watcher thread is detected and
respawned rather than silently degrading to a timer.

**Target:** all three. **Now: all three done.**

- Reconnect is wrapped in coreutils `timeout`, which signals the whole
  process group — killing `pvpn` alone would leave Proton's Python client
  running and two connects racing.
- `WatchdogSec=300` with sd_notify spoken directly. Fed from the main loop,
  never a side thread: a side thread would keep reporting health while the
  loop was wedged, which is worse than having no watchdog at all.
- The watcher thread is supervised by its `JoinHandle`. The channel cannot
  detect its death — the daemon holds a `Sender`, so it never reports
  disconnected.

## Where they are ahead today

Stated plainly so it does not get quietly dropped:

- Flatpak app routing — criterion 7. Still not implemented here.
- Test *breadth*. Theirs is ~1,545 lines including a Rust-vs-Python
  differential run on shared fixtures; that differential idea is good and
  worth taking.

Closed since the first version of this document:

- Per-network learning — criterion 6, now implemented and arguably ahead,
  because outcomes are recorded and not just latency.
- Interception detection — criterion 6, `pvpn-core::tls`.
- The CLI is Rust. `up`, `down`, `hop`, `best`, `status`, `fast`, `blocked`
  and `state` are ported; `login`, `scan`, `try`, `protocols` and `fix`
  still delegate to the bash implementation.

## What we must not regress

- The daemon, and the NetworkManager/GNOME integration
- The GUI, the suspend hook, image and `ujust` integration
- Zero inference in decision paths (criterion 2)
- Idle CPU cost (criterion 4)
