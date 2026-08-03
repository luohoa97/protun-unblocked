# Copyright (C) 2026 Neil Luo
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation, either version 3 of the License, or (at your
# option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program. If not, see <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
"""Rank Proton free servers by measured latency, in parallel.

You cannot connect to two VPN servers at once - a connect rewrites the
default route, DNS and the kill-switch device, and there is one routing
table. So this probes every candidate *concurrently* without connecting,
then pvpn makes a single connect to the winner.

Why TLS handshake time and not TCP connect time:

    On a filtered network a middlebox completes the TCP handshake locally.
    Measured from Australia it reported 1.6ms to a US server and 2.0ms to
    the Netherlands - physically impossible. TCP timing is worthless here.

    A TLS handshake cannot be faked by that middlebox; it has to reach the
    real server. Measured on the same hosts: Tokyo 454ms, US 756ms,
    Netherlands 1464ms - which orders correctly by distance.

Caveat, stated plainly: a TLS handshake is roughly 2-3 round trips plus
the server's crypto work, so these numbers are NOT ping. They are a
comparable-between-servers proxy for it. Server load inflates them too,
which is a feature - a loaded server is a bad pick regardless of distance.
We take the best of several samples to blunt one-off noise.
"""
import argparse
import json
import pathlib
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor

CACHE = pathlib.Path.home() / ".cache/Proton/VPN/serverlist.json"

_ctx = ssl.create_default_context()
_ctx.check_hostname = False
_ctx.verify_mode = ssl.CERT_NONE


def candidates(pattern=""):
    if not CACHE.is_file():
        sys.exit("no cached server list - run `pvpn up` once first")
    data = json.loads(CACHE.read_text())
    key = "LogicalServers" if "LogicalServers" in data else "Servers"
    pattern = pattern.upper()
    out, seen = [], set()
    for s in data[key]:
        name = (s.get("Name") or "").upper()
        # Free accounts can only reach FREE servers; Status 0 means offline.
        if "FREE" not in name or s.get("Status") != 1:
            continue
        if pattern and pattern not in name:
            continue
        for srv in s.get("Servers", []):
            ip = srv.get("EntryIP")
            if ip and ip not in seen:
                seen.add(ip)
                out.append((s.get("Name"), ip, s.get("Load")))
                break
    return out


def probe(entry, samples=2, timeout=6.0):
    name, ip, load = entry
    best = None
    for _ in range(samples):
        try:
            sock = socket.create_connection((ip, 443), timeout=timeout)
        except Exception:
            return (name, ip, load, None)
        try:
            t0 = time.monotonic()
            # SNI is required: without it Proton's endpoint does not complete
            # the handshake at all, which earlier looked like network blocking.
            tls = _ctx.wrap_socket(sock, server_hostname="www.google.com")
            elapsed = (time.monotonic() - t0) * 1000
            tls.close()
            best = elapsed if best is None else min(best, elapsed)
        except Exception:
            try:
                sock.close()
            except Exception:
                pass
            return (name, ip, load, None)
    return (name, ip, load, best)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pattern", nargs="?", default="")
    ap.add_argument("--samples", type=int, default=2)
    ap.add_argument("--workers", type=int, default=24)
    ap.add_argument("--top", type=int, default=10)
    ap.add_argument("--limit", type=int, default=80,
                    help="probe at most this many, lowest reported load first")
    ap.add_argument("--quiet", action="store_true", help="print only the winner")
    args = ap.parse_args()

    cand = candidates(args.pattern)
    if not cand:
        sys.exit(f"no free servers match {args.pattern!r}")
    cand.sort(key=lambda c: c[2] if c[2] is not None else 99)
    cand = cand[: args.limit]

    if not args.quiet:
        print(f"  probing {len(cand)} servers, {args.samples} samples each, "
              f"{args.workers} at a time...", file=sys.stderr)

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        results = list(ex.map(lambda c: probe(c, args.samples), cand))

    live = sorted([r for r in results if r[3] is not None], key=lambda r: r[3])
    dead = [r for r in results if r[3] is None]

    if not live:
        sys.exit("no server completed a TLS handshake - is this network blocking Proton?")

    if args.quiet:
        print(live[0][0])
        return

    print(f"\n  {'server':16} {'latency':>9}  {'load':>5}   ip")
    print(f"  {'-'*16} {'-'*9}  {'-'*5}   {'-'*15}")
    for name, ip, load, ms in live[: args.top]:
        print(f"  {name:16} {ms:7.0f}ms  {load if load is not None else '?':>4}%   {ip}")
    print(f"\n  {len(live)} reachable, {len(dead)} unreachable")
    print(f"  best: {live[0][0]}  ({live[0][3]:.0f}ms)")
    print("\n  latency = TLS handshake (~2-3 round trips + server crypto),")
    print("  not ping. Comparable between servers, not an absolute figure.")


if __name__ == "__main__":
    main()
