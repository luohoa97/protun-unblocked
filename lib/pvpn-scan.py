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
"""Rank Proton free servers by measured latency, probing in parallel.

You cannot connect to two VPN servers at once. A connect rewrites the
default route, DNS and the kill-switch device, there is one routing table,
and Proton's own NetworkManager plugin declares
`supports-multiple-connections=false`. So this probes every candidate
*concurrently* without connecting, and pvpn then makes one connect to the
winner.

Why TLS handshake time and not TCP connect time:

    On a filtered network a middlebox completes the TCP handshake locally.
    Measured from Australia it reported 1.6ms to a US server and 2.0ms to
    the Netherlands - physically impossible. TCP timing is worthless here.

    A TLS handshake cannot be faked by that middlebox; it has to reach the
    real server. Measured on the same hosts: Tokyo 454ms, US 756ms,
    Netherlands 1464ms - ordering correctly by distance.

Caveat, stated plainly: a TLS handshake is roughly 2-3 round trips plus the
server's crypto work, so these numbers are NOT ping. They are a
comparable-between-servers proxy for it. Server load inflates them too,
which is a feature - a loaded server is a bad pick regardless of distance.
We take the best of several samples, because a single sample is badly
noisy: one early measurement put Singapore at 1358ms where the ranked scan
consistently shows ~200ms.
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

# Country name -> ISO code, so "japan" works as well as "JP". Only the
# countries Proton actually offers free servers in are worth listing.
ALIASES = {
    "JAPAN": "JP",
    "NETHERLANDS": "NL", "HOLLAND": "NL", "DUTCH": "NL",
    "USA": "US", "AMERICA": "US", "UNITED STATES": "US",
    "POLAND": "PL", "ROMANIA": "RO", "SINGAPORE": "SG",
    "NORWAY": "NO", "MEXICO": "MX", "CANADA": "CA",
    "SWITZERLAND": "CH", "SWISS": "CH",
}


def matches(server, pattern):
    """Does this server match the filter?

    Compares against name, exit country and city, so all of these select
    the same Tokyo servers:

        JP          country code (also the name prefix)
        japan       country name, via ALIASES
        tokyo       city
        JP-FREE#1   one exact server

    Comma-separated patterns are OR-ed:  "JP,SG"  or  "japan,singapore".
    """
    if not pattern:
        return True

    name = (server.get("Name") or "").upper()
    country = (server.get("ExitCountry") or "").upper()
    city = (server.get("City") or "").upper()

    for raw in pattern.upper().split(","):
        want = raw.strip()
        if not want:
            continue
        # A country NAME must match the country field exactly. Matching it
        # loosely would let "canada" hit an unrelated city substring.
        code = ALIASES.get(want)
        if code is not None:
            if country == code:
                return True
            continue
        if want in name or want == country or want in city:
            return True
    return False


def candidates(pattern=""):
    if not CACHE.is_file():
        sys.exit("no cached server list - run `pvpn up` once first")
    data = json.loads(CACHE.read_text())
    key = "LogicalServers" if "LogicalServers" in data else "Servers"
    out, seen = [], set()
    for s in data[key]:
        name = (s.get("Name") or "").upper()
        # Free accounts can only reach FREE servers; Status 0 means offline.
        if "FREE" not in name or s.get("Status") != 1:
            continue
        if not matches(s, pattern):
            continue
        for srv in s.get("Servers", []):
            ip = srv.get("EntryIP")
            if ip and ip not in seen:
                seen.add(ip)
                out.append((s.get("Name"), ip, s.get("Load"), s.get("City")))
                break
    return out


def probe(entry, samples=2, timeout=6.0):
    name, ip, load, city = entry
    best = None
    for _ in range(samples):
        try:
            sock = socket.create_connection((ip, 443), timeout=timeout)
        except Exception:
            return (name, ip, load, city, None)
        try:
            t0 = time.monotonic()
            # SNI is required: without it Proton's endpoint never completes
            # the handshake, which earlier looked like network blocking.
            tls = _ctx.wrap_socket(sock, server_hostname="www.google.com")
            elapsed = (time.monotonic() - t0) * 1000
            tls.close()
            best = elapsed if best is None else min(best, elapsed)
        except Exception:
            try:
                sock.close()
            except Exception:
                pass
            return (name, ip, load, city, None)
    return (name, ip, load, city, best)


def score(ms, load):
    """Lower is better. Latency, penalised by how busy the server is.

    load is 0-100. At 0% the score is the raw latency; at 100% it is
    doubled. So load only ever reorders servers that are close in latency,
    which is the intent - it should break ties, not override geography.
    """
    if load is None or load < 0:
        load = 50
    return ms * (1.0 + load / 100.0)


def main():
    ap = argparse.ArgumentParser(
        description="Rank Proton free servers by measured latency.",
        epilog="filters: JP | japan | tokyo | JP-FREE#1 | 'JP,SG'",
    )
    ap.add_argument("pattern", nargs="?", default="")
    ap.add_argument("--samples", type=int, default=2)
    ap.add_argument("--workers", type=int, default=24)
    ap.add_argument("--top", type=int, default=10)
    ap.add_argument("--rank", choices=("score", "latency"), default="score",
                    help="score (default) weights latency by server load; "
                         "latency sorts on the raw handshake time")
    ap.add_argument("--limit", type=int, default=80,
                    help="probe at most this many, lowest reported load first")
    ap.add_argument("--quiet", action="store_true", help="print only the winner")
    ap.add_argument("--json", action="store_true",
                    help="machine-readable results, for the GUI")
    ap.add_argument("--names", action="store_true",
                    help="list matching server names without probing; "
                         "`pvpn hop` uses this so both share one matcher")
    args = ap.parse_args()

    cand = candidates(args.pattern)
    if not cand:
        sys.exit(f"no free servers match {args.pattern!r}")

    if args.names:
        for c in cand:
            print(c[0])
        return

    cand.sort(key=lambda c: c[2] if c[2] is not None else 99)
    cand = cand[: args.limit]

    if not args.quiet:
        print(f"  probing {len(cand)} servers, {args.samples} samples each, "
              f"{args.workers} at a time...", file=sys.stderr)

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        results = list(ex.map(lambda c: probe(c, args.samples), cand))

    if args.rank == "latency":
        live = sorted([r for r in results if r[4] is not None], key=lambda r: r[4])
    else:
        live = sorted([r for r in results if r[4] is not None],
                      key=lambda r: score(r[4], r[2]))
    dead = [r for r in results if r[4] is None]

    if not live:
        sys.exit("no server completed a TLS handshake - "
                 "is this network blocking Proton?")

    if args.json:
        json.dump([
            {"name": n, "ip": ip, "load": load, "city": city,
             "ms": round(ms, 1), "score": round(score(ms, load), 1)}
            for n, ip, load, city, ms in live
        ], sys.stdout)
        return

    if args.quiet:
        print(live[0][0])
        return

    print("\n  {:16} {:14} {:>9}  {:>5}".format("server", "city", "latency", "load"))
    print("  {} {} {}  {}".format("-" * 16, "-" * 14, "-" * 9, "-" * 5))
    for name, ip, load, city, ms in live[: args.top]:
        shown_load = "{}%".format(load) if load is not None else "?"
        print("  {:16} {:14} {:7.0f}ms  {:>5}".format(
            name, (city or "?")[:14], ms, shown_load))

    print("\n  {} reachable, {} unreachable".format(len(live), len(dead)))
    print("  best: {} in {} ({:.0f}ms)".format(
        live[0][0], live[0][3] or "?", live[0][4]))
    print("\n  latency = TLS handshake (~2-3 round trips + server crypto),")
    print("  not ping. Comparable between servers, not an absolute figure.")


if __name__ == "__main__":
    main()
