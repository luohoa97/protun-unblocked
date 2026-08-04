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

"""Make Proton's client workable on filtered networks.

Python imports `sitecustomize` automatically at interpreter startup if it is
on sys.path. pvpn puts this directory on PYTHONPATH, so it applies only to
the commands pvpn launches - nothing else on the system is affected.

Patches:
  1. Fail API refreshes fast when Proton domains are blocked
     (TRANSPORT_TIMEOUT 15s → PVPN_API_TIMEOUT, default 2).
  2. Prefer OpenVPN TCP/443 only — default ports are [443, 7770, 8443]
     with remote-random; school wifi often blocks 7770, and the CLI's
     10s CONNECTED wait expires before OpenVPN can try the next port.
  3. Raise the CLI's wait-for-CONNECTED timeout (10s → PVPN_EVENT_TIMEOUT,
     default 45) so a real handshake has time to finish.
"""
import os
from contextlib import asynccontextmanager


# --- 1. Fast-fail blocked API refreshes ---------------------------------
try:
    from proton.session.transports.auto import AutoTransport

    _t = float(os.environ.get("PVPN_API_TIMEOUT", "2"))
    AutoTransport.TRANSPORT_TIMEOUT = _t

    # The transport list is [(0, Aiohttp), (5, AlternativeRouting)] - the
    # number is a head-start delay before that transport is tried. A 5s
    # delay is pointless once the whole budget is ~2s, so compress it too.
    _orig_init = AutoTransport.__init__

    def _patched_init(self, session, transport_choices=None, transport_timeout=None):
        _orig_init(self, session, transport_choices, transport_timeout or _t)
        try:
            self._transport_choices = [
                (min(delay, _t / 2), cls) for delay, cls in self._transport_choices
            ]
        except Exception:
            pass

    AutoTransport.__init__ = _patched_init

except Exception:
    # Never break the interpreter over this. If proton-core moves or renames
    # things, we simply fall back to the stock 15s behaviour.
    pass


# --- 2. OpenVPN TCP: only ports that look like HTTPS --------------------
# Override with e.g. PVPN_OPENVPN_TCP_PORTS=443,8443
try:
    from proton.vpn.session.dataclasses.client_config import ProtocolPorts
    from proton.vpn.session import client_config as _cc

    _tcp_raw = os.environ.get("PVPN_OPENVPN_TCP_PORTS", "443")
    _tcp_ports = [int(p.strip()) for p in _tcp_raw.split(",") if p.strip()] or [443]

    _orig_cc_from_dict = _cc.ClientConfig.from_dict.__func__

    @classmethod
    def _patched_cc_from_dict(cls, apidata: dict):
        cfg = _orig_cc_from_dict(cls, apidata)
        cfg.openvpn_ports = ProtocolPorts(
            udp=list(cfg.openvpn_ports.udp),
            tcp=list(_tcp_ports),
            tls=list(cfg.openvpn_ports.tls or []),
        )
        return cfg

    _cc.ClientConfig.from_dict = _patched_cc_from_dict

    # Cold-start default (used when cache is missing / corrupt).
    try:
        _cc.DEFAULT_CLIENT_CONFIG["DefaultPorts"]["OpenVPN"]["TCP"] = list(_tcp_ports)
    except Exception:
        pass

except Exception:
    pass


# --- 3. Longer wait for CONNECTED ---------------------------------------
try:
    import proton.vpn.cli.core.controller as _ctrl

    _event_t = float(os.environ.get("PVPN_EVENT_TIMEOUT", "45"))
    _orig_wait = _ctrl._wait_for_event

    @asynccontextmanager
    async def _patched_wait_for_event(
        connector,
        event_types=None,
        timeout=None,
        wait_for_new_connection=False,
    ):
        # Callers omit timeout (stock default 10). Bump that default.
        if timeout is None or timeout == 10:
            timeout = _event_t
        async with _orig_wait(
            connector,
            event_types,
            timeout=timeout,
            wait_for_new_connection=wait_for_new_connection,
        ):
            yield

    _ctrl._wait_for_event = _patched_wait_for_event

except Exception:
    pass

# --- 4. In-memory server steering ---------------------------------------
#
# A free Proton account cannot choose its server: --country, --random and
# by-ID are all refused. The only lever is which servers the client believes
# are online, and the obvious way to pull it is to edit the cached
# serverlist.json.
#
# Do NOT do that. Editing it means the user's real cache is mutated, so a
# crash between "hide the others" and "put them back" leaves the Proton
# client permanently convinced most of the network is offline, with nothing
# to explain why. Backups, markers and traps only narrow that window; they
# cannot close it, and a SIGKILL beats all of them.
#
# So this is an OVERRIDE instead of a write. ServerList.from_dict is the one
# funnel every load passes through - cache reads and fresh API responses
# alike - so filtering there applies our choice in memory, for the lifetime
# of one process, while the file on disk is never touched. A crash simply
# means the override stops applying. There is nothing to clean up and
# nothing to corrupt.
#
#   PVPN_ONLY="JP-FREE#5,JP-FREE#8"   treat only these as online
#   PVPN_EXCLUDE="US-FREE#15"         treat these as offline
try:
    from proton.vpn.session.servers.logicals import ServerList

    _only = {n.strip().upper() for n in os.environ.get("PVPN_ONLY", "").split(",") if n.strip()}
    _excl = {n.strip().upper() for n in os.environ.get("PVPN_EXCLUDE", "").split(",") if n.strip()}

    if _only or _excl:
        _orig_from_dict = ServerList.from_dict.__func__

        @classmethod
        def _steered_from_dict(cls, data):
            try:
                rows = data.get("LogicalServers")
                if isinstance(rows, list):
                    kept = 0
                    # Copy the row dicts we change, so we never mutate the
                    # caller's structure - it may be the parsed cache that
                    # something else still holds a reference to.
                    new_rows = []
                    for row in rows:
                        if not isinstance(row, dict):
                            new_rows.append(row)
                            continue
                        name = (row.get("Name") or "").upper()
                        # Only steer among FREE servers; the rest are
                        # unreachable on this tier regardless.
                        if "FREE" not in name:
                            new_rows.append(row)
                            continue
                        hide = (name in _excl) if _excl else (name not in _only)
                        if hide:
                            row = dict(row)
                            row["Status"] = 0
                        else:
                            kept += 1
                        new_rows.append(row)
                    # Never steer the client into having nothing to pick.
                    if kept:
                        data = dict(data)
                        data["LogicalServers"] = new_rows
            except Exception:
                pass  # a steering failure must never break connecting
            return _orig_from_dict(cls, data)

        ServerList.from_dict = _steered_from_dict

except Exception:
    pass

# --- 5. DNS resolver, so torsocks can actually proxy lookups -------------
#
# torsocks intercepts connect() and getaddrinfo(), but it CANNOT proxy UDP -
# Tor does not carry UDP. aiohttp defaults to AsyncResolver whenever aiodns
# is installed, and aiodns does its own raw UDP DNS, which torsocks blocks.
# Result: "Could not contact DNS servers" and login fails over Tor.
#
# The previous fix was a fake `aiodns` module on PYTHONPATH that raised
# ImportError, exploiting aiohttp's documented fallback. It worked, but it
# shadowed a real package for EVERY process sharing that PYTHONPATH -
# verified: `import aiodns` raised for anything run with it. That is too
# blunt.
#
# aiohttp.connector does `from .resolver import DefaultResolver` at import,
# so rebinding aiohttp.resolver.DefaultResolver does nothing - verified, the
# connector still saw AsyncResolver. The binding that matters is the one in
# connector. Patching it there flips exactly one thing and touches no other
# package. Verified: AsyncResolver -> ThreadedResolver, live request HTTP 204.
#
# ThreadedResolver uses getaddrinfo, which torsocks does intercept.
try:
    import aiohttp.connector as _conn
    from aiohttp.resolver import ThreadedResolver as _Threaded

    if os.environ.get("PVPN_FORCE_THREADED_DNS", "1") != "0":
        _conn.DefaultResolver = _Threaded
except Exception:
    # If aiohttp renames this, we degrade to its default rather than break.
    # Login over Tor would fail again, loudly, rather than silently.
    pass
