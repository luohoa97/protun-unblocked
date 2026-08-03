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
