"""Make Proton's client give up on a blocked API quickly.

Python imports `sitecustomize` automatically at interpreter startup if it is
on sys.path. pvpn puts this directory on PYTHONPATH, so it applies only to
the commands pvpn launches - nothing else on the system is affected.

Why:
    proton/session/transports/auto.py has

        class AutoTransport(Transport):
            TRANSPORT_TIMEOUT = 15

    On a network where Proton's API domains are blocked, `protonvpn connect`
    makes two API calls before it even starts the tunnel - /vpn/v1/logicals
    and /vpn/v2/clientconfig. Each fails with "No working transports found"
    after exactly 15.0s. Measured: 30s of the ~40s connect was these two
    doomed calls. The tunnel itself takes 0.3s.

    Both calls are optional refreshes: the client proceeds with its cached
    data when they fail. So failing fast costs nothing and saves ~26s.

Override with PVPN_API_TIMEOUT (seconds). Set it higher on a slow but
working link, where you actually want the refresh to succeed.
"""
import os

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
