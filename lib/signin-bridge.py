#!/usr/bin/env python3
"""Browser → Proton CLI sign-in bridge.

Proton's Linux CLI cannot complete CAPTCHAs. This bridge:

  1. Opens a local helper page + Proton authorize in your default browser
  2. After you sign in (CAPTCHA works in the browser), Proton redirects to a
     URL whose hash contains selector=...
  3. You paste that URL into the helper (or pass --url)
  4. We pull the forked session into the same keyring the protonvpn CLI uses

Typical (from pvpn):
    # collect selector (no Tor)
    /usr/bin/python3 signin-bridge.py --helper
    # import over Tor when API is blocked
    torsocks env PYTHONPATH=... /usr/bin/python3 signin-bridge.py --import-selector SEL

Env:
    PVPN_API_TIMEOUT   transport timeout (default 60 — needed over Tor)
    PVPN_BRIDGE_PORT   local helper page port (default 8765)
    PVPN_BRIDGE_APP    Proton app id for authorize (default proton-mail)
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import os
import secrets
import sys
import threading
import time
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, "/usr/lib/python3/dist-packages")

from proton.sso import ProtonSSO  # noqa: E402
from proton.vpn.core.session_holder import ClientTypeMetadata  # noqa: E402
from proton.vpn.session import VPNSession  # noqa: E402
from proton.vpn.session.utils import get_core_api_semver_version  # noqa: E402

AUTHORIZE = "https://account.proton.me/authorize"
DEFAULT_APP = os.environ.get("PVPN_BRIDGE_APP", "proton-mail")
HELPER_PORT = int(os.environ.get("PVPN_BRIDGE_PORT", "8765"))


def _b64url(nbytes: int = 32) -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(nbytes)).decode("ascii").rstrip("=")


def build_authorize_url(state: str, app: str = DEFAULT_APP, email: str | None = None) -> str:
    q = {"app": app, "state": state, "v": "2", "u": "1"}
    if email:
        q["email"] = email
    return f"{AUTHORIZE}?{urllib.parse.urlencode(q)}"


def parse_selector(text: str) -> str:
    """Extract fork selector from a pasted redirect URL, hash, or raw selector."""
    text = text.strip().strip("'\"")
    if not text:
        raise ValueError("empty input")

    if "://" in text or text.startswith("#") or "selector=" in text:
        params: dict[str, list[str]] = {}
        if text.startswith("#"):
            params = urllib.parse.parse_qs(text[1:])
        elif "://" in text:
            parts = urllib.parse.urlsplit(text)
            params = urllib.parse.parse_qs(parts.query)
            if parts.fragment:
                params = {**params, **urllib.parse.parse_qs(parts.fragment)}
        else:
            params = urllib.parse.parse_qs(text)
        sel = (params.get("selector") or [None])[0]
        if not sel:
            raise ValueError("no selector= in that URL — paste the address bar AFTER sign-in")
        return sel

    if len(text) >= 16 and all(c.isalnum() or c in "-_" for c in text):
        return text

    raise ValueError("could not parse selector from input")


def _appversion() -> str:
    meta = ClientTypeMetadata(type="cli", version=get_core_api_semver_version())
    return f"linux-vpn-{meta.type}@{meta.version}"


def import_selector(selector: str) -> str:
    """Pull forked session into ProtonSSO keyring. Returns account name."""
    sso = ProtonSSO(
        appversion=_appversion(),
        user_agent=f"ProtonVPN/{get_core_api_semver_version()} (Linux; pvpn-bridge)",
    )
    session: VPNSession = sso.get_session(None, override_class=VPNSession)

    print("Pulling forked session from Proton...", file=sys.stderr)
    session.import_fork(selector)

    if not session.authenticated:
        raise RuntimeError("import_fork did not authenticate the session")

    vpninfo = session.api_request("/vpn/v2")
    name = (vpninfo.get("VPN") or {}).get("Name") or vpninfo.get("Name")
    if not name:
        name = f"uid-{session.UID[:8]}"

    state = session.__getstate__()
    state["AccountName"] = name
    session.__setstate__(state)

    asyncio.run(session.fetch_session_data())

    state = session.__getstate__()
    if not state.get("AccountName"):
        state["AccountName"] = name
        session.__setstate__(state)
        session._requests_lock(no_condition_check=True)
        session._requests_unlock(no_condition_check=False)

    try:
        sso.set_default_account(name)
    except KeyError:
        # Index may lag one unlock; ignore — session is still stored.
        pass
    return name


class _BridgeHandler(BaseHTTPRequestHandler):
    bridge_state: dict

    def log_message(self, fmt, *args):
        return

    def _html(self, body: str, code: int = 200):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/callback":
            qs = urllib.parse.parse_qs(parsed.query)
            sel = (qs.get("selector") or [None])[0]
            if sel:
                self.bridge_state["selector"] = sel
                self._html("<h1>Got it</h1><p>Return to the terminal.</p>")
                return
        auth = self.bridge_state["authorize_url"]
        self._html(
            f"""<!doctype html>
<html><head><meta charset="utf-8"><title>pvpn sign-in bridge</title>
<style>
 body{{font-family:system-ui,sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem;line-height:1.45}}
 input,button{{font:inherit;padding:.5rem;width:100%;margin:.4rem 0;box-sizing:border-box}}
 code{{background:#f2f2f2;padding:.1rem .3rem}}
 a.btn{{display:inline-block;background:#6d4aff;color:#fff;text-decoration:none;
        padding:.6rem 1rem;border-radius:6px;margin:.5rem 0}}
</style></head><body>
<h1>pvpn sign-in bridge</h1>
<ol>
<li><a class="btn" href="{auth}" target="_blank" rel="noopener">Open Proton sign-in</a>
    <div>Complete CAPTCHA / 2FA in the browser.</div></li>
<li>After redirect, copy the <strong>full address bar URL</strong>
    (it contains <code>selector=</code>).</li>
<li>Paste it below and submit.</li>
</ol>
<form method="POST" action="/submit">
<input name="url" placeholder="https://mail.proton.me/login#selector=..." autofocus>
<button type="submit">Authenticate CLI</button>
</form>
<p>On filtered wifi, use a phone hotspot for the Proton tab, then paste here.</p>
</body></html>"""
        )

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8", "replace")
        form = urllib.parse.parse_qs(body)
        raw = (form.get("url") or [""])[0]
        try:
            sel = parse_selector(raw)
        except ValueError as e:
            self._html(f"<h1>Bad link</h1><p>{e}</p><p><a href='/'>Try again</a></p>", 400)
            return
        self.bridge_state["selector"] = sel
        self._html("<h1>Got it</h1><p>Return to the terminal — importing session…</p>")


def run_helper(authorize_url: str, port: int, timeout: int = 600) -> str:
    state = {"authorize_url": authorize_url, "selector": None}
    _BridgeHandler.bridge_state = state
    httpd = HTTPServer(("127.0.0.1", port), _BridgeHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    local = f"http://127.0.0.1:{port}/"
    print(f"Bridge page: {local}", file=sys.stderr)
    webbrowser.open(local)
    deadline = time.time() + timeout
    try:
        while time.time() < deadline:
            if state["selector"]:
                return state["selector"]
            time.sleep(0.25)
    finally:
        httpd.shutdown()
    raise TimeoutError("timed out waiting for the pasted sign-in link")


def main() -> int:
    ap = argparse.ArgumentParser(description="pvpn browser sign-in bridge")
    ap.add_argument("--helper", action="store_true",
                    help="Only collect selector via local page (print it, do not import)")
    ap.add_argument("--import-selector", metavar="SEL",
                    help="Import an existing fork selector into the CLI keyring")
    ap.add_argument("--url", help="Post-login redirect URL (implies import)")
    ap.add_argument("--email", help="Prefill email on Proton sign-in")
    ap.add_argument("--port", type=int, default=HELPER_PORT)
    args = ap.parse_args()

    if args.import_selector:
        try:
            name = import_selector(args.import_selector)
        except Exception as e:  # noqa: BLE001
            print(f"error: failed to import session: {e}", file=sys.stderr)
            return 1
        print(f"Signed in as '{name}'")
        return 0

    state = _b64url()
    auth_url = build_authorize_url(state, email=args.email)
    print("Authorize URL:", auth_url, file=sys.stderr)

    if args.url:
        selector = parse_selector(args.url)
    else:
        try:
            selector = run_helper(auth_url, args.port)
        except TimeoutError as e:
            print(f"error: {e}", file=sys.stderr)
            print("Paste the redirect URL manually:", file=sys.stderr)
            raw = input("URL> ").strip()
            try:
                selector = parse_selector(raw)
            except ValueError as ve:
                print(f"error: {ve}", file=sys.stderr)
                return 1

    if args.helper:
        # Caller (pvpn) will re-exec under torsocks to import.
        print(selector)
        return 0

    try:
        name = import_selector(selector)
    except Exception as e:  # noqa: BLE001
        print(f"error: failed to import session: {e}", file=sys.stderr)
        print("If the API is blocked, re-run import via:", file=sys.stderr)
        print(f"  torsocks /usr/bin/python3 {sys.argv[0]} --import-selector {selector}",
              file=sys.stderr)
        return 1

    print(f"Signed in as '{name}'")
    print("Next:  pvpn account --view")
    print("Then:  pvpn up protun-tls")
    return 0


if __name__ == "__main__":
    sys.exit(main())
