"""Run a protonvpn CLI command with a masked password prompt and real tracebacks.

Two things the stock CLI doesn't do:

1. proton.vpn.cli.main() wraps everything in `except Exception` and prints
   "An unexpected error occurred", discarding the traceback. This calls the
   same click group directly so the real exception surfaces.

2. proton/vpn/cli/commands/account.py passes `getpass.getpass` straight to
   controller.login(), which echoes nothing at all while you type. This
   swaps in a reader that echoes one mask character per keypress.

Usage:
    torsocks env PYTHONPATH="$HOME/.local/share/protonvpn-torshim" \
        /usr/bin/python3 "$HOME/.local/share/protonvpn-torshim/debug-signin.py" \
        signin YOUR-USERNAME

Env:
    PVPN_MASK    mask character (default the bullet); set to "" for no echo
    PVPN_DEBUG   set to 0 to silence the debug logging
"""
import getpass
import logging
import os
import sys
import termios
import traceback
import tty

MASK = os.environ.get("PVPN_MASK", "•")


def masked_getpass(prompt="Password: ", stream=None):
    """getpass.getpass work-alike that echoes MASK per character typed.

    Falls back to the real getpass when stdin isn't a terminal (pipes,
    heredocs) since raw mode needs a tty.
    """
    out = stream or sys.stderr
    if not sys.stdin.isatty() or not MASK:
        return _ORIG_GETPASS(prompt, stream)

    out.write(prompt)
    out.flush()

    fd = sys.stdin.fileno()
    saved = termios.tcgetattr(fd)
    chars = []
    try:
        tty.setraw(fd)
        while True:
            ch = sys.stdin.read(1)
            if ch in ("\r", "\n"):
                break
            if ch == "\x03":                      # Ctrl-C
                raise KeyboardInterrupt
            if ch == "\x04":                      # Ctrl-D
                if not chars:
                    raise EOFError
                continue
            if ch in ("\x7f", "\b"):              # backspace
                if chars:
                    chars.pop()
                    out.write("\b \b")
                    out.flush()
                continue
            if ch == "\x15":                      # Ctrl-U: clear line
                while chars:
                    chars.pop()
                    out.write("\b \b")
                out.flush()
                continue
            if ch < " ":                          # ignore other control chars
                continue
            chars.append(ch)
            out.write(MASK)
            out.flush()
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, saved)
        out.write("\n")
        out.flush()

    return "".join(chars)


_ORIG_GETPASS = getpass.getpass
getpass.getpass = masked_getpass

if os.environ.get("PVPN_DEBUG", "1") != "0":
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(levelname)-8s %(name)s: %(message)s",
        stream=sys.stderr,
    )

from proton.vpn.cli import app                      # noqa: E402
from proton.vpn.cli.core.controller import Params   # noqa: E402

try:
    from proton.session.exceptions import ProtonAPIError
except Exception:  # noqa: BLE001
    ProtonAPIError = ()  # type: ignore

args = sys.argv[1:] or ["signin"]


def _is_captcha(exc: BaseException) -> bool:
    text = str(exc)
    return "CAPTCHA" in text.upper() or "9001" in text


try:
    app(
        obj=Params(verbose=True, allow_gui_concurrency=False,
                   overriding_controller=None),
        standalone_mode=False,
        args=args,
    )
except KeyboardInterrupt:
    print("\nAborted.", file=sys.stderr)
    sys.exit(130)
except ProtonAPIError as exc:
    if _is_captcha(exc):
        print(
            "\nProton requires a CAPTCHA for this sign-in.\n"
            "The Linux CLI cannot complete CAPTCHAs (common via Tor).\n"
            "Handing off to the browser sign-in bridge...\n",
            file=sys.stderr,
        )
        sys.exit(2)
    print("\n=========== REAL TRACEBACK ===========", file=sys.stderr)
    traceback.print_exc()
    sys.exit(1)
except BaseException:  # noqa: BLE001 - the whole point is to see it
    if _is_captcha(sys.exc_info()[1] or Exception()):
        print(
            "\nProton requires a CAPTCHA — CLI cannot complete it.\n"
            "Sign in once on a phone hotspot/home wifi, then use\n"
            "pvpn up protun-tls on the filtered network.\n",
            file=sys.stderr,
        )
        sys.exit(2)
    print("\n=========== REAL TRACEBACK ===========", file=sys.stderr)
    traceback.print_exc()
    sys.exit(1)
