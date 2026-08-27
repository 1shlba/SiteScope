"""SiteScope desktop launcher.

Starts the local web service on the loopback interface and shows it in a
chromeless browser window, so the application behaves like an ordinary desktop
program: an icon in the Start Menu, its own window with no address bar, and
closing the window quits the application.

Why a local web service rather than a native widget toolkit
-----------------------------------------------------------
Every dependency ships prebuilt Windows wheels and none is a GUI toolkit,
which makes the PyInstaller build reliable and the resulting executable small.
It also renders the dashboard exactly as designed on every Windows machine
without shipping a GUI runtime alongside it.
"""

from __future__ import annotations

import argparse
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import webbrowser
from pathlib import Path

DEFAULT_PORT = 8731
HOST = "127.0.0.1"


# --------------------------------------------------------------------------
# Networking helpers
# --------------------------------------------------------------------------

def port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.4)
        return sock.connect_ex((HOST, port)) == 0


def sitescope_already_running(port: int) -> bool:
    """True when the port is answering and it is our own application."""
    if not port_in_use(port):
        return False
    try:
        import urllib.request
        with urllib.request.urlopen(f"http://{HOST}:{port}/api/health", timeout=1.5) as response:
            return b"ok" in response.read(200)
    except Exception:
        return False


def find_free_port(preferred: int) -> int:
    if not port_in_use(preferred):
        return preferred
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((HOST, 0))
        return int(sock.getsockname()[1])


# --------------------------------------------------------------------------
# Browser window
# --------------------------------------------------------------------------

def find_chromium_browser() -> str | None:
    """Locate Edge or Chrome, which can display a page as a standalone window."""
    if sys.platform == "win32":
        program_files = [
            os.environ.get("PROGRAMFILES", r"C:\Program Files"),
            os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)"),
            os.environ.get("LOCALAPPDATA", ""),
        ]
        relative = [
            r"Microsoft\Edge\Application\msedge.exe",
            r"Google\Chrome\Application\chrome.exe",
        ]
        for base in program_files:
            if not base:
                continue
            for suffix in relative:
                candidate = Path(base) / suffix
                if candidate.exists():
                    return str(candidate)
        return None

    for name in ("microsoft-edge", "google-chrome", "chromium", "chromium-browser"):
        found = shutil.which(name)
        if found:
            return found
    return None


def open_app_window(url: str, browser: str | None) -> subprocess.Popen | None:
    """Open the interface in a chromeless window. Returns the process if we own it."""
    if browser is None:
        webbrowser.open(url)
        return None

    # A dedicated profile directory keeps SiteScope out of the user's normal
    # browsing session and guarantees a separate process we can wait on.
    profile = Path(tempfile.gettempdir()) / "sitescope-window-profile"
    profile.mkdir(parents=True, exist_ok=True)

    command = [
        browser,
        f"--app={url}",
        f"--user-data-dir={profile}",
        "--window-size=1320,880",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-features=Translate,AutofillServerCommunication",
    ]

    creation_flags = 0
    if sys.platform == "win32":
        creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)

    try:
        return subprocess.Popen(
            command, creationflags=creation_flags,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except OSError:
        webbrowser.open(url)
        return None


def show_windows_message(title: str, message: str) -> None:
    """Fall back to a native dialog when there is no console to print to."""
    if sys.platform != "win32":
        return
    try:
        import ctypes
        ctypes.windll.user32.MessageBoxW(0, message, title, 0x40)
    except Exception:
        pass


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sitescope", description="SiteScope website security scanner")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="port for the local service")
    parser.add_argument("--no-window", action="store_true", help="start the service without opening a window")
    parser.add_argument("--browser", action="store_true", help="open in the default browser instead of an app window")
    parser.add_argument("--version", action="store_true", help="print the version and exit")
    args = parser.parse_args(argv)

    from . import __version__

    if args.version:
        print(f"SiteScope {__version__}")
        return 0

    # A second launch should raise the existing window rather than start again.
    if sitescope_already_running(args.port):
        url = f"http://{HOST}:{args.port}/"
        if not args.no_window:
            open_app_window(url, None if args.browser else find_chromium_browser())
        print(f"SiteScope is already running at {url}")
        return 0

    port = find_free_port(args.port)
    url = f"http://{HOST}:{port}/"

    from werkzeug.serving import make_server
    from .app import create_app

    try:
        app = create_app()
    except Exception as exc:  # noqa: BLE001
        message = f"SiteScope could not start.\n\n{type(exc).__name__}: {exc}"
        print(message, file=sys.stderr)
        show_windows_message("SiteScope", message)
        return 1

    # Bound to the loopback interface only - never reachable from the network.
    server = make_server(HOST, port, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, name="sitescope-http", daemon=True)
    thread.start()

    print(f"SiteScope {__version__} is running at {url}")
    print("Close the SiteScope window to quit.")

    if args.no_window:
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            server.shutdown()
        return 0

    browser = None if args.browser else find_chromium_browser()
    if browser is None and not args.browser:
        show_windows_message(
            "SiteScope",
            "SiteScope is running and will now open in your default web browser.\n\n"
            f"If it does not appear, open this address manually:\n{url}\n\n"
            "Leave this program running while you use SiteScope.",
        )

    time.sleep(0.4)  # let the server bind before the window requests the page
    process = open_app_window(url, browser)

    try:
        if process is not None:
            process.wait()          # window closed by the user
        else:
            while True:             # default browser: no window to watch
                time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()

    return 0


if __name__ == "__main__":
    sys.exit(main())
