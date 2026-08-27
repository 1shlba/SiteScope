"""Shared pytest fixtures.

Every test runs against a throwaway data directory so a test run can never
touch a developer's real scan history, and starts the deliberately insecure
sample site on a free local port when a live scan is needed.
"""

from __future__ import annotations

import os
import socket
import sys
import threading
import time
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


@pytest.fixture(scope="session", autouse=True)
def isolated_data_dir(tmp_path_factory):
    """Point SiteScope at a temporary data directory for the whole session."""
    data_dir = tmp_path_factory.mktemp("sitescope-data")
    os.environ["SITESCOPE_DATA_DIR"] = str(data_dir)

    # A proxy configured in the environment would intercept loopback requests.
    for variable in ("http_proxy", "https_proxy", "HTTP_PROXY",
                     "HTTPS_PROXY", "all_proxy", "ALL_PROXY"):
        os.environ.pop(variable, None)
    os.environ["NO_PROXY"] = "*"

    yield data_dir


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture(scope="session")
def vulnerable_site():
    """Run the deliberately insecure sample site for the duration of the session."""
    from tests.vulnerable_target import VulnerableHandler

    port = _free_port()
    server = ThreadingHTTPServer(("127.0.0.1", port), VulnerableHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.3)

    yield f"http://127.0.0.1:{port}/"

    server.shutdown()
    server.server_close()


@pytest.fixture
def scan_settings():
    """Default settings with the rate limit lifted so tests run quickly."""
    from sitescope.config import DEFAULT_SETTINGS

    settings = dict(DEFAULT_SETTINGS)
    settings["requests_per_second"] = 100.0
    settings["max_pages"] = 8
    settings["request_timeout"] = 5
    return settings


@pytest.fixture
def app():
    from sitescope import db
    from sitescope.app import create_app

    application = create_app()
    application.config.update(TESTING=True)
    db.clear_all_data()
    yield application


@pytest.fixture
def client(app):
    return app.test_client()
