#!/usr/bin/env python3
"""Development entry point.

Runs the SiteScope service without opening a desktop window, with Flask's
reloader enabled so template and code changes appear immediately.

    python run_dev.py [--port 8731]
"""

from __future__ import annotations

import argparse

from sitescope.app import create_app


def main() -> None:
    parser = argparse.ArgumentParser(description="Run SiteScope in development mode")
    parser.add_argument("--port", type=int, default=8731)
    parser.add_argument("--no-reload", action="store_true")
    args = parser.parse_args()

    app = create_app()
    print(f"SiteScope development server: http://127.0.0.1:{args.port}/")
    app.run(host="127.0.0.1", port=args.port, debug=not args.no_reload,
            use_reloader=not args.no_reload, threaded=True)


if __name__ == "__main__":
    main()
