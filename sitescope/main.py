#!/usr/bin/env python3
"""Packaging entry point for SiteScope.

PyInstaller executes its entry script as ``__main__``, which leaves
``__package__`` empty. A module that uses relative imports - as
``sitescope/__main__.py`` does - therefore fails at startup with
"attempted relative import with no known parent package".

This file exists to avoid that: it is a plain top-level script that imports
the real launcher by its absolute package name, so ``sitescope.__main__`` is
loaded as a proper package module and its relative imports resolve normally.

Both of these work and do the same thing:

    python main.py            # and this is what the packaged .exe runs
    python -m sitescope
"""

from __future__ import annotations

import multiprocessing
import sys


def run() -> int:
    from sitescope.__main__ import main
    return main()


if __name__ == "__main__":
    # Harmless when unused, and required if a frozen build ever spawns a
    # child process on Windows - without it the child re-runs the launcher.
    multiprocessing.freeze_support()
    sys.exit(run())
