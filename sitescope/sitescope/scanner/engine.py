"""Scan orchestration.

`ScanEngine` is the interface the application depends on. `BuiltinEngine` is the
implementation that ships with SiteScope and performs all analysis locally in
Python.

Adding OWASP ZAP later
----------------------
A `ZapEngine` subclassing `ScanEngine` can drive a local ZAP daemon through its
REST API, translate ZAP alerts into `Finding` objects using the same knowledge
base (`knowledge.KNOWLEDGE`), and be selected in Settings. Nothing outside this
module needs to change, because the rest of the application only ever sees
`ScanResult` and `Finding`.
"""

from __future__ import annotations

import threading
import time
from typing import Callable, Optional, Protocol

from ..models import Finding, ScanResult, utcnow
from . import crawler
from .base import ScanCancelled, ScanContext, dedupe, normalise_url
from .checks import ALL_CHECKS
from .scoring import calculate_score

# progress fraction, phase label
ProgressCallback = Callable[[float, str], None]
LogCallback = Callable[[str, str], None]


class ScanEngine(Protocol):
    """Any scanning backend SiteScope can drive."""

    name: str

    def run(
        self,
        target_url: str,
        settings: dict,
        scan_type: str = "full",
        on_log: Optional[LogCallback] = None,
        on_progress: Optional[ProgressCallback] = None,
        cancelled: Optional[threading.Event] = None,
        on_request: Optional[Callable[[int], None]] = None,
    ) -> ScanResult:
        ...


class BuiltinEngine:
    """SiteScope's own passive scanning engine.

    Runs entirely in Python with no external dependencies, so the application
    works immediately after installation with nothing else to set up.
    """

    name = "VulnGuard Engine"

    def run(
        self,
        target_url: str,
        settings: dict,
        scan_type: str = "full",
        on_log: Optional[LogCallback] = None,
        on_progress: Optional[ProgressCallback] = None,
        cancelled: Optional[threading.Event] = None,
        on_request: Optional[Callable[[int], None]] = None,
    ) -> ScanResult:
        target_url = normalise_url(target_url)
        log = on_log or (lambda level, message: None)
        progress = on_progress or (lambda fraction, phase: None)

        result = ScanResult(target_url=target_url, scan_type=scan_type)
        ctx = ScanContext(target_url, settings, scan_type=scan_type,
                          log=lambda level, msg: log(level, msg), cancelled=cancelled,
                          on_request=on_request)

        try:
            progress(0.02, "Checking Target Reachability")
            ctx.log(f"Starting {scan_type} scan of {target_url}")

            if not self._verify_reachable(ctx, result):
                return result

            checks = [c() for c in ALL_CHECKS
                      if scan_type != "quick" or getattr(c, "quick_scan", True)]

            # Transport checks run before the crawl so a certificate problem is
            # detected and tolerated rather than aborting the whole scan.
            transport = [c for c in checks if c.phase.startswith("Transport")]
            remaining = [c for c in checks if not c.phase.startswith("Transport")]

            findings: list[Finding] = []
            for index, check in enumerate(transport):
                progress(0.05 + 0.15 * (index / max(1, len(transport))), check.phase)
                findings.extend(self._run_check(ctx, check))

            progress(0.22, "Site Crawl")
            max_pages = 5 if scan_type == "quick" else int(settings.get("max_pages", 25))
            ctx.log(f"Crawling up to {max_pages} page(s) on this site.")
            crawler.crawl(ctx, max_pages)
            result.pages_scanned = len(ctx.pages)

            if not ctx.pages:
                # The crawl found nothing, but transport findings may still exist.
                ctx.log("No pages could be retrieved from this site.", "ALERT")
                result.status = "completed" if findings else "failed"
                if not findings:
                    result.error = "The website did not return any readable pages."
            else:
                ctx.log(f"Crawl complete: {len(ctx.pages)} page(s) retrieved.")

            for index, check in enumerate(remaining):
                if ctx.cancelled.is_set():
                    raise ScanCancelled()
                fraction = 0.35 + 0.55 * (index / max(1, len(remaining)))
                progress(fraction, check.phase)
                findings.extend(self._run_check(ctx, check))

            progress(0.95, "Scoring & Report")
            result.findings = dedupe(findings)
            result.score, result.grade = calculate_score(result.findings)
            result.requests_sent = ctx.requests_sent
            result.finished_at = utcnow()
            if result.status == "running":
                result.status = "completed"

            counts = result.counts
            ctx.log(
                f"Scan complete. Score {result.score}/950 (grade {result.grade}). "
                f"{counts['critical']} critical, {counts['high']} high, "
                f"{counts['medium']} medium, {counts['low']} low.",
                "INFO",
            )
            progress(1.0, "Complete")

        except ScanCancelled:
            result.status = "cancelled"
            result.error = "Scan stopped by the user."
            result.finished_at = utcnow()
            result.requests_sent = ctx.requests_sent
            ctx.log("Scan cancelled.", "WARN")
        except Exception as exc:  # noqa: BLE001 - a scan must never crash the app
            result.status = "failed"
            result.error = f"{type(exc).__name__}: {exc}"
            result.finished_at = utcnow()
            result.requests_sent = ctx.requests_sent
            ctx.log(f"Scan failed: {result.error}", "ALERT")
        finally:
            ctx.session.close()

        return result

    # ------------------------------------------------------------------

    def _verify_reachable(self, ctx: ScanContext, result: ScanResult) -> bool:
        """Confirm the target answers before committing to a full scan."""
        page = ctx.fetch(ctx.target_url, allow_redirects=True)

        if page.error and "TLS" in page.error:
            ctx.log("Certificate problem detected - continuing with verification relaxed.", "WARN")
            ctx.allow_insecure_tls()
            page = ctx.fetch(ctx.target_url, allow_redirects=True)

        if page.error or page.status_code == 0:
            result.status = "failed"
            result.error = (
                f"Could not reach {ctx.target_url}. {page.error or 'No response from the server.'}"
            )
            result.finished_at = utcnow()
            result.requests_sent = ctx.requests_sent
            ctx.log(result.error, "ALERT")
            return False

        ctx.log(f"Target reachable. HTTP {page.status_code} returned in {page.elapsed_ms}ms.")
        if page.redirect_chain:
            ctx.log(f"Followed {len(page.redirect_chain)} redirect(s) to {page.final_url}")
        return True

    def _run_check(self, ctx: ScanContext, check) -> list[Finding]:
        """Run one check, converting any unexpected error into a log entry.

        A single misbehaving check must never abort an otherwise useful scan.
        """
        started = time.monotonic()
        try:
            findings = check.run(ctx) or []
        except ScanCancelled:
            raise
        except Exception as exc:  # noqa: BLE001
            ctx.log(f"Check '{check.name}' could not complete: {exc}", "WARN")
            return []

        elapsed = int((time.monotonic() - started) * 1000)
        if findings:
            ctx.log(f"{check.name}: {len(findings)} issue(s) found ({elapsed}ms).", "DETECT")
        return findings


def get_engine(settings: Optional[dict] = None) -> ScanEngine:
    """Return the configured scanning engine.

    Currently always the built-in engine. When a ZAP adapter is added this is
    where the selection happens, based on a Settings value.
    """
    return BuiltinEngine()
