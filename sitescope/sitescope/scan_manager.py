"""Runs a scan on a background thread and exposes its live state to the UI.

Only one scan runs at a time. This is deliberate: the target is usually a small
business's own modest hosting, and running several scans at once against it
would be both impolite and misleading about the site's real performance.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any, Optional

from . import db
from .models import ScanResult
from .scanner import get_engine, normalise_url

MAX_LOG_LINES = 400


class ScanManager:
    """Owns the currently running scan and its log feed."""

    def __init__(self):
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._cancel = threading.Event()

        self.active = False
        self.scan_id: Optional[int] = None
        self.target_url = ""
        self.scan_type = "full"
        self.phase = "Idle"
        self.progress = 0.0
        self.requests_sent = 0
        self.detections = 0
        self.started_at: Optional[float] = None
        self.result: Optional[ScanResult] = None
        self.error = ""
        self.logs: deque[dict[str, Any]] = deque(maxlen=MAX_LOG_LINES)

    # ------------------------------------------------------------------

    def start(self, target_url: str, scan_type: str, settings: dict) -> dict[str, Any]:
        """Begin a scan. Returns the initial status payload."""
        with self._lock:
            if self.active:
                raise RuntimeError("A scan is already running. Wait for it to finish or stop it.")

            normalised = normalise_url(target_url)

            self._cancel = threading.Event()
            self.active = True
            self.target_url = normalised
            self.scan_type = scan_type
            self.phase = "Starting"
            self.progress = 0.0
            self.requests_sent = 0
            self.detections = 0
            self.started_at = time.monotonic()
            self.result = None
            self.error = ""
            self.logs.clear()

            self.scan_id = db.create_scan(normalised, scan_type)

            self._thread = threading.Thread(
                target=self._run, args=(normalised, scan_type, settings),
                name="sitescope-scan", daemon=True,
            )
            self._thread.start()

        return self.status()

    def cancel(self) -> None:
        self._cancel.set()
        self._log("WARN", "Stop requested - finishing the current step.")

    def status(self) -> dict[str, Any]:
        elapsed = int(time.monotonic() - self.started_at) if self.started_at else 0
        payload: dict[str, Any] = {
            "active": self.active,
            "scan_id": self.scan_id,
            "target_url": self.target_url,
            "scan_type": self.scan_type,
            "phase": self.phase,
            "progress": round(self.progress * 100),
            "requests_sent": self.requests_sent,
            "detections": self.detections,
            "elapsed": elapsed,
            "elapsed_display": _format_elapsed(elapsed),
            "error": self.error,
            "logs": list(self.logs),
        }
        if self.result is not None and not self.active:
            payload["result"] = {
                "status": self.result.status,
                "score": self.result.score,
                "grade": self.result.grade,
                "counts": self.result.counts,
                "pages_scanned": self.result.pages_scanned,
                "total_findings": len([f for f in self.result.findings if f.severity != "info"]),
                "error": self.result.error,
            }
        return payload

    # ------------------------------------------------------------------

    def _run(self, target_url: str, scan_type: str, settings: dict) -> None:
        engine = get_engine(settings)
        try:
            result = engine.run(
                target_url, settings, scan_type,
                on_log=self._log,
                on_progress=self._progress,
                cancelled=self._cancel,
                on_request=self._count_request,
            )
        except Exception as exc:  # noqa: BLE001 - the UI must always get an answer
            self._log("ALERT", f"Scan could not run: {exc}")
            result = ScanResult(target_url=target_url, scan_type=scan_type)
            result.status = "failed"
            result.error = str(exc)

        try:
            if self.scan_id is not None:
                db.finish_scan(self.scan_id, result)
        except Exception as exc:  # noqa: BLE001
            self._log("ALERT", f"Results could not be saved: {exc}")

        with self._lock:
            self.result = result
            self.error = result.error
            self.active = False
            self.progress = 1.0
            self.phase = {
                "completed": "Complete",
                "cancelled": "Stopped",
                "failed": "Failed",
            }.get(result.status, "Complete")

    def _log(self, level: str, message: str) -> None:
        self.logs.append({
            "time": datetime.now(timezone.utc).astimezone().strftime("%H:%M:%S"),
            "level": level,
            "message": message,
        })
        if level == "DETECT":
            self.detections += 1

    def _progress(self, fraction: float, phase: str) -> None:
        self.progress = max(0.0, min(1.0, fraction))
        self.phase = phase

    def _count_request(self, total: int) -> None:
        self.requests_sent = total


def _format_elapsed(seconds: int) -> str:
    hours, remainder = divmod(max(0, seconds), 3600)
    minutes, secs = divmod(remainder, 60)
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


# A single shared instance used by the web layer.
manager = ScanManager()
