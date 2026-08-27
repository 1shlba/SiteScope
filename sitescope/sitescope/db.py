"""SQLite persistence for scans, findings and generated reports.

A single file database lives in the user's application data directory. All
access goes through short-lived connections so the scanner thread and the web
request threads never share a connection object.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from typing import Any, Iterator, Optional

from . import config
from .models import Finding, ScanResult, utcnow

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    target_url     TEXT    NOT NULL,
    scan_type      TEXT    NOT NULL DEFAULT 'full',
    started_at     TEXT    NOT NULL,
    finished_at    TEXT,
    status         TEXT    NOT NULL DEFAULT 'running',
    pages_scanned  INTEGER NOT NULL DEFAULT 0,
    requests_sent  INTEGER NOT NULL DEFAULT 0,
    score          INTEGER NOT NULL DEFAULT 0,
    grade          TEXT    NOT NULL DEFAULT '-',
    error          TEXT    NOT NULL DEFAULT '',
    is_demo        INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS findings (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id           INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    check_id          TEXT    NOT NULL,
    title             TEXT    NOT NULL,
    severity          TEXT    NOT NULL,
    cvss              REAL    NOT NULL DEFAULT 0,
    owasp             TEXT    NOT NULL DEFAULT '',
    url               TEXT    NOT NULL DEFAULT '',
    evidence          TEXT    NOT NULL DEFAULT '',
    what_it_means     TEXT    NOT NULL DEFAULT '',
    why_it_matters    TEXT    NOT NULL DEFAULT '',
    how_to_fix        TEXT    NOT NULL DEFAULT '[]',
    difficulty        TEXT    NOT NULL DEFAULT 'Moderate',
    needs_professional INTEGER NOT NULL DEFAULT 0,
    reference         TEXT    NOT NULL DEFAULT '',
    confidence        TEXT    NOT NULL DEFAULT 'High',
    resolved          INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS reports (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id      INTEGER REFERENCES scans(id) ON DELETE CASCADE,
    title        TEXT    NOT NULL,
    target_url   TEXT    NOT NULL DEFAULT '',
    created_at   TEXT    NOT NULL,
    status       TEXT    NOT NULL DEFAULT 'ready',
    file_path    TEXT    NOT NULL DEFAULT '',
    page_count   INTEGER NOT NULL DEFAULT 0,
    summary      TEXT    NOT NULL DEFAULT '',
    is_demo      INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started_at DESC);
"""


@contextmanager
def connect() -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(config.db_path(), timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with connect() as conn:
        conn.executescript(SCHEMA)


# --------------------------------------------------------------------------
# Scans
# --------------------------------------------------------------------------

def create_scan(target_url: str, scan_type: str, is_demo: bool = False) -> int:
    with connect() as conn:
        cur = conn.execute(
            "INSERT INTO scans (target_url, scan_type, started_at, status, is_demo)"
            " VALUES (?, ?, ?, 'running', ?)",
            (target_url, scan_type, utcnow(), 1 if is_demo else 0),
        )
        return int(cur.lastrowid)


def finish_scan(scan_id: int, result: ScanResult) -> None:
    """Persist the terminal state of a scan together with all its findings."""
    with connect() as conn:
        conn.execute(
            "UPDATE scans SET finished_at = ?, status = ?, pages_scanned = ?,"
            " requests_sent = ?, score = ?, grade = ?, error = ? WHERE id = ?",
            (
                result.finished_at or utcnow(),
                result.status,
                result.pages_scanned,
                result.requests_sent,
                result.score,
                result.grade,
                result.error,
                scan_id,
            ),
        )
        conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
        conn.executemany(
            "INSERT INTO findings (scan_id, check_id, title, severity, cvss, owasp, url,"
            " evidence, what_it_means, why_it_matters, how_to_fix, difficulty,"
            " needs_professional, reference, confidence, resolved)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            [
                (
                    scan_id, f.check_id, f.title, f.severity, f.cvss, f.owasp, f.url,
                    f.evidence, f.what_it_means, f.why_it_matters,
                    json.dumps(f.how_to_fix), f.difficulty,
                    1 if f.needs_professional else 0, f.reference, f.confidence,
                    1 if f.resolved else 0,
                )
                for f in result.findings
            ],
        )


def _row_to_finding(row: sqlite3.Row) -> Finding:
    try:
        steps = json.loads(row["how_to_fix"])
    except (ValueError, TypeError):
        steps = []
    return Finding(
        check_id=row["check_id"],
        title=row["title"],
        severity=row["severity"],
        cvss=row["cvss"],
        owasp=row["owasp"],
        url=row["url"],
        evidence=row["evidence"],
        what_it_means=row["what_it_means"],
        why_it_matters=row["why_it_matters"],
        how_to_fix=steps if isinstance(steps, list) else [],
        difficulty=row["difficulty"],
        needs_professional=bool(row["needs_professional"]),
        reference=row["reference"],
        confidence=row["confidence"],
        resolved=bool(row["resolved"]),
    )


def get_scan(scan_id: int) -> Optional[ScanResult]:
    with connect() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if row is None:
            return None
        finding_rows = conn.execute(
            "SELECT * FROM findings WHERE scan_id = ? ORDER BY cvss DESC, id ASC", (scan_id,)
        ).fetchall()

    return ScanResult(
        scan_id=row["id"],
        target_url=row["target_url"],
        scan_type=row["scan_type"],
        started_at=row["started_at"],
        finished_at=row["finished_at"],
        status=row["status"],
        pages_scanned=row["pages_scanned"],
        requests_sent=row["requests_sent"],
        score=row["score"],
        grade=row["grade"],
        error=row["error"],
        findings=[_row_to_finding(r) for r in finding_rows],
    )


def list_scans(limit: int = 100, offset: int = 0, search: str = "") -> list[dict[str, Any]]:
    """Recent scans with a per-scan unresolved finding count, newest first."""
    sql = (
        "SELECT s.*, "
        " (SELECT COUNT(*) FROM findings f WHERE f.scan_id = s.id AND f.resolved = 0"
        "  AND f.severity != 'info') AS findings_count, "
        " (SELECT COUNT(*) FROM findings f WHERE f.scan_id = s.id AND f.resolved = 0"
        "  AND f.severity = 'critical') AS critical_count, "
        " (SELECT COUNT(*) FROM findings f WHERE f.scan_id = s.id AND f.resolved = 0"
        "  AND f.severity = 'high') AS high_count, "
        " (SELECT COUNT(*) FROM findings f WHERE f.scan_id = s.id AND f.resolved = 0"
        "  AND f.severity = 'medium') AS medium_count "
        "FROM scans s "
    )
    params: list[Any] = []
    if search:
        sql += "WHERE s.target_url LIKE ? "
        params.append(f"%{search}%")
    sql += "ORDER BY s.started_at DESC, s.id DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    with connect() as conn:
        rows = conn.execute(sql, params).fetchall()
    return [dict(r) for r in rows]


def delete_scan(scan_id: int) -> None:
    with connect() as conn:
        conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))


def set_finding_resolved(scan_id: int, check_id: str, url: str, resolved: bool) -> None:
    with connect() as conn:
        conn.execute(
            "UPDATE findings SET resolved = ? WHERE scan_id = ? AND check_id = ? AND url = ?",
            (1 if resolved else 0, scan_id, check_id, url),
        )


# --------------------------------------------------------------------------
# Aggregates used by the dashboard
# --------------------------------------------------------------------------

def dashboard_stats() -> dict[str, Any]:
    with connect() as conn:
        total_scans = conn.execute(
            "SELECT COUNT(*) AS c FROM scans WHERE status = 'completed'"
        ).fetchone()["c"]

        week_scans = conn.execute(
            "SELECT COUNT(*) AS c FROM scans WHERE status = 'completed'"
            " AND started_at >= datetime('now', '-7 days')"
        ).fetchone()["c"]

        latest = conn.execute(
            "SELECT * FROM scans WHERE status = 'completed'"
            " ORDER BY started_at DESC, id DESC LIMIT 1"
        ).fetchone()

        # Active vulnerabilities: unresolved findings from each target's most
        # recent completed scan only, so fixed issues stop being counted.
        rows = conn.execute(
            """
            SELECT f.severity, COUNT(*) AS c
            FROM findings f
            JOIN (
                SELECT target_url, MAX(id) AS latest_id
                FROM scans WHERE status = 'completed' GROUP BY target_url
            ) latest_per_target ON f.scan_id = latest_per_target.latest_id
            WHERE f.resolved = 0 AND f.severity != 'info'
            GROUP BY f.severity
            """
        ).fetchall()

        success = conn.execute(
            "SELECT "
            " SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) AS ok,"
            " COUNT(*) AS total FROM scans"
        ).fetchone()

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for row in rows:
        if row["severity"] in counts:
            counts[row["severity"]] = row["c"]

    total = success["total"] or 0
    ok = success["ok"] or 0

    return {
        "total_scans": total_scans,
        "week_scans": week_scans,
        "counts": counts,
        "active_vulnerabilities": sum(counts.values()),
        "latest_scan": dict(latest) if latest else None,
        "success_rate": round((ok / total) * 100) if total else 0,
    }


def top_findings(limit: int = 5) -> list[dict[str, Any]]:
    """Highest-severity unresolved findings, one row per issue per target.

    Drawn only from each target's most recent completed scan, so an issue the
    user has since fixed stops appearing on the dashboard.
    """
    with connect() as conn:
        rows = conn.execute(
            """
            SELECT f.check_id, f.title, f.severity, f.cvss, f.difficulty,
                   f.needs_professional, s.target_url, s.id AS scan_id
            FROM findings f
            JOIN (
                SELECT target_url, MAX(id) AS latest_id
                FROM scans WHERE status = 'completed' GROUP BY target_url
            ) latest_per_target ON f.scan_id = latest_per_target.latest_id
            JOIN scans s ON s.id = f.scan_id
            WHERE f.resolved = 0 AND f.severity != 'info'
            ORDER BY f.cvss DESC, f.title ASC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def monthly_trend(months: int = 8) -> list[dict[str, Any]]:
    """Findings discovered per calendar month, oldest first (dashboard chart)."""
    with connect() as conn:
        rows = conn.execute(
            """
            SELECT strftime('%Y-%m', s.started_at) AS month,
                   COUNT(f.id) AS findings,
                   AVG(s.score) AS avg_score
            FROM scans s LEFT JOIN findings f
              ON f.scan_id = s.id AND f.severity != 'info'
            WHERE s.status = 'completed'
            GROUP BY month ORDER BY month DESC LIMIT ?
            """,
            (months,),
        ).fetchall()
    return [dict(r) for r in reversed(rows)]


# --------------------------------------------------------------------------
# Reports
# --------------------------------------------------------------------------

def create_report(
    scan_id: Optional[int],
    title: str,
    target_url: str,
    file_path: str,
    page_count: int,
    summary: str,
    status: str = "ready",
    is_demo: bool = False,
) -> int:
    with connect() as conn:
        cur = conn.execute(
            "INSERT INTO reports (scan_id, title, target_url, created_at, status,"
            " file_path, page_count, summary, is_demo) VALUES (?,?,?,?,?,?,?,?,?)",
            (scan_id, title, target_url, utcnow(), status, file_path,
             page_count, summary, 1 if is_demo else 0),
        )
        return int(cur.lastrowid)


def list_reports(limit: int = 100, search: str = "") -> list[dict[str, Any]]:
    sql = "SELECT * FROM reports "
    params: list[Any] = []
    if search:
        sql += "WHERE title LIKE ? OR target_url LIKE ? "
        params.extend([f"%{search}%", f"%{search}%"])
    sql += "ORDER BY created_at DESC, id DESC LIMIT ?"
    params.append(limit)
    with connect() as conn:
        return [dict(r) for r in conn.execute(sql, params).fetchall()]


def get_report(report_id: int) -> Optional[dict[str, Any]]:
    with connect() as conn:
        row = conn.execute("SELECT * FROM reports WHERE id = ?", (report_id,)).fetchone()
    return dict(row) if row else None


def delete_report(report_id: int) -> None:
    with connect() as conn:
        conn.execute("DELETE FROM reports WHERE id = ?", (report_id,))


def report_count() -> int:
    with connect() as conn:
        return conn.execute("SELECT COUNT(*) AS c FROM reports").fetchone()["c"]


def reports_this_month() -> int:
    with connect() as conn:
        return conn.execute(
            "SELECT COUNT(*) AS c FROM reports WHERE created_at >= datetime('now','start of month')"
        ).fetchone()["c"]


# --------------------------------------------------------------------------
# Maintenance
# --------------------------------------------------------------------------

def clear_demo_data() -> int:
    """Remove seeded sample data, leaving the user's real scans untouched."""
    with connect() as conn:
        removed = conn.execute("SELECT COUNT(*) AS c FROM scans WHERE is_demo = 1").fetchone()["c"]
        conn.execute("DELETE FROM findings WHERE scan_id IN (SELECT id FROM scans WHERE is_demo = 1)")
        conn.execute("DELETE FROM reports WHERE is_demo = 1")
        conn.execute("DELETE FROM scans WHERE is_demo = 1")
    return removed


def clear_all_data() -> None:
    with connect() as conn:
        conn.execute("DELETE FROM findings")
        conn.execute("DELETE FROM reports")
        conn.execute("DELETE FROM scans")


def has_demo_data() -> bool:
    with connect() as conn:
        return conn.execute("SELECT COUNT(*) AS c FROM scans WHERE is_demo = 1").fetchone()["c"] > 0
