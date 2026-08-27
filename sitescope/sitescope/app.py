"""Flask application: page routes and the JSON API the interface talks to.

The interface is a local web application served on 127.0.0.1 and displayed in a
desktop window, so it is single-user by design. There is no authentication layer
because there is no remote access - the server refuses to bind to anything other
than the loopback interface.
"""

from __future__ import annotations

import webbrowser
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from flask import (
    Flask, jsonify, render_template, request, send_file, abort, url_for,
)

from . import __version__, config, db, demo
from .models import SEVERITY_LABELS, SEVERITY_ORDER
from .reporting.pdf import build_pdf_report, estimate_page_count, executive_summary
from .scan_manager import manager
from .scanner import normalise_url
from .scanner.scoring import MAX_SCORE, score_summary

# The score a site should be aiming at. Shown as a reference line on the
# dashboard trend chart so the user has something concrete to measure against.
# It is a stated goal, not a measured industry figure.
TARGET_SCORE = 850

NAV_ITEMS = [
    ("dashboard", "Dashboard", "grid"),
    ("new_scan", "New Scan", "plus"),
    ("history", "Scan History", "activity"),
    ("reports", "Reports", "file"),
    ("settings", "Settings", "cog"),
]


def create_app() -> Flask:
    app = Flask(
        __name__,
        template_folder=str(config.resource_dir() / "web" / "templates"),
        static_folder=str(config.resource_dir() / "web" / "static"),
    )
    app.config["JSON_SORT_KEYS"] = False

    db.init_db()
    if config.load_settings().get("demo_data_loaded", True):
        demo.seed_if_empty()

    register_pages(app)
    register_api(app)
    return app


# --------------------------------------------------------------------------
# Pages
# --------------------------------------------------------------------------

def register_pages(app: Flask) -> None:

    @app.context_processor
    def inject_globals() -> dict[str, Any]:
        return {
            "nav_items": NAV_ITEMS,
            "app_version": __version__,
            "max_score": MAX_SCORE,
            "severity_order": SEVERITY_ORDER,
            "severity_labels": SEVERITY_LABELS,
        }

    @app.route("/")
    def dashboard():
        return render_template("dashboard.html", page="dashboard", page_title="Security Dashboard")

    @app.route("/new-scan")
    def new_scan():
        return render_template("new_scan.html", page="new_scan", page_title="New Scan")

    @app.route("/history")
    def history():
        return render_template("history.html", page="history", page_title="Scan History")

    @app.route("/reports")
    def reports():
        return render_template("reports.html", page="reports", page_title="Results and Report Summary")

    @app.route("/settings")
    def settings():
        return render_template("settings.html", page="settings", page_title="Settings")

    @app.route("/scan/<int:scan_id>")
    def scan_detail(scan_id: int):
        result = db.get_scan(scan_id)
        if result is None:
            abort(404)
        return render_template(
            "scan_detail.html", page="history", page_title="Scan Results",
            scan_id=scan_id, target_url=result.target_url,
        )


# --------------------------------------------------------------------------
# JSON API
# --------------------------------------------------------------------------

def register_api(app: Flask) -> None:

    @app.errorhandler(404)
    def not_found(_):
        if request.path.startswith("/api/"):
            return jsonify({"error": "Not found"}), 404
        return render_template("error.html", page="dashboard", page_title="Not found",
                               message="That page does not exist."), 404

    # -- Scanning --------------------------------------------------------

    @app.post("/api/scan/start")
    def api_scan_start():
        payload = request.get_json(silent=True) or {}
        target = (payload.get("url") or "").strip()
        scan_type = payload.get("scan_type") or "full"
        authorised = bool(payload.get("authorised"))

        if not authorised:
            return jsonify({
                "error": "Confirm you own this website or have permission to scan it before starting."
            }), 400

        try:
            normalise_url(target)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

        try:
            status = manager.start(target, scan_type, config.load_settings())
        except RuntimeError as exc:
            return jsonify({"error": str(exc)}), 409
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

        return jsonify(status)

    @app.get("/api/scan/status")
    def api_scan_status():
        return jsonify(manager.status())

    @app.post("/api/scan/cancel")
    def api_scan_cancel():
        manager.cancel()
        return jsonify(manager.status())

    # -- Dashboard -------------------------------------------------------

    @app.get("/api/dashboard")
    def api_dashboard():
        stats = db.dashboard_stats()
        trend = db.monthly_trend(8)
        latest = stats.get("latest_scan")

        latest_payload = None
        if latest:
            latest_payload = {
                "id": latest["id"],
                "target_url": latest["target_url"],
                "display_name": _display_host(latest["target_url"]),
                "when": _relative_time(latest["started_at"]),
                "findings": _finding_count(latest["id"]),
                "score": latest["score"],
                "grade": latest["grade"],
            }

        return jsonify({
            "total_scans": stats["total_scans"],
            "week_scans": stats["week_scans"],
            "active_vulnerabilities": stats["active_vulnerabilities"],
            "counts": stats["counts"],
            "latest": latest_payload,
            "score": latest["score"] if latest else 0,
            "grade": latest["grade"] if latest else "-",
            "max_score": MAX_SCORE,
            "success_rate": stats["success_rate"],
            "trend": [
                {"label": _month_label(row["month"]), "value": row["findings"] or 0,
                 "score": round(row["avg_score"] or 0)}
                for row in trend
            ],
            "priorities": [{
                "title": row["title"],
                "severity": row["severity"],
                "cvss": row["cvss"],
                "difficulty": row["difficulty"],
                "needs_professional": bool(row["needs_professional"]),
                "target": _display_host(row["target_url"]),
                "scan_id": row["scan_id"],
            } for row in db.top_findings(5)],
            "target_score": TARGET_SCORE,
            "has_data": stats["total_scans"] > 0,
        })

    # -- History ---------------------------------------------------------

    @app.get("/api/scans")
    def api_scans():
        search = request.args.get("search", "").strip()
        limit = min(500, int(request.args.get("limit", 100)))
        rows = db.list_scans(limit=limit, search=search)

        return jsonify({
            "scans": [{
                "id": row["id"],
                "target_url": row["target_url"],
                "scan_type": row["scan_type"],
                "started_at": row["started_at"],
                "date_display": _format_datetime(row["started_at"]),
                "status": row["status"],
                "badge": _severity_badge(row),
                "findings": row["findings_count"],
                "score": row["score"],
                "grade": row["grade"],
            } for row in rows],
            "total_completed": sum(1 for r in rows if r["status"] == "completed"),
            "success_rate": db.dashboard_stats()["success_rate"],
            "critical_total": sum(r["critical_count"] for r in rows),
            "unresolved_critical": sum(r["critical_count"] for r in rows[:1]),
        })

    @app.get("/api/scans/<int:scan_id>")
    def api_scan_detail(scan_id: int):
        result = db.get_scan(scan_id)
        if result is None:
            return jsonify({"error": "Scan not found"}), 404

        data = result.to_dict()
        data["summary"] = executive_summary(result)
        data["verdict"] = score_summary(result.score, result.findings)
        data["date_display"] = _format_datetime(result.started_at)
        data["max_score"] = MAX_SCORE
        data["report"] = _existing_report_for(scan_id)
        return jsonify(data)

    @app.delete("/api/scans/<int:scan_id>")
    def api_scan_delete(scan_id: int):
        db.delete_scan(scan_id)
        return jsonify({"ok": True})

    @app.post("/api/scans/<int:scan_id>/findings/resolve")
    def api_resolve_finding(scan_id: int):
        payload = request.get_json(silent=True) or {}
        check_id = payload.get("check_id")
        url = payload.get("url", "")
        resolved = bool(payload.get("resolved"))
        if not check_id:
            return jsonify({"error": "check_id is required"}), 400

        db.set_finding_resolved(scan_id, check_id, url, resolved)

        # Recalculate the stored score so the dashboard reflects the change.
        result = db.get_scan(scan_id)
        if result:
            from .scanner.scoring import calculate_score
            score, grade = calculate_score(result.findings)
            with db.connect() as conn:
                conn.execute("UPDATE scans SET score = ?, grade = ? WHERE id = ?",
                             (score, grade, scan_id))
            return jsonify({"ok": True, "score": score, "grade": grade,
                            "counts": result.counts})
        return jsonify({"ok": True})

    # -- Reports ---------------------------------------------------------

    @app.get("/api/reports")
    def api_reports():
        search = request.args.get("search", "").strip()
        rows = db.list_reports(search=search)
        return jsonify({
            "reports": [{
                "id": row["id"],
                "scan_id": row["scan_id"],
                "title": row["title"],
                "target_url": row["target_url"],
                "display_name": _display_host(row["target_url"]),
                "created_at": row["created_at"],
                "date_display": _format_date_only(row["created_at"]),
                "full_date": _format_datetime(row["created_at"]),
                "status": row["status"],
                "page_count": row["page_count"],
                "summary": row["summary"],
                "has_file": bool(row["file_path"]) and Path(row["file_path"]).exists(),
            } for row in rows],
            "total": db.report_count(),
            "this_month": db.reports_this_month(),
            "scans_completed": db.dashboard_stats()["total_scans"],
            "critical_total": db.dashboard_stats()["counts"]["critical"],
            "score": db.dashboard_stats().get("latest_scan", {}).get("score", 0)
            if db.dashboard_stats().get("latest_scan") else 0,
        })

    @app.post("/api/scans/<int:scan_id>/report")
    def api_generate_report(scan_id: int):
        result = db.get_scan(scan_id)
        if result is None:
            return jsonify({"error": "Scan not found"}), 404
        if result.status != "completed":
            return jsonify({"error": "Only completed scans can be turned into a report."}), 400

        settings = config.load_settings()
        try:
            path = build_pdf_report(result, business_name=settings.get("business_name", ""))
        except Exception as exc:  # noqa: BLE001
            return jsonify({"error": f"The report could not be created: {exc}"}), 500

        report_id = db.create_report(
            scan_id=scan_id,
            title=f"Security Assessment - {_display_host(result.target_url)}",
            target_url=result.target_url,
            file_path=str(path),
            page_count=estimate_page_count(path),
            summary=executive_summary(result),
        )
        return jsonify({"ok": True, "report_id": report_id,
                        "download_url": url_for("api_download_report", report_id=report_id)})

    @app.get("/api/reports/<int:report_id>/download")
    def api_download_report(report_id: int):
        report = db.get_report(report_id)
        if report is None or not report["file_path"]:
            return jsonify({"error": "Report file not found"}), 404

        path = Path(report["file_path"])
        if not path.exists():
            return jsonify({"error": "The report file has been moved or deleted."}), 404

        return send_file(path, as_attachment=True, download_name=path.name,
                         mimetype="application/pdf")

    @app.post("/api/reports/<int:report_id>/reveal")
    def api_reveal_report(report_id: int):
        """Open the report in the operating system's default PDF viewer."""
        report = db.get_report(report_id)
        if report is None or not report["file_path"]:
            return jsonify({"error": "Report file not found"}), 404
        path = Path(report["file_path"])
        if not path.exists():
            return jsonify({"error": "The report file has been moved or deleted."}), 404
        try:
            webbrowser.open(path.as_uri())
        except Exception as exc:  # noqa: BLE001
            return jsonify({"error": str(exc)}), 500
        return jsonify({"ok": True})

    @app.delete("/api/reports/<int:report_id>")
    def api_delete_report(report_id: int):
        db.delete_report(report_id)
        return jsonify({"ok": True})

    # -- Settings and data ----------------------------------------------

    @app.get("/api/settings")
    def api_get_settings():
        settings = config.load_settings()
        settings["has_demo_data"] = db.has_demo_data()
        settings["data_dir"] = str(config.data_dir())
        settings["reports_dir"] = str(config.reports_dir())
        settings["version"] = __version__
        settings["engine"] = "VulnGuard (built in)"
        return jsonify(settings)

    @app.post("/api/settings")
    def api_save_settings():
        payload = request.get_json(silent=True) or {}
        cleaned: dict[str, Any] = {}

        for key in ("max_pages", "request_timeout"):
            if key in payload:
                try:
                    cleaned[key] = max(1, min(500, int(payload[key])))
                except (TypeError, ValueError):
                    pass

        if "requests_per_second" in payload:
            try:
                cleaned["requests_per_second"] = max(0.5, min(50.0, float(payload["requests_per_second"])))
            except (TypeError, ValueError):
                pass

        for key in ("respect_robots", "follow_redirects", "verify_tls_errors"):
            if key in payload:
                cleaned[key] = bool(payload[key])

        for key in ("business_name", "report_footer"):
            if key in payload:
                cleaned[key] = str(payload[key])[:120]

        return jsonify(config.save_settings(cleaned))

    @app.post("/api/demo/clear")
    def api_clear_demo():
        removed = db.clear_demo_data()
        config.save_settings({"demo_data_loaded": False})
        return jsonify({"ok": True, "removed": removed})

    @app.post("/api/demo/load")
    def api_load_demo():
        if not db.has_demo_data():
            demo.seed()
        config.save_settings({"demo_data_loaded": True})
        return jsonify({"ok": True})

    @app.post("/api/data/clear")
    def api_clear_all():
        db.clear_all_data()
        config.save_settings({"demo_data_loaded": False})
        return jsonify({"ok": True})

    @app.get("/api/health")
    def api_health():
        return jsonify({"status": "ok", "version": __version__})


# --------------------------------------------------------------------------
# Formatting helpers
# --------------------------------------------------------------------------

def _finding_count(scan_id: int) -> int:
    with db.connect() as conn:
        return conn.execute(
            "SELECT COUNT(*) AS c FROM findings WHERE scan_id = ? AND resolved = 0"
            " AND severity != 'info'", (scan_id,)
        ).fetchone()["c"]


def _existing_report_for(scan_id: int) -> dict[str, Any] | None:
    with db.connect() as conn:
        row = conn.execute(
            "SELECT * FROM reports WHERE scan_id = ? ORDER BY id DESC LIMIT 1", (scan_id,)
        ).fetchone()
    if row is None:
        return None
    return {"id": row["id"], "title": row["title"],
            "has_file": bool(row["file_path"]) and Path(row["file_path"]).exists()}


def _severity_badge(row) -> str:
    """The status word shown in the scan history table."""
    if row["status"] != "completed":
        return row["status"].upper()
    if row["critical_count"]:
        return "CRITICAL"
    if row["high_count"]:
        return "HIGH"
    if row["medium_count"]:
        return "MEDIUM"
    if row["findings_count"]:
        return "LOW"
    return "SAFE"


def _display_host(url: str) -> str:
    from urllib.parse import urlparse
    parsed = urlparse(url)
    return parsed.netloc or url


def _parse(iso: str) -> datetime | None:
    try:
        value = datetime.fromisoformat(iso)
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


def _format_datetime(iso: str) -> str:
    value = _parse(iso)
    return value.astimezone().strftime("%Y-%m-%d %H:%M") if value else (iso or "")


def _format_date_only(iso: str) -> str:
    value = _parse(iso)
    return value.astimezone().strftime("%Y-%m-%d") if value else (iso or "")


def _month_label(month: str) -> str:
    try:
        return datetime.strptime(month, "%Y-%m").strftime("%b")
    except (ValueError, TypeError):
        return month or ""


def _relative_time(iso: str) -> str:
    value = _parse(iso)
    if value is None:
        return ""
    delta = datetime.now(timezone.utc) - value
    seconds = int(delta.total_seconds())

    if seconds < 60:
        return "just now"
    if seconds < 3600:
        minutes = seconds // 60
        return f"{minutes} min{'s' if minutes != 1 else ''} ago"
    if seconds < 86400:
        hours = seconds // 3600
        return f"{hours} hour{'s' if hours != 1 else ''} ago"
    days = seconds // 86400
    if days < 30:
        return f"{days} day{'s' if days != 1 else ''} ago"
    months = days // 30
    return f"{months} month{'s' if months != 1 else ''} ago"
