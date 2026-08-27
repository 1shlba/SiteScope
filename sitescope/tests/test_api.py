"""Tests for the JSON API and the page routes."""

from __future__ import annotations

import time

import pytest

from sitescope import db
from sitescope.models import Finding, ScanResult, utcnow
from sitescope.scanner.scoring import calculate_score


def seed_scan(target="https://example.com/", cvss=9.8, resolved=False) -> int:
    scan_id = db.create_scan(target, "full")
    finding = Finding(
        check_id="exposed-env",
        title="Configuration file containing passwords is publicly readable",
        severity="critical", cvss=cvss,
        owasp="A05:2021 Security Misconfiguration",
        url=target, evidence="test",
        what_it_means="x", why_it_matters="y", how_to_fix=["step one", "step two"],
        resolved=resolved,
    )
    score, grade = calculate_score([finding])
    result = ScanResult(
        target_url=target, status="completed", findings=[finding],
        pages_scanned=3, requests_sent=12, score=score, grade=grade,
        finished_at=utcnow(),
    )
    db.finish_scan(scan_id, result)
    return scan_id


# --------------------------------------------------------------------------
# Pages
# --------------------------------------------------------------------------

@pytest.mark.parametrize("path", ["/", "/new-scan", "/history", "/reports", "/settings"])
def test_pages_render(client, path):
    response = client.get(path)
    assert response.status_code == 200
    assert b"SiteScope" in response.data


def test_unknown_page_returns_404(client):
    assert client.get("/no-such-page").status_code == 404


def test_unknown_api_route_returns_json(client):
    response = client.get("/api/no-such-endpoint")
    assert response.status_code == 404
    assert response.json["error"]


def test_scan_detail_page_404s_for_a_missing_scan(client):
    assert client.get("/scan/999999").status_code == 404


# --------------------------------------------------------------------------
# Authorisation gate
# --------------------------------------------------------------------------

def test_scan_refused_without_authorisation(client):
    """The consent checkbox is enforced server-side, not only in the browser."""
    response = client.post("/api/scan/start", json={
        "url": "https://example.com", "scan_type": "quick", "authorised": False,
    })
    assert response.status_code == 400
    assert "permission" in response.json["error"].lower()


def test_scan_refused_when_authorisation_field_is_absent(client):
    response = client.post("/api/scan/start", json={"url": "https://example.com"})
    assert response.status_code == 400


def test_invalid_url_is_rejected(client):
    response = client.post("/api/scan/start", json={
        "url": "not a url at all", "authorised": True,
    })
    assert response.status_code == 400


def test_empty_url_is_rejected(client):
    response = client.post("/api/scan/start", json={"url": "", "authorised": True})
    assert response.status_code == 400


# --------------------------------------------------------------------------
# Dashboard and history
# --------------------------------------------------------------------------

def test_dashboard_on_an_empty_database(client):
    data = client.get("/api/dashboard").json
    assert data["total_scans"] == 0
    assert data["active_vulnerabilities"] == 0
    assert data["latest"] is None
    assert data["has_data"] is False


def test_dashboard_reflects_a_recorded_scan(client):
    seed_scan()
    data = client.get("/api/dashboard").json

    assert data["total_scans"] == 1
    assert data["counts"]["critical"] == 1
    assert data["latest"]["display_name"] == "example.com"
    assert data["priorities"]
    assert data["priorities"][0]["severity"] == "critical"


def test_resolved_findings_leave_the_dashboard(client):
    seed_scan(resolved=True)
    data = client.get("/api/dashboard").json
    assert data["active_vulnerabilities"] == 0


def test_history_lists_and_searches(client):
    seed_scan("https://alpha.example.com/")
    seed_scan("https://beta.example.com/")

    everything = client.get("/api/scans").json
    assert len(everything["scans"]) == 2

    filtered = client.get("/api/scans?search=alpha").json
    assert len(filtered["scans"]) == 1
    assert "alpha" in filtered["scans"][0]["target_url"]


def test_scan_detail_includes_plain_language_summary(client):
    scan_id = seed_scan()
    data = client.get(f"/api/scans/{scan_id}").json

    assert data["target_url"] == "https://example.com/"
    assert len(data["findings"]) == 1
    assert data["summary"]
    assert data["verdict"]
    assert data["findings"][0]["how_to_fix"]


def test_missing_scan_returns_404(client):
    assert client.get("/api/scans/999999").status_code == 404


# --------------------------------------------------------------------------
# Marking findings as fixed
# --------------------------------------------------------------------------

def test_marking_a_finding_fixed_raises_the_score(client):
    scan_id = seed_scan()
    before = client.get(f"/api/scans/{scan_id}").json["score"]

    response = client.post(f"/api/scans/{scan_id}/findings/resolve", json={
        "check_id": "exposed-env", "url": "https://example.com/", "resolved": True,
    })
    assert response.status_code == 200
    assert response.json["score"] > before
    assert response.json["counts"]["critical"] == 0


def test_resolve_requires_a_check_id(client):
    scan_id = seed_scan()
    response = client.post(f"/api/scans/{scan_id}/findings/resolve", json={"resolved": True})
    assert response.status_code == 400


# --------------------------------------------------------------------------
# Reports
# --------------------------------------------------------------------------

def test_report_generation_produces_a_downloadable_pdf(client):
    scan_id = seed_scan()

    created = client.post(f"/api/scans/{scan_id}/report")
    assert created.status_code == 200
    report_id = created.json["report_id"]

    listing = client.get("/api/reports").json
    assert listing["total"] == 1
    assert listing["reports"][0]["has_file"] is True

    download = client.get(f"/api/reports/{report_id}/download")
    assert download.status_code == 200
    assert download.data[:4] == b"%PDF"


def test_report_cannot_be_generated_for_an_unfinished_scan(client):
    scan_id = db.create_scan("https://example.com/", "full")  # left running
    response = client.post(f"/api/scans/{scan_id}/report")
    assert response.status_code == 400


def test_report_can_be_deleted(client):
    scan_id = seed_scan()
    report_id = client.post(f"/api/scans/{scan_id}/report").json["report_id"]

    assert client.delete(f"/api/reports/{report_id}").status_code == 200
    assert client.get("/api/reports").json["total"] == 0


# --------------------------------------------------------------------------
# Settings and data management
# --------------------------------------------------------------------------

def test_settings_round_trip(client):
    saved = client.post("/api/settings", json={"max_pages": 40, "respect_robots": False}).json
    assert saved["max_pages"] == 40
    assert saved["respect_robots"] is False

    assert client.get("/api/settings").json["max_pages"] == 40


def test_settings_values_are_clamped_to_a_sane_range(client):
    saved = client.post("/api/settings", json={
        "max_pages": 100000, "requests_per_second": 9999,
    }).json
    assert saved["max_pages"] <= 500
    assert saved["requests_per_second"] <= 50


def test_settings_ignores_unknown_keys(client):
    saved = client.post("/api/settings", json={"evil_key": "value"}).json
    assert "evil_key" not in saved


def test_clearing_demo_data_keeps_real_scans(client):
    from sitescope import demo

    demo.seed()
    real_scan = seed_scan("https://mysite.example/")
    assert db.has_demo_data()

    client.post("/api/demo/clear")

    assert not db.has_demo_data()
    assert db.get_scan(real_scan) is not None


def test_clear_all_removes_everything(client):
    seed_scan()
    client.post("/api/data/clear")
    assert client.get("/api/scans").json["scans"] == []


def test_health_endpoint(client):
    data = client.get("/api/health").json
    assert data["status"] == "ok"
    assert data["version"]


# --------------------------------------------------------------------------
# Live scan through the API
# --------------------------------------------------------------------------

def test_full_scan_lifecycle_through_the_api(client, vulnerable_site):
    started = client.post("/api/scan/start", json={
        "url": vulnerable_site, "scan_type": "quick", "authorised": True,
    })
    assert started.status_code == 200
    assert started.json["active"] is True

    # A second scan must be refused while the first is running.
    conflict = client.post("/api/scan/start", json={
        "url": vulnerable_site, "scan_type": "quick", "authorised": True,
    })
    assert conflict.status_code == 409

    for _ in range(120):
        status = client.get("/api/scan/status").json
        if not status["active"]:
            break
        time.sleep(0.5)
    else:
        pytest.fail("The scan did not finish within 60 seconds")

    assert status["result"]["status"] == "completed"
    assert status["logs"]

    detail = client.get(f"/api/scans/{status['scan_id']}").json
    assert detail["findings"]


def test_two_reports_for_one_site_do_not_share_a_file(client):
    """Generated within the same second, each report must keep its own file."""
    scan_id = seed_scan("https://collision.example.com/")

    first = client.post(f"/api/scans/{scan_id}/report").json["report_id"]
    second = client.post(f"/api/scans/{scan_id}/report").json["report_id"]

    paths = {db.get_report(first)["file_path"], db.get_report(second)["file_path"]}
    assert len(paths) == 2, "the second report overwrote the first"

    for report_id in (first, second):
        response = client.get(f"/api/reports/{report_id}/download")
        assert response.status_code == 200
        assert response.data[:4] == b"%PDF"
