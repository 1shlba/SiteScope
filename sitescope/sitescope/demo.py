"""Seeded sample data.

A fresh install is populated with a plausible history so the dashboard, history
and reports screens are meaningful before the first real scan - useful for
demonstrations and for evaluating the interface.

Everything created here is tagged `is_demo = 1` in the database and can be
removed in one click from Settings, which leaves any real scans untouched.

The target addresses used below are all reserved example domains under
RFC 2606 / RFC 6761, so nothing here refers to a real website.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

from . import db
from .models import Finding, ScanResult
from .reporting.pdf import build_pdf_report, executive_summary
from .scanner.knowledge import build_finding
from .scanner.scoring import calculate_score

# Fictional targets, all on reserved example domains.
DEMO_TARGETS = [
    ("https://shop.example.com/", [
        "header-missing-csp", "header-missing-hsts", "cookie-missing-samesite",
        "info-powered-by", "header-missing-referrer", "missing-security-txt",
    ]),
    ("https://www.example.com/", [
        "header-missing-xcto", "header-missing-permissions", "missing-security-txt",
    ]),
    ("https://booking.example.net/", [
        "tls-cert-expiring", "header-missing-csp", "header-missing-xfo",
        "cookie-missing-httponly", "info-server-version", "header-missing-referrer",
        "cache-sensitive-page",
    ]),
    ("https://legacy.example.org/", [
        "exposed-env", "tls-no-redirect", "info-outdated-component",
        "directory-listing", "header-missing-csp", "header-missing-hsts",
        "header-missing-xfo", "cookie-missing-secure", "cookie-missing-httponly",
        "info-server-version", "info-email-disclosure", "missing-security-txt",
    ]),
    ("https://mail.example.com/", [
        "header-missing-hsts", "cookie-missing-samesite", "info-powered-by",
    ]),
]

EVIDENCE = {
    "header-missing-csp": "No Content-Security-Policy header was returned by the site.",
    "header-missing-hsts": "No Strict-Transport-Security header was returned by the site.",
    "header-missing-xfo": "Neither X-Frame-Options nor a frame-ancestors directive was returned.",
    "header-missing-xcto": "No X-Content-Type-Options header was returned by the site.",
    "header-missing-referrer": "No Referrer-Policy header was returned by the site.",
    "header-missing-permissions": "No Permissions-Policy header was returned by the site.",
    "cookie-missing-secure": "Cookie(s) set without the Secure attribute: SESSIONID, cart_ref.",
    "cookie-missing-httponly": "Cookie(s) set without the HttpOnly attribute: SESSIONID.",
    "cookie-missing-samesite": "Cookie(s) set without a SameSite attribute: SESSIONID, pref.",
    "info-powered-by": "The site returns 'X-Powered-By: PHP/8.1.2', naming the technology behind it.",
    "info-server-version": "The site returns the header 'Server: Apache/2.4.41 (Ubuntu)'.",
    "info-email-disclosure": "3 email address(es) found in page source: info@example.org, sales@example.org.",
    "info-outdated-component": "The page declares generator 'WordPress 5.8.1', behind the 6.x series.",
    "missing-security-txt": "No security.txt file was found at either standard location.",
    "tls-cert-expiring": "The certificate expires on 14 September 2026, in 19 days.",
    "tls-no-redirect": "http:// returned HTTP 200 and served the page directly.",
    "exposed-env": "https://legacy.example.org/.env returned HTTP 200 with 412 bytes of content.",
    "directory-listing": "https://legacy.example.org/uploads/ displays a browsable file listing.",
    "cache-sensitive-page": "A page showing account content returned 'Cache-Control: (not set)'.",
}


def seed_if_empty() -> bool:
    """Populate sample data on a fresh install. Returns True if data was added."""
    if db.list_scans(limit=1):
        return False
    seed()
    return True


def seed() -> None:
    """Create the sample scan history, findings and reports."""
    rng = random.Random(20260826)  # fixed seed: the demo looks the same every install
    now = datetime.now(timezone.utc)

    generated: list[tuple[int, ScanResult]] = []

    # Eight months of history, so the dashboard trend chart has a shape.
    for month_offset in range(7, -1, -1):
        month_start = now - timedelta(days=30 * month_offset)
        scans_this_month = rng.randint(2, 4)

        for _ in range(scans_this_month):
            target, check_ids = rng.choice(DEMO_TARGETS)
            when = month_start + timedelta(
                days=rng.randint(0, 27), hours=rng.randint(8, 19), minutes=rng.randint(0, 59)
            )
            if when > now:
                when = now - timedelta(hours=rng.randint(1, 40))

            # Earlier scans carry more issues, so the trend shows improvement.
            severity_bias = min(len(check_ids), max(2, len(check_ids) - (7 - month_offset) // 2))
            selected = check_ids[:severity_bias]

            result = _build_result(target, selected, when, rng)
            scan_id = _insert(result, when)
            generated.append((scan_id, result))

    # Reports for the four most recent completed scans.
    generated.sort(key=lambda pair: pair[1].started_at, reverse=True)
    for index, (scan_id, result) in enumerate(generated[:4]):
        _create_demo_report(scan_id, result, index)


def _build_result(target: str, check_ids: list[str], when: datetime, rng: random.Random) -> ScanResult:
    findings: list[Finding] = []
    for check_id in check_ids:
        try:
            findings.append(build_finding(
                check_id, target, evidence=EVIDENCE.get(check_id, "Detected during automated assessment.")
            ))
        except KeyError:
            continue

    score, grade = calculate_score(findings)
    duration = timedelta(seconds=rng.randint(38, 240))

    result = ScanResult(
        target_url=target,
        scan_type=rng.choice(["full", "full", "quick"]),
        started_at=when.replace(microsecond=0).isoformat(),
        finished_at=(when + duration).replace(microsecond=0).isoformat(),
        status="completed",
        findings=findings,
        pages_scanned=rng.randint(4, 25),
        requests_sent=rng.randint(60, 340),
        score=score,
        grade=grade,
    )
    return result


def _insert(result: ScanResult, when: datetime) -> int:
    scan_id = db.create_scan(result.target_url, result.scan_type, is_demo=True)
    db.finish_scan(scan_id, result)
    # create_scan stamps 'now'; rewrite it so the history spans several months.
    with db.connect() as conn:
        conn.execute(
            "UPDATE scans SET started_at = ? WHERE id = ?",
            (result.started_at, scan_id),
        )
    return scan_id


def _create_demo_report(scan_id: int, result: ScanResult, index: int) -> None:
    """Generate a real PDF for the sample scans so 'Download' works in the demo."""
    titles = [
        "Q3 Security Audit - Production",
        "Compliance Review",
        "Weekly Vulnerability Summary",
        "Monthly Executive Summary",
    ]
    result.scan_id = scan_id

    try:
        path = build_pdf_report(result)
        from .reporting.pdf import estimate_page_count
        pages = estimate_page_count(path)
        file_path = str(path)
        status = "ready"
    except Exception:
        file_path, pages, status = "", 0, "ready"

    db.create_report(
        scan_id=scan_id,
        title=titles[index % len(titles)],
        target_url=result.target_url,
        file_path=file_path,
        page_count=pages,
        summary=executive_summary(result),
        status=status,
        is_demo=True,
    )
    with db.connect() as conn:
        conn.execute(
            "UPDATE reports SET created_at = ? WHERE scan_id = ?",
            (result.finished_at or result.started_at, scan_id),
        )
