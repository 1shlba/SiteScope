"""Scanner tests, including a full scan against the local insecure sample site."""

from __future__ import annotations

import pytest

from sitescope.models import Finding
from sitescope.scanner.base import dedupe, normalise_url, same_host
from sitescope.scanner.engine import BuiltinEngine


# --------------------------------------------------------------------------
# URL handling
# --------------------------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("example.com", "https://example.com/"),
    ("  example.com  ", "https://example.com/"),
    ("http://example.com", "http://example.com/"),
    ("https://example.com/shop", "https://example.com/shop"),
    ("example.com/a/b", "https://example.com/a/b"),
    ("https://example.com/search?q=1", "https://example.com/search?q=1"),
    ("https://example.com/page#section", "https://example.com/page"),
])
def test_normalise_url(raw, expected):
    assert normalise_url(raw) == expected


@pytest.mark.parametrize("raw", [
    "", "   ",
    "ftp://example.com",
    "file:///c:/windows/system32",
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "https://",
    "not a url at all",
    "https://exa mple.com",
    "https://example.com:notaport",
    "https://-badstart.com",
])
def test_normalise_url_rejects_bad_input(raw):
    with pytest.raises(ValueError):
        normalise_url(raw)


@pytest.mark.parametrize("raw,expected", [
    ("example.com:8080", "https://example.com:8080/"),      # host:port is not a scheme
    ("127.0.0.1:8099", "https://127.0.0.1:8099/"),
    ("localhost", "https://localhost/"),
])
def test_normalise_url_accepts_ports_and_bare_hosts(raw, expected):
    assert normalise_url(raw) == expected


def test_same_host_ignores_www():
    assert same_host("https://example.com/a", "https://www.example.com/b")
    assert same_host("https://www.example.com/a", "https://www.example.com/b")
    assert not same_host("https://example.com/", "https://other.com/")


@pytest.mark.parametrize("other", [
    "https://ww.example.com/",        # not a www prefix
    "https://wwexample.com/",
    "https://web.example.com/",       # begins with 'w' but is a real subdomain
    "https://shop.example.com/",
    "https://example.com.evil.net/",  # suffix attack
    "https://notexample.com/",
])
def test_same_host_does_not_let_the_crawler_escape(other):
    """The crawler must stay on the target host.

    A prefix-stripping bug here would let a scan wander onto other sites, which
    is both a correctness problem and an authorisation problem.
    """
    assert not same_host("https://example.com/", other)


# --------------------------------------------------------------------------
# Deduplication
# --------------------------------------------------------------------------

def _finding(check_id: str, title: str, cvss: float = 5.0) -> Finding:
    return Finding(check_id=check_id, title=title, severity="medium", cvss=cvss,
                   owasp="A05:2021 Security Misconfiguration", url="https://example.com/")


def test_dedupe_collapses_repeats_and_counts_them():
    findings = [_finding("h", "Missing header") for _ in range(4)]
    result = dedupe(findings)

    assert len(result) == 1
    assert "3 other pages" in result[0].evidence


def test_dedupe_orders_by_severity():
    result = dedupe([
        _finding("low", "Low issue", 2.0),
        _finding("crit", "Critical issue", 9.8),
        _finding("med", "Medium issue", 5.0),
    ])
    assert [f.cvss for f in result] == [9.8, 5.0, 2.0]


def test_dedupe_keeps_distinct_issues_separate():
    result = dedupe([_finding("a", "First"), _finding("b", "Second")])
    assert len(result) == 2


# --------------------------------------------------------------------------
# Full scan against the sample site
# --------------------------------------------------------------------------

@pytest.fixture(scope="module")
def scan_result(request):
    """Run one scan and share it across the assertions below."""
    site = request.getfixturevalue("vulnerable_site")
    from sitescope.config import DEFAULT_SETTINGS

    settings = dict(DEFAULT_SETTINGS)
    settings.update(requests_per_second=100.0, max_pages=8, request_timeout=5)

    return BuiltinEngine().run(site, settings, "full")


def test_scan_completes(scan_result):
    assert scan_result.status == "completed"
    assert scan_result.pages_scanned > 0
    assert scan_result.requests_sent > 0
    assert scan_result.finished_at is not None


@pytest.mark.parametrize("check_id", [
    "exposed-env",              # .env with credentials
    "exposed-git",              # .git repository
    "exposed-phpinfo",          # diagnostic page
    "directory-listing",        # browsable /uploads/
    "tls-not-available",        # plain HTTP only
    "password-over-http",       # login form without encryption
    "header-missing-csp",       # no content security policy
    "cookie-missing-httponly",  # session cookie readable by scripts
    "cors-credentials-wildcard",# wildcard CORS with credentials
    "info-outdated-component",  # old WordPress generator tag
    "info-error-disclosure",    # database error on the page
    "info-html-comments",       # comment containing a password
])
def test_planted_vulnerability_is_detected(scan_result, check_id):
    """Each issue deliberately planted in the sample site must be found."""
    found = {finding.check_id for finding in scan_result.findings}
    assert check_id in found, f"{check_id} was not detected"


def test_findings_are_ordered_most_severe_first(scan_result):
    scores = [finding.cvss for finding in scan_result.findings]
    assert scores == sorted(scores, reverse=True)


def test_insecure_site_scores_badly(scan_result):
    assert scan_result.score < 400
    assert scan_result.grade in ("D", "F")
    assert scan_result.counts["critical"] >= 2


def test_every_finding_carries_guidance(scan_result):
    for finding in scan_result.findings:
        assert finding.what_it_means, f"{finding.check_id} has no explanation"
        assert finding.why_it_matters, f"{finding.check_id} has no business impact"
        assert finding.how_to_fix, f"{finding.check_id} has no remediation steps"
        assert finding.owasp
        assert finding.url


def test_no_duplicate_findings(scan_result):
    keys = [(f.check_id, f.title) for f in scan_result.findings]
    assert len(keys) == len(set(keys))


def test_unreachable_target_fails_cleanly(scan_settings):
    """A dead address must produce a failed scan, not an exception."""
    result = BuiltinEngine().run("http://127.0.0.1:1/", scan_settings, "quick")

    assert result.status == "failed"
    assert result.error
    assert result.findings == []


def test_quick_scan_is_lighter_than_a_full_scan(vulnerable_site, scan_settings):
    quick = BuiltinEngine().run(vulnerable_site, scan_settings, "quick")
    full = BuiltinEngine().run(vulnerable_site, scan_settings, "full")

    assert quick.status == "completed"
    assert quick.requests_sent < full.requests_sent


def test_scan_can_be_cancelled(vulnerable_site, scan_settings):
    import threading

    cancelled = threading.Event()
    cancelled.set()  # already cancelled before the first request

    result = BuiltinEngine().run(vulnerable_site, scan_settings, "full", cancelled=cancelled)
    assert result.status in ("cancelled", "failed")
