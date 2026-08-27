"""Discovery of files and folders that should not be reachable from the web.

Every probe here is an ordinary GET request for a well-known path - the same
thing a search engine crawler or an automated bot does thousands of times a day.
Nothing is uploaded, modified or exploited.

The main source of false positives in this kind of check is the "soft 404":
a site that answers every unknown address with a friendly page and an HTTP 200
status. The check therefore fingerprints the site's response to a deliberately
random path first, and treats anything resembling it as not-found.
"""

from __future__ import annotations

import re
import uuid

from ...models import Finding
from ..base import BaseCheck, Page, ScanContext
from ..knowledge import build_finding

# path, knowledge base id, signature that must appear for a positive result
SENSITIVE_PATHS: list[tuple[str, str, re.Pattern | None]] = [
    ("/.git/HEAD", "exposed-git", re.compile(r"^ref:\s+refs/", re.IGNORECASE)),
    ("/.git/config", "exposed-git", re.compile(r"\[core\]|\[remote", re.IGNORECASE)),
    ("/.env", "exposed-env", re.compile(r"^\s*[A-Z0-9_]+\s*=", re.MULTILINE)),
    ("/.env.local", "exposed-env", re.compile(r"^\s*[A-Z0-9_]+\s*=", re.MULTILINE)),
    ("/config.php.bak", "exposed-backup", None),
    ("/wp-config.php.bak", "exposed-backup", None),
    ("/backup.zip", "exposed-backup", None),
    ("/backup.sql", "exposed-database-dump", None),
    ("/database.sql", "exposed-database-dump", None),
    ("/dump.sql", "exposed-database-dump", None),
    ("/db.sqlite", "exposed-database-dump", None),
    ("/phpinfo.php", "exposed-phpinfo", re.compile(r"phpinfo\(\)|PHP Version", re.IGNORECASE)),
    ("/info.php", "exposed-phpinfo", re.compile(r"phpinfo\(\)|PHP Version", re.IGNORECASE)),
    ("/web.config", "exposed-config-file", re.compile(r"<configuration", re.IGNORECASE)),
    ("/.htaccess", "exposed-config-file", re.compile(r"RewriteEngine|Options |AuthType", re.IGNORECASE)),
    ("/composer.json", "exposed-config-file", re.compile(r'"require"|"autoload"', re.IGNORECASE)),
    ("/package.json", "exposed-config-file", re.compile(r'"dependencies"|"scripts"', re.IGNORECASE)),
    ("/.DS_Store", "exposed-config-file", None),
]

# Administration entry points. Their presence is normal; it is worth one
# low-severity note about brute-force protection rather than an alarm.
ADMIN_PATHS = [
    "/wp-admin/", "/wp-login.php", "/administrator/", "/admin/", "/admin/login",
    "/user/login", "/login", "/cpanel", "/phpmyadmin/",
]

DIRECTORY_PATHS = ["/uploads/", "/images/", "/files/", "/backup/", "/assets/", "/documents/", "/media/"]

DIRECTORY_LISTING_RE = re.compile(
    r"(<title>\s*Index of /|<h1>\s*Index of /|Directory Listing For|"
    r"\[To Parent Directory\])",
    re.IGNORECASE,
)


class _ProbeMixin:
    """Shared soft-404 fingerprinting used by the discovery checks."""

    def _fingerprint_missing(self, ctx: ScanContext) -> tuple[int, int, str]:
        """Learn how the site responds to a path that definitely does not exist."""
        cached = ctx.notes.get("missing_fingerprint")
        if cached:
            return cached

        random_path = f"/sitescope-not-found-{uuid.uuid4().hex[:12]}"
        page = ctx.fetch(f"{ctx.origin}{random_path}", allow_redirects=True)
        fingerprint = (page.status_code, len(page.body), _title_of(page.body))
        ctx.notes["missing_fingerprint"] = fingerprint

        if page.status_code == 200:
            ctx.log("Site returns HTTP 200 for missing pages - using content matching instead.", "WARN")
        return fingerprint

    def _looks_missing(self, ctx: ScanContext, page: Page) -> bool:
        """True when a response is really a not-found page in disguise."""
        if page.error or page.status_code in (404, 410):
            return True
        if page.status_code in (401, 403):
            return True  # exists but is protected, which is the desired state
        if page.status_code >= 500 or page.status_code == 0:
            return True

        status, length, title = self._fingerprint_missing(ctx)
        if page.status_code == status:
            # Same status as a known-missing path: compare size and title.
            if title and title == _title_of(page.body):
                return True
            if length and abs(len(page.body) - length) < max(64, length * 0.05):
                return True
        return False


class ExposedFilesCheck(_ProbeMixin, BaseCheck):
    """Probe for well-known sensitive files left in the public web folder."""

    check_id = "exposed-files"
    name = "Exposed file discovery"
    phase = "Exposed File Discovery"

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        already_reported: set[str] = set()

        self._fingerprint_missing(ctx)
        ctx.log(f"Probing {len(SENSITIVE_PATHS)} well-known sensitive paths.")

        for path, knowledge_id, signature in SENSITIVE_PATHS:
            if knowledge_id in already_reported:
                continue  # one finding per issue class is enough

            page = ctx.fetch(f"{ctx.origin}{path}", allow_redirects=False)
            if self._looks_missing(ctx, page):
                continue
            if page.status_code != 200:
                continue

            # A signature-less probe must at least not be an HTML page, or we
            # are looking at the site's own error template.
            if signature is None:
                if page.is_html or not page.body.strip():
                    continue
            elif not signature.search(page.body[:4000]):
                continue

            already_reported.add(knowledge_id)
            ctx.log(f"Sensitive file reachable: {path}", "ALERT")
            findings.append(build_finding(
                knowledge_id, f"{ctx.origin}{path}",
                evidence=(
                    f"{ctx.origin}{path} returned HTTP 200 with {len(page.body)} bytes "
                    f"of content.\nFirst characters received: "
                    f"{_snippet(page.body)}"
                ),
            ))

        findings.extend(self._check_admin_pages(ctx))
        if not findings:
            ctx.log("No sensitive files found in the public web folder.")
        return findings

    def _check_admin_pages(self, ctx: ScanContext) -> list[Finding]:
        for path in ADMIN_PATHS:
            page = ctx.fetch(f"{ctx.origin}{path}", allow_redirects=True)
            if self._looks_missing(ctx, page) or page.status_code != 200:
                continue
            if not re.search(r"""type\s*=\s*["']password["']""", page.body, re.IGNORECASE):
                continue

            ctx.log(f"Administrator login page found at {path}")
            return [build_finding(
                "exposed-admin-panel", f"{ctx.origin}{path}",
                evidence=(
                    f"An administrator login form is publicly reachable at {ctx.origin}{path}. "
                    f"This is expected for most websites - the point is to make sure it is "
                    f"protected by two-factor authentication and lockout after failed attempts."
                ),
            )]
        return []


class DirectoryListingCheck(_ProbeMixin, BaseCheck):
    """Detect folders that display their contents instead of a page."""

    check_id = "directory-listing"
    name = "Directory listing"
    phase = "Exposed File Discovery"
    quick_scan = False

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []

        for path in DIRECTORY_PATHS:
            page = ctx.fetch(f"{ctx.origin}{path}", allow_redirects=True)
            if self._looks_missing(ctx, page) or page.status_code != 200:
                continue
            if not DIRECTORY_LISTING_RE.search(page.body):
                continue

            entries = re.findall(r'<a\s+href="([^"?/][^"]*)"', page.body)[:10]
            ctx.log(f"Directory browsing enabled at {path}", "ALERT")
            findings.append(build_finding(
                "directory-listing", f"{ctx.origin}{path}",
                evidence=(
                    f"{ctx.origin}{path} displays a browsable file listing.\n"
                    f"Visible entries include: {', '.join(entries[:8]) if entries else 'unknown'}"
                ),
            ))

        return findings


def _title_of(body: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
    return " ".join(match.group(1).split())[:120] if match else ""


def _snippet(body: str, limit: int = 160) -> str:
    text = " ".join(body[: limit * 2].split())
    return (text[:limit] + "...") if len(text) > limit else text
