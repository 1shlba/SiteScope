"""Server configuration checks: CORS, HTTP methods, caching, security contact."""

from __future__ import annotations

import re
from urllib.parse import urlparse

from ...models import Finding
from ..base import BaseCheck, ScanContext
from ..knowledge import build_finding

SENSITIVE_PATH_RE = re.compile(
    r"(admin|login|account|dashboard|private|internal|staff|manage|cpanel|"
    r"backup|config|billing|invoice|customer|user)",
    re.IGNORECASE,
)

# Signals that a page is showing content belonging to a signed-in user.
# Deliberately narrow: a navigation link reading "My Account" appears on every
# page of most sites and is not evidence that the current page is private.
SENSITIVE_PAGE_CONTENT_RE = re.compile(
    r"""(<input\b[^>]*type\s*=\s*["']password["']|\b(?:log\s?out|sign\s?out)\b)""",
    re.IGNORECASE,
)


class CorsPolicyCheck(BaseCheck):
    """Check which other websites are permitted to read this site's responses."""

    check_id = "cors"
    name = "Cross-origin resource sharing"
    phase = "Server Configuration"

    def run(self, ctx: ScanContext) -> list[Finding]:
        if not ctx.pages:
            return []

        target = ctx.pages[0].final_url
        # Ask the server how it treats a request claiming to come from elsewhere.
        page = ctx.fetch(target, extra_headers={"Origin": "https://sitescope-cors-probe.example"})

        allow_origin = page.header("Access-Control-Allow-Origin")
        allow_credentials = page.header("Access-Control-Allow-Credentials").lower() == "true"

        if not allow_origin:
            ctx.log("No cross-origin sharing policy is advertised.")
            return []

        if allow_origin == "*" and allow_credentials:
            ctx.log("CORS policy allows any origin together with credentials.", "ALERT")
            return [build_finding(
                "cors-credentials-wildcard", target,
                evidence=(
                    "The server returned 'Access-Control-Allow-Origin: *' together with "
                    "'Access-Control-Allow-Credentials: true'."
                ),
            )]

        if allow_origin == "sitescope-cors-probe.example" or allow_origin == "https://sitescope-cors-probe.example":
            # The server echoed back whatever origin was supplied.
            severity_id = "cors-credentials-wildcard" if allow_credentials else "cors-wildcard"
            ctx.log("Server reflects any origin back in its CORS policy.", "ALERT")
            return [build_finding(
                severity_id, target,
                evidence=(
                    f"The server echoed the supplied Origin header back as "
                    f"'Access-Control-Allow-Origin: {allow_origin}'"
                    + (" with credentials enabled." if allow_credentials
                       else ", meaning any website is permitted.")
                ),
            )]

        if allow_origin == "*":
            ctx.log("CORS policy allows any origin (without credentials).", "WARN")
            return [build_finding(
                "cors-wildcard", target,
                evidence="The server returned 'Access-Control-Allow-Origin: *'.",
            )]

        ctx.log(f"CORS policy restricted to: {allow_origin}")
        return []


class HttpMethodsCheck(BaseCheck):
    """Ask the server which request types it accepts."""

    check_id = "http-methods"
    name = "HTTP methods"
    phase = "Server Configuration"
    quick_scan = False

    DANGEROUS = {"TRACE", "TRACK", "PUT", "DELETE", "CONNECT", "PATCH"}

    def run(self, ctx: ScanContext) -> list[Finding]:
        target = ctx.pages[0].final_url if ctx.pages else ctx.target_url
        page = ctx.fetch(target, method="OPTIONS", allow_redirects=False)

        allowed_header = page.header("Allow") or page.header("Access-Control-Allow-Methods")
        if not allowed_header:
            ctx.log("Server did not advertise its accepted request methods.")
            return []

        allowed = {m.strip().upper() for m in allowed_header.split(",") if m.strip()}
        risky = sorted(allowed & self.DANGEROUS)

        if not risky:
            ctx.log(f"Accepted request methods look appropriate: {', '.join(sorted(allowed))}")
            return []

        ctx.log(f"Server advertises risky request methods: {', '.join(risky)}", "ALERT")
        return [build_finding(
            "http-dangerous-methods", target,
            evidence=(
                f"An OPTIONS request returned 'Allow: {allowed_header}'. The following are "
                f"not needed by a normal website and should be disabled: {', '.join(risky)}."
            ),
            confidence="Medium",
        )]


class CachePolicyCheck(BaseCheck):
    """Check that pages showing personal information are not cacheable."""

    check_id = "cache-policy"
    name = "Cache policy on private pages"
    phase = "Server Configuration"
    quick_scan = False

    def run(self, ctx: ScanContext) -> list[Finding]:
        for page in ctx.html_pages():
            # Match on the path only - a hostname like admin.example.com would
            # otherwise make every page on the site look private.
            path = urlparse(page.final_url).path
            looks_private = (
                SENSITIVE_PATH_RE.search(path)
                or SENSITIVE_PAGE_CONTENT_RE.search(page.body)
            )
            if not looks_private:
                continue

            cache_control = page.header("Cache-Control").lower()
            if "no-store" in cache_control:
                continue

            ctx.log(f"Private-looking page is cacheable: {page.final_url}", "WARN")
            return [build_finding(
                "cache-sensitive-page", page.final_url,
                confidence="Medium",
                evidence=(
                    f"{page.final_url} appears to show account or login content but returned "
                    f"'Cache-Control: {page.header('Cache-Control') or '(not set)'}'. Add "
                    f"no-store so shared computers do not retain a copy."
                ),
            )]
        return []


class SecurityContactCheck(BaseCheck):
    """Look for a published security.txt contact file."""

    check_id = "security-txt"
    name = "Security contact"
    phase = "Server Configuration"
    quick_scan = False

    def run(self, ctx: ScanContext) -> list[Finding]:
        for path in ("/.well-known/security.txt", "/security.txt"):
            page = ctx.fetch(f"{ctx.origin}{path}")
            if page.ok and page.status_code == 200 and "contact:" in page.body.lower():
                ctx.log("Security contact file found.")
                return []

        ctx.log("No security.txt contact file published.")
        return [build_finding(
            "missing-security-txt", f"{ctx.origin}/.well-known/security.txt",
            evidence="No security.txt file was found at either standard location.",
        )]


class RobotsCheck(BaseCheck):
    """Report sensitive paths advertised in robots.txt."""

    check_id = "robots"
    name = "robots.txt review"
    phase = "Server Configuration"
    quick_scan = False

    def run(self, ctx: ScanContext) -> list[Finding]:
        if not ctx.robots_disallow:
            return []

        interesting = [p for p in ctx.robots_disallow if SENSITIVE_PATH_RE.search(p)]
        if not interesting:
            return []

        ctx.log(f"robots.txt names {len(interesting)} sensitive path(s).")
        return [build_finding(
            "robots-sensitive-paths", f"{ctx.origin}/robots.txt",
            evidence=(
                "robots.txt asks search engines to avoid these paths, which also tells a "
                "curious visitor exactly where to look:\n"
                + "\n".join(f"  - {p}" for p in interesting[:10])
            ),
        )]
