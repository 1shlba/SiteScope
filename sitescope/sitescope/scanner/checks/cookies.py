"""Cookie attribute review (Secure, HttpOnly, SameSite)."""

from __future__ import annotations

import re

from ...models import Finding
from ..base import BaseCheck, ScanContext
from ..knowledge import build_finding

# Cookies whose names suggest they carry a session or authentication token.
SESSION_NAME_RE = re.compile(
    r"(sess|sid|auth|token|login|user|remember|jwt|csrf|xsrf|wordpress_logged_in)",
    re.IGNORECASE,
)

# Cookies set by analytics scripts, which are not session tokens and would
# otherwise dominate the findings list with low-value noise.
ANALYTICS_NAME_RE = re.compile(r"^(_ga|_gid|_gat|_fbp|_fbc|__utm|_hj|_clck|_clsk)", re.IGNORECASE)


class CookieSecurityCheck(BaseCheck):
    """Inspect the attributes on every cookie the site sets."""

    check_id = "cookies"
    name = "Cookie security"
    phase = "Cookie & Session Review"

    def run(self, ctx: ScanContext) -> list[Finding]:
        raw_cookies = self._collect_set_cookie_headers(ctx)
        if not raw_cookies:
            ctx.log("No cookies are set by this site.")
            return []

        ctx.log(f"Reviewing {len(raw_cookies)} cookie(s) for security attributes.")

        findings: list[Finding] = []
        missing_secure: list[str] = []
        missing_httponly: list[str] = []
        missing_samesite: list[str] = []
        page_url = ctx.pages[0].final_url if ctx.pages else ctx.target_url
        site_is_https = ctx.pages[0].is_https if ctx.pages else ctx.parsed.scheme == "https"

        for header_value, _source_url in raw_cookies:
            name = header_value.split("=", 1)[0].strip()
            if not name or ANALYTICS_NAME_RE.match(name):
                continue

            lowered = header_value.lower()
            is_session_cookie = bool(SESSION_NAME_RE.search(name))

            if site_is_https and "secure" not in lowered:
                missing_secure.append(name)
            # HttpOnly only matters for cookies the site's own scripts should not read.
            if is_session_cookie and "httponly" not in lowered:
                missing_httponly.append(name)
            if "samesite" not in lowered:
                missing_samesite.append(name)

        if missing_secure:
            ctx.log(f"Cookies without the Secure flag: {', '.join(missing_secure[:5])}", "ALERT")
            findings.append(build_finding(
                "cookie-missing-secure", page_url,
                evidence=_evidence("without the Secure attribute", missing_secure),
            ))

        if missing_httponly:
            ctx.log(f"Session cookies readable by scripts: {', '.join(missing_httponly[:5])}", "ALERT")
            findings.append(build_finding(
                "cookie-missing-httponly", page_url,
                evidence=_evidence("without the HttpOnly attribute", missing_httponly),
            ))

        if missing_samesite:
            findings.append(build_finding(
                "cookie-missing-samesite", page_url,
                evidence=_evidence("without a SameSite attribute", missing_samesite),
            ))

        if not findings:
            ctx.log("All cookies carry appropriate security attributes.")
        return findings

    def _collect_set_cookie_headers(self, ctx: ScanContext) -> list[tuple[str, str]]:
        """Gather Set-Cookie values across crawled pages, de-duplicated by name."""
        collected: dict[str, tuple[str, str]] = {}
        for page in ctx.pages:
            for key, value in page.headers.items():
                if key.lower() != "set-cookie":
                    continue
                # requests joins repeated Set-Cookie headers with ', ' - split
                # on the boundary between one cookie ending and a new name=value
                # pair beginning, without breaking on dates inside Expires.
                for part in re.split(r",\s*(?=[A-Za-z0-9!#$%&'*+.^_`|~-]+=)", value):
                    name = part.split("=", 1)[0].strip()
                    if name and name not in collected:
                        collected[name] = (part.strip(), page.final_url)
        return list(collected.values())


def _evidence(description: str, names: list[str]) -> str:
    shown = ", ".join(names[:8])
    more = f" and {len(names) - 8} more" if len(names) > 8 else ""
    return f"Cookie(s) set {description}: {shown}{more}."
