"""HTTP security header analysis."""

from __future__ import annotations

import re

from ...models import Finding
from ..base import BaseCheck, ScanContext
from ..knowledge import build_finding


class SecurityHeadersCheck(BaseCheck):
    """Check the response headers that instruct browsers how to protect visitors.

    Only HTML pages are assessed - these headers are meaningless on an image or
    a stylesheet, and including them would produce noisy duplicate findings.
    """

    check_id = "security-headers"
    name = "Security headers"
    phase = "Security Header Analysis"

    def run(self, ctx: ScanContext) -> list[Finding]:
        pages = ctx.html_pages() or ctx.pages
        if not pages:
            return []

        findings: list[Finding] = []
        home = pages[0]

        # HSTS only makes sense on a site already served over HTTPS.
        if home.is_https and not home.has_header("Strict-Transport-Security"):
            ctx.log("Strict-Transport-Security header is missing.", "ALERT")
            findings.append(build_finding(
                "header-missing-hsts", home.final_url,
                evidence="No Strict-Transport-Security header was returned by the site.",
            ))
        elif home.is_https:
            findings.extend(self._check_hsts_value(ctx, home))

        findings.extend(self._check_csp(ctx, home))

        if not home.has_header("X-Frame-Options") and not self._csp_blocks_framing(home):
            ctx.log("X-Frame-Options header is missing - page can be framed.", "ALERT")
            findings.append(build_finding(
                "header-missing-xfo", home.final_url,
                evidence=(
                    "Neither an X-Frame-Options header nor a Content-Security-Policy "
                    "'frame-ancestors' directive was returned, so any site can embed these pages."
                ),
            ))

        if not home.has_header("X-Content-Type-Options"):
            findings.append(build_finding(
                "header-missing-xcto", home.final_url,
                evidence="No X-Content-Type-Options header was returned by the site.",
            ))

        if not home.has_header("Referrer-Policy"):
            findings.append(build_finding(
                "header-missing-referrer", home.final_url,
                evidence="No Referrer-Policy header was returned by the site.",
            ))

        if not home.has_header("Permissions-Policy") and not home.has_header("Feature-Policy"):
            findings.append(build_finding(
                "header-missing-permissions", home.final_url,
                evidence="No Permissions-Policy header was returned by the site.",
            ))

        present = [
            name for name in (
                "Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
                "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy",
            ) if home.has_header(name)
        ]
        ctx.log(f"Security headers present: {len(present)} of 6 recommended.")
        return findings

    # ------------------------------------------------------------------

    def _check_hsts_value(self, ctx: ScanContext, page) -> list[Finding]:
        value = page.header("Strict-Transport-Security")
        match = re.search(r"max-age\s*=\s*(\d+)", value, re.IGNORECASE)
        max_age = int(match.group(1)) if match else 0

        # Under a day provides effectively no protection for returning visitors.
        if max_age < 86400:
            return [build_finding(
                "header-missing-hsts", page.final_url,
                title="Secure-connection instruction expires too quickly to help",
                cvss=3.1,
                evidence=(
                    f"Strict-Transport-Security is set to '{value}'. A max-age of {max_age} "
                    f"seconds is too short; the recommended value is 31536000 (one year)."
                ),
            )]
        return []

    def _check_csp(self, ctx: ScanContext, page) -> list[Finding]:
        policy = page.header("Content-Security-Policy")
        if not policy:
            if page.has_header("Content-Security-Policy-Report-Only"):
                ctx.log("Content-Security-Policy is in report-only mode - not enforced.", "WARN")
                return [build_finding(
                    "header-missing-csp", page.final_url,
                    title="Content security policy is set up but not switched on",
                    cvss=4.0,
                    evidence=(
                        "A Content-Security-Policy-Report-Only header is present, which logs "
                        "violations but does not block anything. Once you are satisfied with "
                        "the reports, switch it to the enforcing Content-Security-Policy header."
                    ),
                )]
            ctx.log("Content-Security-Policy header is missing.", "ALERT")
            return [build_finding(
                "header-missing-csp", page.final_url,
                evidence="No Content-Security-Policy header was returned by the site.",
            )]

        weaknesses = []
        lowered = policy.lower()
        if "unsafe-inline" in lowered:
            weaknesses.append("'unsafe-inline' allows inline scripts to run")
        if "unsafe-eval" in lowered:
            weaknesses.append("'unsafe-eval' allows dynamically generated code to run")
        if re.search(r"(default-src|script-src)\s[^;]*\*", lowered):
            weaknesses.append("a wildcard (*) source allows scripts from any website")

        if weaknesses:
            ctx.log("Content-Security-Policy present but weakened.", "WARN")
            return [build_finding(
                "header-csp-weak", page.final_url,
                evidence="Policy: " + policy[:300] + "\n\nWeaknesses: " + "; ".join(weaknesses) + ".",
            )]

        ctx.log("Content-Security-Policy present and reasonably strict.")
        return []

    def _csp_blocks_framing(self, page) -> bool:
        return "frame-ancestors" in page.header("Content-Security-Policy").lower()
