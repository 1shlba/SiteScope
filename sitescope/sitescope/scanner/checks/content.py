"""Page content inspection: mixed content, forms, and information left in HTML."""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from ...models import Finding
from ..base import BaseCheck, ScanContext, dedupe
from ..knowledge import build_finding

INSECURE_RESOURCE_RE = re.compile(
    r"""<(?:script|img|iframe|link|source|audio|video|embed|object)\b[^>]*?"""
    r"""\b(?:src|href|data)\s*=\s*["'](http://[^"']+)["']""",
    re.IGNORECASE,
)

FORM_RE = re.compile(r"<form\b(.*?)</form>", re.IGNORECASE | re.DOTALL)
FORM_ATTRS_RE = re.compile(r"<form\b([^>]*)>", re.IGNORECASE)
ACTION_RE = re.compile(r"""\baction\s*=\s*["']([^"']*)["']""", re.IGNORECASE)
METHOD_RE = re.compile(r"""\bmethod\s*=\s*["']([^"']*)["']""", re.IGNORECASE)
PASSWORD_INPUT_RE = re.compile(r"""<input\b[^>]*\btype\s*=\s*["']password["']""", re.IGNORECASE)
HIDDEN_TOKEN_RE = re.compile(
    r"""<input\b[^>]*\btype\s*=\s*["']hidden["'][^>]*\bname\s*=\s*["']"""
    r"""([^"']*(?:csrf|token|nonce|authenticity|_wpnonce)[^"']*)["']""",
    re.IGNORECASE,
)

COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

# Words in an HTML comment that suggest it should not have been published.
RISKY_COMMENT_RE = re.compile(
    r"\b(password|passwd|pwd|api[_ -]?key|secret|token|todo|fixme|hack|"
    r"temporary|remove before|debug|staging|internal|do not (?:commit|deploy)|"
    r"credential|username\s*[:=])\b",
    re.IGNORECASE,
)

ERROR_SIGNATURE_RE = re.compile(
    r"(Fatal error:|Warning: mysql|Uncaught exception|Traceback \(most recent call last\)|"
    r"java\.lang\.[A-Za-z]+Exception|System\.Web\.|ORA-\d{5}|SQLSTATE\[|"
    r"You have an error in your SQL syntax|Microsoft OLE DB Provider|"
    r"Whoops, looks like something went wrong|DEBUG = True)",
    re.IGNORECASE,
)


class MixedContentCheck(BaseCheck):
    """Find resources loaded over HTTP on a page served over HTTPS."""

    check_id = "mixed-content"
    name = "Mixed content"
    phase = "Content & Form Inspection"

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []

        for page in ctx.html_pages():
            if not page.is_https:
                continue

            insecure = []
            for match in INSECURE_RESOURCE_RE.finditer(page.body):
                url = match.group(1)
                # Ignore XML namespace and schema declarations, which are
                # identifiers rather than resources the browser fetches.
                if "://www.w3.org/" in url or "://schema.org" in url:
                    continue
                insecure.append(url)

            if not insecure:
                continue

            unique = list(dict.fromkeys(insecure))[:8]
            ctx.log(f"Mixed content on {page.final_url}: {len(insecure)} insecure resource(s).", "WARN")
            findings.append(build_finding(
                "mixed-content", page.final_url,
                evidence=(
                    f"This secure page loads {len(insecure)} resource(s) over an insecure "
                    f"connection:\n" + "\n".join(f"  - {u}" for u in unique)
                ),
            ))

        if not findings:
            ctx.log("No mixed (insecure) content found on secure pages.")
        return dedupe(findings)


class FormSecurityCheck(BaseCheck):
    """Assess how each form on the site transmits and protects its data."""

    check_id = "forms"
    name = "Form security"
    phase = "Content & Form Inspection"

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        form_count = 0

        for page in ctx.html_pages():
            for attrs_match in FORM_ATTRS_RE.finditer(page.body):
                form_count += 1
                attrs = attrs_match.group(1)
                # Take the form body from this tag to the closing tag.
                body_start = attrs_match.end()
                body_end = page.body.lower().find("</form>", body_start)
                form_body = page.body[body_start: body_end if body_end != -1 else body_start + 4000]

                action = (ACTION_RE.search(attrs).group(1).strip()
                          if ACTION_RE.search(attrs) else "")
                method = (METHOD_RE.search(attrs).group(1).strip().upper()
                          if METHOD_RE.search(attrs) else "GET")
                target = urljoin(page.final_url, action) if action else page.final_url
                has_password = bool(PASSWORD_INPUT_RE.search(form_body))

                if urlparse(target).scheme == "http":
                    findings.append(build_finding(
                        "form-insecure-action", page.final_url,
                        evidence=(
                            f"A form on {page.final_url} submits to {target}, which is not "
                            f"an encrypted address."
                        ),
                    ))

                if has_password and not page.is_https:
                    findings.append(build_finding(
                        "password-over-http", page.final_url,
                        evidence=f"A password field appears on {page.final_url}, served over plain HTTP.",
                    ))

                if (method == "POST" and page.is_https
                        and not HIDDEN_TOKEN_RE.search(form_body)
                        and not self._is_search_form(form_body)):
                    findings.append(build_finding(
                        "form-no-csrf-token", page.final_url,
                        confidence="Medium",
                        evidence=(
                            f"A form on {page.final_url} submits data with POST but contains no "
                            f"hidden anti-forgery token field. Some frameworks send this "
                            f"protection in a header instead, so confirm with your developer "
                            f"before treating this as confirmed."
                        ),
                    ))

        ctx.log(f"Inspected {form_count} form(s) across the crawled pages.")
        return dedupe(findings)

    def _is_search_form(self, form_body: str) -> bool:
        """Search forms do not change data, so a forgery token is not required."""
        return bool(re.search(r"""type\s*=\s*["']search["']|name\s*=\s*["'](q|s|search|query)["']""",
                              form_body, re.IGNORECASE))


class InformationLeakCheck(BaseCheck):
    """Find sensitive material left in page source: comments, emails, errors."""

    check_id = "information-leak"
    name = "Information disclosure in page content"
    phase = "Information Disclosure"

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        risky_comments: list[str] = []
        emails: set[str] = set()

        for page in ctx.html_pages():
            for comment in COMMENT_RE.findall(page.body):
                text = " ".join(comment.split())
                if not text or text.startswith("[if ") or len(text) > 400:
                    continue  # conditional comments and minified blocks
                if RISKY_COMMENT_RE.search(text):
                    risky_comments.append(f"{page.final_url}: <!-- {text[:150]} -->")

            for email in EMAIL_RE.findall(page.body):
                if not email.lower().endswith((".png", ".jpg", ".gif", ".webp")):
                    emails.add(email)

            error_match = ERROR_SIGNATURE_RE.search(page.body)
            if error_match:
                ctx.log(f"Technical error output visible on {page.final_url}", "ALERT")
                findings.append(build_finding(
                    "info-error-disclosure", page.final_url,
                    evidence=(
                        f"The page at {page.final_url} contains technical error output "
                        f"beginning '{error_match.group(0)[:80]}'. Visitors can see internal "
                        f"details of how the site works."
                    ),
                ))

        if risky_comments:
            ctx.log(f"{len(risky_comments)} developer comment(s) contain sensitive keywords.", "WARN")
            findings.append(build_finding(
                "info-html-comments", ctx.pages[0].final_url if ctx.pages else ctx.target_url,
                evidence="Comments containing potentially sensitive keywords:\n" +
                         "\n".join(f"  - {c}" for c in risky_comments[:6]),
            ))

        if emails:
            findings.append(build_finding(
                "info-email-disclosure", ctx.pages[0].final_url if ctx.pages else ctx.target_url,
                evidence=(
                    f"{len(emails)} email address(es) found in page source: "
                    + ", ".join(sorted(emails)[:6])
                    + (" ..." if len(emails) > 6 else "")
                ),
            ))

        return dedupe(findings)
