"""Polite, breadth-first crawler restricted to the target's own hostname.

The crawler exists to give the checks a representative sample of the site
rather than to mirror it. It obeys robots.txt by default, stays on one host,
skips binary assets, and stops at a page budget the user controls in Settings.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse
from urllib.robotparser import RobotFileParser

from .base import Page, ScanContext, same_host, strip_fragment

# File types that cannot contain the things our checks look for.
SKIP_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp", ".ico", ".bmp", ".avif",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".pdf", ".zip", ".gz", ".tar", ".rar", ".7z", ".doc", ".docx", ".xls",
    ".xlsx", ".ppt", ".pptx", ".mp4", ".mp3", ".avi", ".mov", ".wav", ".webm",
}

# Paths that log a session out or trigger an action rather than showing a page.
SKIP_PATTERNS = re.compile(
    r"(logout|signout|sign-out|log-out|delete|remove|unsubscribe|cart/add|"
    r"add-to-cart|\?add-to-cart|wp-login\.php\?action=logout)",
    re.IGNORECASE,
)

HREF_RE = re.compile(r"""<a\b[^>]*?\bhref\s*=\s*["']([^"'#]+)["']""", re.IGNORECASE)


def load_robots(ctx: ScanContext) -> RobotFileParser | None:
    """Fetch and parse robots.txt. Returns None when unavailable."""
    page = ctx.fetch(f"{ctx.origin}/robots.txt")
    if not page.ok or "html" in page.content_type.lower():
        return None

    parser = RobotFileParser()
    parser.parse(page.body.splitlines())

    for line in page.body.splitlines():
        if line.lower().startswith("disallow:"):
            path = line.split(":", 1)[1].strip()
            if path and path != "/":
                ctx.robots_disallow.append(path)

    ctx.notes["robots_body"] = page.body[:4000]
    return parser


def crawl(ctx: ScanContext, max_pages: int) -> list[Page]:
    """Breadth-first crawl from the target URL, returning fetched HTML pages."""
    robots = None
    if ctx.settings.get("respect_robots", True):
        robots = load_robots(ctx)
        if robots is not None:
            ctx.log("robots.txt found and will be respected during the crawl.")

    user_agent = ctx.session.headers.get("User-Agent", "*")
    queue: list[str] = [ctx.target_url]
    visited: set[str] = set()

    while queue and len(ctx.pages) < max_pages:
        url = strip_fragment(queue.pop(0))
        if url in visited:
            continue
        visited.add(url)

        if robots is not None and not robots.can_fetch(user_agent, url):
            ctx.log(f"Skipped (robots.txt disallow): {_short(url)}", "WARN")
            continue

        page = ctx.fetch(url, record=True)

        if page.error:
            ctx.log(f"Could not fetch {_short(url)} - {page.error}", "WARN")
            continue
        if not page.ok:
            ctx.log(f"{_short(url)} returned HTTP {page.status_code}", "WARN")
            continue

        ctx.log(f"Crawled {_short(page.final_url)} ({page.status_code}, {page.elapsed_ms}ms)")

        if page.elapsed_ms > 5000:
            ctx.log(f"Slow response from {_short(page.final_url)}: {page.elapsed_ms}ms", "WARN")

        if page.is_html and len(ctx.pages) < max_pages:
            for link in extract_links(page):
                if link not in visited and link not in queue:
                    queue.append(link)

    return ctx.pages


def extract_links(page: Page) -> list[str]:
    """Same-host, crawlable links found in a page's HTML."""
    links: list[str] = []
    for href in HREF_RE.findall(page.body):
        href = href.strip()
        if not href or href.lower().startswith(("mailto:", "tel:", "javascript:", "data:")):
            continue

        absolute = strip_fragment(urljoin(page.final_url, href))
        if not same_host(absolute, page.final_url):
            continue
        if SKIP_PATTERNS.search(absolute):
            continue

        path = urlparse(absolute).path.lower()
        if any(path.endswith(ext) for ext in SKIP_EXTENSIONS):
            continue

        links.append(absolute)

    # Preserve order while removing duplicates.
    return list(dict.fromkeys(links))


def _short(url: str, limit: int = 60) -> str:
    """Trim a URL for the on-screen log feed."""
    return url if len(url) <= limit else url[: limit - 3] + "..."
