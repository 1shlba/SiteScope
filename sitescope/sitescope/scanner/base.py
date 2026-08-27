"""Scanner foundations: page snapshots, the shared scan context and the check
interface that every individual security check implements.

Design note
-----------
All checks receive a `ScanContext` and return a list of `Finding`. Nothing in a
check knows about the database or the web layer, which keeps them independently
testable and makes it possible to add a different engine (for example an OWASP
ZAP adapter) behind the same interface later.

Every request the scanner makes is passive: it fetches pages the way a browser
or search engine would and inspects what comes back. No payloads are injected,
nothing is modified on the target, and requests are rate limited.
"""

from __future__ import annotations

import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional
from urllib.parse import urlparse, urlunparse

import requests
import urllib3
from requests.adapters import HTTPAdapter

from ..models import Finding

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# --------------------------------------------------------------------------
# URL helpers
# --------------------------------------------------------------------------

# A scheme is only a scheme when '//' follows it, so that 'example.com:8080'
# is read as a host and port rather than a scheme named 'example.com'.
SCHEME_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.\-]*):")

# Standard DNS name rules: labels of 1-63 characters, 253 characters overall.
HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.?$"
)

INVALID_ADDRESS = "That does not look like a valid website address."


def _is_valid_host(host: str) -> bool:
    """True for a syntactically valid DNS name or IP address literal."""
    import ipaddress
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(HOSTNAME_RE.match(host))


def normalise_url(raw: str) -> str:
    """Turn user input into a fetchable absolute URL.

    Accepts 'example.com', 'example.com/path', 'example.com:8080',
    'http://example.com' and so on. Defaults to https:// because that is what
    a site should be using.

    Anything that is not an http(s) address is rejected outright, including
    scheme-like input such as 'javascript:' or 'file:' - the address goes
    straight into an HTTP client, so it is validated before it gets there
    rather than after.
    """
    value = (raw or "").strip()
    if not value:
        raise ValueError("Please enter a website address.")

    scheme_match = SCHEME_RE.match(value)
    if scheme_match and value[scheme_match.end():].startswith("//"):
        if scheme_match.group(1).lower() not in ("http", "https"):
            raise ValueError("Only http:// and https:// addresses can be scanned.")
    else:
        value = "https://" + value

    parsed = urlparse(value)

    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only http:// and https:// addresses can be scanned.")
    if not parsed.netloc:
        raise ValueError(INVALID_ADDRESS)

    host = parsed.hostname
    if not host or not _is_valid_host(host):
        raise ValueError(INVALID_ADDRESS)

    try:
        port = parsed.port          # raises ValueError on a non-numeric port
    except ValueError:
        raise ValueError(INVALID_ADDRESS) from None
    if port is not None and not 0 < port < 65536:
        raise ValueError(INVALID_ADDRESS)

    path = parsed.path or "/"
    return urlunparse((parsed.scheme, parsed.netloc, path, "", parsed.query, ""))


def _bare_host(url: str) -> str:
    """Hostname in lower case with a single leading 'www.' removed.

    Uses removeprefix rather than lstrip: lstrip strips *characters*, so
    lstrip("www.") would turn 'ww.example.com' into 'example.com' and make two
    genuinely different hosts compare equal - which would let the crawler walk
    off the target site.
    """
    return (urlparse(url).hostname or "").lower().removeprefix("www.")


def same_host(url_a: str, url_b: str) -> bool:
    """True when two URLs share a hostname, ignoring a leading 'www.'."""
    return _bare_host(url_a) == _bare_host(url_b)


def strip_fragment(url: str) -> str:
    parsed = urlparse(url)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", parsed.query, ""))


# --------------------------------------------------------------------------
# Page snapshot
# --------------------------------------------------------------------------

@dataclass
class Page:
    """One fetched page and everything the checks need to inspect it."""

    url: str
    final_url: str
    status_code: int
    headers: dict[str, str]
    body: str
    content_type: str = ""
    elapsed_ms: int = 0
    redirect_chain: list[str] = field(default_factory=list)
    error: str = ""
    cookies: list[Any] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.error and 200 <= self.status_code < 400

    @property
    def is_html(self) -> bool:
        return "html" in self.content_type.lower()

    @property
    def is_https(self) -> bool:
        return urlparse(self.final_url).scheme == "https"

    def header(self, name: str, default: str = "") -> str:
        """Case-insensitive header lookup."""
        lowered = name.lower()
        for key, value in self.headers.items():
            if key.lower() == lowered:
                return value
        return default

    def has_header(self, name: str) -> bool:
        lowered = name.lower()
        return any(k.lower() == lowered for k in self.headers)


# --------------------------------------------------------------------------
# Rate limiting
# --------------------------------------------------------------------------

class RateLimiter:
    """Simple thread-safe minimum-interval limiter.

    Keeps the scanner polite so it never resembles a denial of service against
    the target, which matters both ethically and for staying inside the terms
    of service of most hosting providers.
    """

    def __init__(self, requests_per_second: float):
        self.min_interval = 1.0 / max(0.1, requests_per_second)
        self._last = 0.0
        self._lock = threading.Lock()

    def wait(self) -> None:
        with self._lock:
            now = time.monotonic()
            delay = self.min_interval - (now - self._last)
            if delay > 0:
                time.sleep(delay)
            self._last = time.monotonic()


# --------------------------------------------------------------------------
# Scan context
# --------------------------------------------------------------------------

class ScanContext:
    """Shared state passed to every check during a single scan."""

    MAX_BODY_BYTES = 2_000_000  # never read more than 2 MB from one response

    def __init__(
        self,
        target_url: str,
        settings: dict,
        scan_type: str = "full",
        log: Optional[Callable[[str, str], None]] = None,
        cancelled: Optional[threading.Event] = None,
        on_request: Optional[Callable[[int], None]] = None,
    ):
        self.target_url = target_url
        self.settings = settings
        self.scan_type = scan_type
        self.parsed = urlparse(target_url)
        self.host = self.parsed.hostname or ""
        self.port = self.parsed.port or (443 if self.parsed.scheme == "https" else 80)
        self.origin = f"{self.parsed.scheme}://{self.parsed.netloc}"

        self.pages: list[Page] = []
        self.requests_sent = 0
        self.tls_info: dict[str, Any] = {}
        self.robots_disallow: list[str] = []
        self.notes: dict[str, Any] = {}

        self._log = log or (lambda level, message: None)
        self._on_request = on_request or (lambda count: None)
        self.cancelled = cancelled or threading.Event()
        self.limiter = RateLimiter(settings.get("requests_per_second", 5.0))
        self.timeout = settings.get("request_timeout", 12)
        self._tls_verify = True

        self.session = requests.Session()
        adapter = HTTPAdapter(pool_connections=4, pool_maxsize=8, max_retries=0)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self.session.headers.update({
            "User-Agent": settings.get(
                "user_agent",
                "Mozilla/5.0 (compatible; SiteScope/1.0; authorised security assessment)",
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-AU,en;q=0.9",
        })

    # -- logging ---------------------------------------------------------

    def log(self, message: str, level: str = "INFO") -> None:
        self._log(level, message)

    # -- fetching --------------------------------------------------------

    def allow_insecure_tls(self) -> None:
        """Continue scanning a site whose certificate failed verification.

        The certificate problem is reported as a finding in its own right; we
        still want the rest of the assessment to run.
        """
        self._tls_verify = False

    def fetch(
        self,
        url: str,
        method: str = "GET",
        allow_redirects: Optional[bool] = None,
        extra_headers: Optional[dict[str, str]] = None,
        record: bool = False,
    ) -> Page:
        """Fetch one URL, respecting the rate limit and cancellation."""
        if self.cancelled.is_set():
            raise ScanCancelled()

        if allow_redirects is None:
            allow_redirects = self.settings.get("follow_redirects", True)

        self.limiter.wait()
        self.requests_sent += 1
        self._on_request(self.requests_sent)
        started = time.monotonic()

        try:
            response = self.session.request(
                method,
                url,
                timeout=self.timeout,
                allow_redirects=allow_redirects,
                verify=self._tls_verify,
                headers=extra_headers,
                stream=True,
            )
            raw = response.raw.read(self.MAX_BODY_BYTES, decode_content=True) or b""
            encoding = response.encoding or "utf-8"
            try:
                body = raw.decode(encoding, errors="replace")
            except (LookupError, TypeError):
                body = raw.decode("utf-8", errors="replace")

            page = Page(
                url=url,
                final_url=response.url,
                status_code=response.status_code,
                headers=dict(response.headers),
                body=body,
                content_type=response.headers.get("Content-Type", ""),
                elapsed_ms=int((time.monotonic() - started) * 1000),
                redirect_chain=[r.url for r in response.history],
                cookies=list(response.cookies),
            )
            response.close()
        except requests.exceptions.SSLError as exc:
            page = Page(url=url, final_url=url, status_code=0, headers={}, body="",
                        error=f"TLS error: {exc}")
        except requests.exceptions.Timeout:
            page = Page(url=url, final_url=url, status_code=0, headers={}, body="",
                        error="Request timed out")
        except requests.exceptions.RequestException as exc:
            page = Page(url=url, final_url=url, status_code=0, headers={}, body="",
                        error=str(exc))

        if record and page.ok:
            self.pages.append(page)
        return page

    # -- helpers ---------------------------------------------------------

    @property
    def home(self) -> Optional[Page]:
        """The first successfully fetched page, used for site-wide checks."""
        return self.pages[0] if self.pages else None

    def html_pages(self) -> list[Page]:
        return [p for p in self.pages if p.is_html]


class ScanCancelled(Exception):
    """Raised inside the scan thread when the user stops a running scan."""


# --------------------------------------------------------------------------
# Check interface
# --------------------------------------------------------------------------

class BaseCheck:
    """Interface implemented by every security check.

    Subclasses set `check_id`, `name` and `phase`, and implement `run`.
    A check must never raise: the engine catches exceptions, but returning an
    empty list on uncertainty is preferable to guessing.
    """

    check_id: str = "base"
    name: str = "Base check"
    phase: str = "Analysis"
    quick_scan: bool = True   # included in the fast "Quick Scan" preset

    def run(self, ctx: ScanContext) -> list[Finding]:  # pragma: no cover - interface
        raise NotImplementedError


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Collapse repeats of the same issue across many pages into one finding.

    A missing security header will otherwise be reported once per crawled page,
    which buries the report in noise. The first occurrence is kept and the
    number of affected pages is appended to its evidence.
    """
    seen: dict[str, Finding] = {}
    extra_counts: dict[str, int] = {}

    for finding in findings:
        key = f"{finding.check_id}|{finding.title}"
        if key in seen:
            extra_counts[key] = extra_counts.get(key, 0) + 1
        else:
            seen[key] = finding

    for key, count in extra_counts.items():
        finding = seen[key]
        finding.evidence = (
            f"{finding.evidence}\nAlso affects {count} other page"
            f"{'s' if count != 1 else ''} on this site."
        ).strip()

    return sorted(seen.values(), key=lambda f: (-f.cvss, f.title))
