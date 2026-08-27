"""Detection of technology and version information the site publishes."""

from __future__ import annotations

import re

from ...models import Finding
from ..base import BaseCheck, ScanContext
from ..knowledge import build_finding

# Server / framework banners that include a version number.
VERSIONED_BANNER_RE = re.compile(r"([A-Za-z][A-Za-z0-9_+.-]*)/(\d+[\d.]*)")

GENERATOR_RE = re.compile(
    r"""<meta\b[^>]*\bname\s*=\s*["']generator["'][^>]*\bcontent\s*=\s*["']([^"']+)["']""",
    re.IGNORECASE,
)

# Latest major versions known at build time. Used only to flag a site running
# a clearly older major release; the advice is always "check for updates"
# rather than "you are running exactly version X".
KNOWN_CURRENT_MAJOR = {
    "wordpress": 6,
    "joomla": 5,
    "drupal": 10,
}


class TechnologyDisclosureCheck(BaseCheck):
    """Report software banners, version numbers and outdated components."""

    check_id = "technology-disclosure"
    name = "Technology disclosure"
    phase = "Information Disclosure"

    def run(self, ctx: ScanContext) -> list[Finding]:
        if not ctx.pages:
            return []

        page = ctx.pages[0]
        findings: list[Finding] = []

        server = page.header("Server")
        if server and VERSIONED_BANNER_RE.search(server):
            ctx.log(f"Server banner discloses a version: {server}", "WARN")
            findings.append(build_finding(
                "info-server-version", page.final_url,
                evidence=f"The site returns the header 'Server: {server}', which names the exact software version in use.",
            ))
        elif server:
            ctx.log(f"Server banner present without a version: {server}")

        powered_by = page.header("X-Powered-By") or page.header("X-AspNet-Version")
        if powered_by:
            findings.append(build_finding(
                "info-powered-by", page.final_url,
                evidence=f"The site returns 'X-Powered-By: {powered_by}', naming the technology behind it.",
            ))

        findings.extend(self._check_generator(ctx, page))
        return findings

    def _check_generator(self, ctx: ScanContext, page) -> list[Finding]:
        match = GENERATOR_RE.search(page.body)
        if not match:
            return []

        generator = match.group(1).strip()
        ctx.log(f"Site reports its platform as: {generator}")

        version_match = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", generator)
        if not version_match:
            return []

        name = generator.split()[0].lower()
        major = int(version_match.group(1))
        current_major = KNOWN_CURRENT_MAJOR.get(name)

        if current_major and major < current_major:
            ctx.log(f"{generator} appears to be a major version behind.", "ALERT")
            return [build_finding(
                "info-outdated-component", page.final_url,
                evidence=(
                    f"The page declares '<meta name=\"generator\" content=\"{generator}\">'. "
                    f"Major version {major} is behind the {current_major}.x series, so this "
                    f"installation is likely missing security updates. Confirm the exact "
                    f"version in your site's administration area."
                ),
                confidence="Medium",
            )]

        # Version disclosed but not obviously outdated - still worth hiding.
        return [build_finding(
            "info-powered-by", page.final_url,
            title="Website platform and version are published in the page",
            cvss=2.6,
            evidence=(
                f"The page declares '<meta name=\"generator\" content=\"{generator}\">'. "
                f"This tells anyone which platform and version you run."
            ),
        )]
