"""Core data structures shared by the scanner, storage and reporting layers."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Optional

# --------------------------------------------------------------------------
# Severity, derived from the CVSS v3.1 qualitative rating scale.
# These bands are the ones shown in the UI and the PDF report.
# --------------------------------------------------------------------------

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

SEVERITY_BANDS = {
    "critical": (9.0, 10.0),
    "high": (7.0, 8.9),
    "medium": (4.0, 6.9),
    "low": (0.1, 3.9),
    "info": (0.0, 0.0),
}

SEVERITY_LABELS = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Information",
}

# Hex colours mirrored in the stylesheet so PDF and UI agree.
SEVERITY_COLOURS = {
    "critical": "#ef4444",
    "high": "#f97316",
    "medium": "#eab308",
    "low": "#3b82f6",
    "info": "#8b93a7",
}


def severity_from_cvss(score: float) -> str:
    """Map a CVSS base score onto its qualitative severity band."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


def utcnow() -> str:
    """ISO-8601 timestamp in UTC, used for every stored date."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass
class Finding:
    """A single security issue detected on the target site.

    Fields are split into machine-facing data (`check_id`, `cvss`, `owasp`) and
    the plain-language explanation shown to a non-technical business owner
    (`what_it_means`, `why_it_matters`, `how_to_fix`).
    """

    check_id: str
    title: str
    severity: str
    cvss: float
    owasp: str                       # e.g. "A05:2021 Security Misconfiguration"
    url: str                         # where the issue was observed
    evidence: str = ""               # what the scanner actually saw
    what_it_means: str = ""          # plain-language description
    why_it_matters: str = ""         # business impact
    how_to_fix: list[str] = field(default_factory=list)  # ordered remediation steps
    difficulty: str = "Moderate"     # Easy | Moderate | Advanced
    needs_professional: bool = False
    reference: str = ""              # authoritative URL for further reading
    confidence: str = "High"         # High | Medium | Low
    resolved: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        allowed = set(cls.__dataclass_fields__)
        return cls(**{k: v for k, v in data.items() if k in allowed})


@dataclass
class ScanResult:
    """Everything produced by one scan of one target."""

    target_url: str
    scan_type: str = "full"          # full | quick
    started_at: str = field(default_factory=utcnow)
    finished_at: Optional[str] = None
    status: str = "running"          # running | completed | failed | cancelled
    findings: list[Finding] = field(default_factory=list)
    pages_scanned: int = 0
    requests_sent: int = 0
    score: int = 0
    grade: str = "-"
    error: str = ""
    scan_id: Optional[int] = None

    @property
    def counts(self) -> dict[str, int]:
        """Number of unresolved findings per severity band."""
        result = dict.fromkeys(SEVERITY_ORDER, 0)
        for finding in self.findings:
            if not finding.resolved:
                result[finding.severity] = result.get(finding.severity, 0) + 1
        return result

    @property
    def duration_seconds(self) -> int:
        if not self.finished_at:
            return 0
        start = datetime.fromisoformat(self.started_at)
        end = datetime.fromisoformat(self.finished_at)
        return max(0, int((end - start).total_seconds()))

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["findings"] = [f.to_dict() for f in self.findings]
        data["counts"] = self.counts
        data["duration_seconds"] = self.duration_seconds
        return data
