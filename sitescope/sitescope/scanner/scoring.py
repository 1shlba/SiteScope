"""Security score calculation.

The score is a single number a non-technical owner can watch over time. It is
deliberately simple and explainable: every unresolved finding subtracts a fixed
weight for its severity band, with diminishing weight applied to repeats of the
same severity so that one bad category cannot drive the score to zero on its own.

The scale runs to 950 to match the product design. Grades follow the bands the
UI displays next to the number.
"""

from __future__ import annotations

from ..models import Finding

MAX_SCORE = 950

# Points deducted for the first finding in each severity band.
BASE_DEDUCTION = {
    "critical": 220,
    "high": 110,
    "medium": 45,
    "low": 15,
    "info": 0,
}

# Each additional finding in the same band counts for progressively less,
# multiplied by this factor per repeat, with a floor so it never reaches zero.
DECAY = 0.6
MIN_FACTOR = 0.15

GRADE_BANDS = [
    (900, "A+"),
    (850, "A"),
    (780, "B+"),
    (700, "B"),
    (620, "C+"),
    (540, "C"),
    (450, "D"),
    (0, "F"),
]


def calculate_score(findings: list[Finding]) -> tuple[int, str]:
    """Return (score out of 950, letter grade) for a set of findings."""
    counts: dict[str, int] = {}
    for finding in findings:
        if finding.resolved or finding.severity == "info":
            continue
        counts[finding.severity] = counts.get(finding.severity, 0) + 1

    deduction = 0.0
    for severity, count in counts.items():
        base = BASE_DEDUCTION.get(severity, 0)
        factor = 1.0
        for _ in range(count):
            deduction += base * factor
            factor = max(MIN_FACTOR, factor * DECAY)

    score = max(0, min(MAX_SCORE, round(MAX_SCORE - deduction)))
    return score, grade_for(score)


def grade_for(score: int) -> str:
    for threshold, grade in GRADE_BANDS:
        if score >= threshold:
            return grade
    return "F"


def score_summary(score: int, findings: list[Finding]) -> str:
    """One plain-language sentence describing the overall posture."""
    counts: dict[str, int] = {}
    for finding in findings:
        if not finding.resolved and finding.severity != "info":
            counts[finding.severity] = counts.get(finding.severity, 0) + 1

    critical = counts.get("critical", 0)
    high = counts.get("high", 0)

    if critical:
        return (
            f"Urgent attention needed. {critical} critical issue"
            f"{'s' if critical != 1 else ''} could expose your business or customer data "
            f"and should be dealt with today."
        )
    if high:
        return (
            f"Action needed soon. {high} high-severity issue"
            f"{'s were' if high != 1 else ' was'} found that a determined attacker could "
            f"use against your site."
        )
    if counts.get("medium"):
        return (
            "Reasonable posture with room to improve. The issues found are worth fixing "
            "but none of them expose your site directly."
        )
    if counts.get("low"):
        return (
            "Good posture. Only minor hardening opportunities were found, none of which "
            "put your business at immediate risk."
        )
    return (
        "Excellent. No security issues were detected in the areas SiteScope checks. "
        "Re-scan after any significant change to your website."
    )
