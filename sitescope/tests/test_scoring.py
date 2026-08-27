"""Tests for the security score and its grade bands."""

from __future__ import annotations

import pytest

from sitescope.models import Finding, severity_from_cvss
from sitescope.scanner.scoring import MAX_SCORE, calculate_score, grade_for


def make_finding(cvss: float, check_id: str = "test", resolved: bool = False) -> Finding:
    return Finding(
        check_id=check_id,
        title=f"Test finding {check_id}",
        severity=severity_from_cvss(cvss),
        cvss=cvss,
        owasp="A05:2021 Security Misconfiguration",
        url="https://example.com/",
        resolved=resolved,
    )


def test_perfect_score_when_nothing_found():
    score, grade = calculate_score([])
    assert score == MAX_SCORE
    assert grade == "A+"


def test_informational_findings_do_not_reduce_the_score():
    score, _ = calculate_score([make_finding(0.0), make_finding(0.0, "other")])
    assert score == MAX_SCORE


def test_resolved_findings_do_not_reduce_the_score():
    score, _ = calculate_score([make_finding(9.8, resolved=True)])
    assert score == MAX_SCORE


def test_critical_finding_costs_more_than_a_low_one():
    critical, _ = calculate_score([make_finding(9.8)])
    low, _ = calculate_score([make_finding(2.0)])
    assert critical < low < MAX_SCORE


def test_repeated_findings_have_diminishing_impact():
    """The second issue of a severity must cost less than the first.

    Without this, a site with many low-severity items would score worse than
    one with a single critical issue, which would mislead the user badly.
    """
    one, _ = calculate_score([make_finding(5.0, "a")])
    two, _ = calculate_score([make_finding(5.0, "a"), make_finding(5.0, "b")])
    three, _ = calculate_score([make_finding(5.0, "a"), make_finding(5.0, "b"),
                                make_finding(5.0, "c")])

    first_cost = MAX_SCORE - one
    second_cost = one - two
    third_cost = two - three

    assert first_cost > second_cost > third_cost > 0


def test_score_never_goes_negative():
    findings = [make_finding(9.9, f"critical-{index}") for index in range(40)]
    score, grade = calculate_score(findings)
    assert score == 0
    assert grade == "F"


def test_one_critical_never_scores_above_a_b():
    """A site with a critical issue must not be presented as healthy."""
    score, grade = calculate_score([make_finding(9.8)])
    assert grade not in ("A+", "A", "B+")


@pytest.mark.parametrize("score,expected", [
    (950, "A+"), (900, "A+"), (899, "A"), (850, "A"),
    (849, "B+"), (700, "B"), (620, "C+"), (540, "C"),
    (450, "D"), (449, "F"), (0, "F"),
])
def test_grade_bands(score, expected):
    assert grade_for(score) == expected


@pytest.mark.parametrize("cvss,expected", [
    (10.0, "critical"), (9.0, "critical"),
    (8.9, "high"), (7.0, "high"),
    (6.9, "medium"), (4.0, "medium"),
    (3.9, "low"), (0.1, "low"),
    (0.0, "info"),
])
def test_cvss_maps_to_the_right_band(cvss, expected):
    assert severity_from_cvss(cvss) == expected
