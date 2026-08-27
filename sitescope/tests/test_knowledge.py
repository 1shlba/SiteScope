"""Quality gate on the vulnerability knowledge base.

The whole product promise is that a non-technical owner can read a finding and
know what to do. These tests enforce that every entry actually delivers that,
so a new check cannot be added with a placeholder explanation.
"""

from __future__ import annotations

import re

import pytest

from sitescope.models import SEVERITY_ORDER, severity_from_cvss
from sitescope.scanner.knowledge import KNOWLEDGE, build_finding

REQUIRED_FIELDS = [
    "title", "cvss", "owasp", "what_it_means", "why_it_matters",
    "how_to_fix", "difficulty", "needs_professional", "reference",
]

# Words that mean nothing to the audience this tool is written for.
JARGON = [
    "xss", "csrf token validation", "sanitise input", "payload", "exploit chain",
    "attack vector", "threat actor", "misconfigured header value",
]

ALL_IDS = sorted(KNOWLEDGE)


@pytest.mark.parametrize("check_id", ALL_IDS)
def test_entry_has_every_required_field(check_id):
    entry = KNOWLEDGE[check_id]
    for field in REQUIRED_FIELDS:
        assert field in entry, f"{check_id} is missing '{field}'"
        assert entry[field] != "" and entry[field] is not None or field == "needs_professional"


@pytest.mark.parametrize("check_id", ALL_IDS)
def test_cvss_is_in_range(check_id):
    cvss = KNOWLEDGE[check_id]["cvss"]
    assert 0.0 <= cvss <= 10.0
    assert severity_from_cvss(cvss) in SEVERITY_ORDER


@pytest.mark.parametrize("check_id", ALL_IDS)
def test_remediation_is_actionable(check_id):
    """Every issue must come with concrete, ordered steps."""
    steps = KNOWLEDGE[check_id]["how_to_fix"]
    assert isinstance(steps, list) and len(steps) >= 2, f"{check_id} needs at least two steps"
    for step in steps:
        assert len(step) > 25, f"{check_id} has a step too short to be useful: {step!r}"
        assert step[0].isupper(), f"{check_id} step should read as a sentence: {step!r}"


@pytest.mark.parametrize("check_id", ALL_IDS)
def test_explanations_are_written_for_a_business_owner(check_id):
    entry = KNOWLEDGE[check_id]

    assert len(entry["what_it_means"]) > 60, f"{check_id}: explanation is too thin"
    assert len(entry["why_it_matters"]) > 80, f"{check_id}: business impact is too thin"

    combined = (entry["what_it_means"] + " " + entry["why_it_matters"]).lower()
    for term in JARGON:
        assert term not in combined, f"{check_id} uses jargon: {term!r}"


@pytest.mark.parametrize("check_id", ALL_IDS)
def test_difficulty_and_reference_are_valid(check_id):
    entry = KNOWLEDGE[check_id]
    assert entry["difficulty"] in ("Easy", "Moderate", "Advanced")
    assert isinstance(entry["needs_professional"], bool)
    assert entry["reference"].startswith("https://")


@pytest.mark.parametrize("check_id", ALL_IDS)
def test_owasp_category_is_well_formed(check_id):
    owasp = KNOWLEDGE[check_id]["owasp"]
    assert re.match(r"^A\d{2}:\d{4} .+", owasp), f"{check_id} has a malformed OWASP category"


@pytest.mark.parametrize("check_id", ALL_IDS)
def test_build_finding_produces_a_complete_finding(check_id):
    finding = build_finding(check_id, "https://example.com/", evidence="test evidence")

    assert finding.check_id == check_id
    assert finding.severity == severity_from_cvss(finding.cvss)
    assert finding.url == "https://example.com/"
    assert finding.evidence == "test evidence"
    assert finding.how_to_fix


def test_high_severity_issues_are_explained_at_least_as_carefully():
    """Critical findings must not have thinner guidance than trivial ones."""
    for check_id, entry in KNOWLEDGE.items():
        if entry["cvss"] >= 9.0:
            assert len(entry["how_to_fix"]) >= 3, (
                f"{check_id} is critical but offers fewer than three remediation steps"
            )


def test_advanced_fixes_flag_professional_help():
    for check_id, entry in KNOWLEDGE.items():
        if entry["difficulty"] == "Advanced":
            assert entry["needs_professional"], (
                f"{check_id} is Advanced but does not recommend professional help"
            )


def test_unknown_check_id_is_rejected():
    with pytest.raises(KeyError):
        build_finding("no-such-check", "https://example.com/")
