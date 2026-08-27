"""PDF report generation.

The report is written for a small business owner, not a security analyst. It
opens with a score and a plain-language verdict, then a prioritised action list,
then the detail for each finding. Technical evidence is included but placed last
within each finding so it can be skipped or handed to a developer.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Optional

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate, Frame, KeepTogether, PageBreak, PageTemplate, Paragraph,
    Spacer, Table, TableStyle,
)

from .. import config
from ..models import SEVERITY_LABELS, SEVERITY_ORDER, Finding, ScanResult
from ..scanner.scoring import MAX_SCORE, score_summary

# Palette shared with the on-screen interface.
INK = colors.HexColor("#12141c")
MUTED = colors.HexColor("#5b6376")
RULE = colors.HexColor("#d8dce5")
ACCENT = colors.HexColor("#5b53e8")
PANEL = colors.HexColor("#f4f5f9")

SEVERITY_PDF_COLOURS = {
    "critical": colors.HexColor("#d92b2b"),
    "high": colors.HexColor("#e2690f"),
    "medium": colors.HexColor("#b8860b"),
    "low": colors.HexColor("#2563eb"),
    "info": colors.HexColor("#5b6376"),
}


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "SSTitle", parent=base["Title"], fontName="Helvetica-Bold",
            fontSize=24, leading=28, textColor=INK, alignment=TA_LEFT, spaceAfter=2,
        ),
        "subtitle": ParagraphStyle(
            "SSSubtitle", parent=base["Normal"], fontName="Helvetica",
            fontSize=10.5, leading=15, textColor=MUTED, spaceAfter=14,
        ),
        "h2": ParagraphStyle(
            "SSH2", parent=base["Heading2"], fontName="Helvetica-Bold",
            fontSize=14, leading=18, textColor=INK, spaceBefore=16, spaceAfter=8,
        ),
        "h3": ParagraphStyle(
            "SSH3", parent=base["Heading3"], fontName="Helvetica-Bold",
            fontSize=11.5, leading=15, textColor=INK, spaceBefore=10, spaceAfter=4,
        ),
        "body": ParagraphStyle(
            "SSBody", parent=base["Normal"], fontName="Helvetica",
            fontSize=9.8, leading=14.5, textColor=INK, spaceAfter=6,
        ),
        "muted": ParagraphStyle(
            "SSMuted", parent=base["Normal"], fontName="Helvetica",
            fontSize=8.6, leading=12.5, textColor=MUTED, spaceAfter=4,
        ),
        "label": ParagraphStyle(
            "SSLabel", parent=base["Normal"], fontName="Helvetica-Bold",
            fontSize=8.2, leading=11, textColor=MUTED, spaceAfter=2,
        ),
        "step": ParagraphStyle(
            "SSStep", parent=base["Normal"], fontName="Helvetica",
            fontSize=9.6, leading=14, textColor=INK, leftIndent=14,
            bulletIndent=2, spaceAfter=3,
        ),
        "evidence": ParagraphStyle(
            "SSEvidence", parent=base["Normal"], fontName="Courier",
            fontSize=7.8, leading=10.5, textColor=MUTED,
        ),
        "score": ParagraphStyle(
            "SSScore", parent=base["Normal"], fontName="Helvetica-Bold",
            fontSize=40, leading=42, textColor=INK, alignment=TA_CENTER,
        ),
        "grade": ParagraphStyle(
            "SSGrade", parent=base["Normal"], fontName="Helvetica-Bold",
            fontSize=11, leading=14, textColor=MUTED, alignment=TA_CENTER,
        ),
    }


def executive_summary(result: ScanResult) -> str:
    """The paragraph shown both in the app and at the top of the PDF."""
    counts = result.counts
    verdict = score_summary(result.score, result.findings)
    total = sum(counts[s] for s in ("critical", "high", "medium", "low"))

    if total == 0:
        return (
            f"SiteScope assessed {result.target_url} and found no security issues in the "
            f"areas it checks. The site scored {result.score} out of {MAX_SCORE} "
            f"(grade {result.grade}). {verdict}"
        )

    parts = [f"{counts[s]} {SEVERITY_LABELS[s].lower()}"
             for s in ("critical", "high", "medium", "low") if counts[s]]
    breakdown = ", ".join(parts[:-1]) + (" and " + parts[-1] if len(parts) > 1 else parts[0])

    return (
        f"SiteScope assessed {result.target_url} across {result.pages_scanned} page"
        f"{'s' if result.pages_scanned != 1 else ''} and identified {total} issue"
        f"{'s' if total != 1 else ''}: {breakdown}. The site scored {result.score} out of "
        f"{MAX_SCORE} (grade {result.grade}). {verdict}"
    )


def _unique_path(path: Path) -> Path:
    """Return `path`, or the next free '-2', '-3'... variant of it.

    Two reports generated for the same site within the same second would
    otherwise resolve to one filename, and the second would silently overwrite
    the first - leaving a database row pointing at the wrong report.
    """
    if not path.exists():
        return path

    for counter in range(2, 1000):
        candidate = path.with_name(f"{path.stem}-{counter}{path.suffix}")
        if not candidate.exists():
            return candidate

    return path.with_name(f"{path.stem}-{datetime.now():%f}{path.suffix}")


def _priority_order(findings: list[Finding]) -> list[Finding]:
    """Fix-first ordering: severity, then whichever is easiest to action."""
    difficulty_rank = {"Easy": 0, "Moderate": 1, "Advanced": 2}
    return sorted(
        [f for f in findings if not f.resolved],
        key=lambda f: (-f.cvss, difficulty_rank.get(f.difficulty, 1), f.title),
    )


def build_pdf_report(
    result: ScanResult,
    output_path: Optional[Path] = None,
    business_name: str = "",
) -> Path:
    """Render the full assessment to a PDF and return its path."""
    if output_path is None:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        safe_host = "".join(c if c.isalnum() or c in "-_." else "_"
                            for c in result.target_url.split("//")[-1])[:50]
        output_path = _unique_path(config.reports_dir() / f"SiteScope-{safe_host}-{stamp}.pdf")

    st = _styles()
    findings = _priority_order(result.findings)
    counts = result.counts

    doc = BaseDocTemplate(
        str(output_path), pagesize=A4,
        leftMargin=20 * mm, rightMargin=20 * mm,
        topMargin=18 * mm, bottomMargin=20 * mm,
        title=f"SiteScope Security Assessment - {result.target_url}",
        author="SiteScope",
    )
    frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="main")
    doc.addPageTemplates([
        PageTemplate(id="report", frames=[frame],
                     onPage=lambda canvas, d: _draw_footer(canvas, d, result))
    ])

    story: list = []

    # -- Cover -----------------------------------------------------------
    story.append(Paragraph("Website Security Assessment", st["title"]))
    subtitle = result.target_url
    if business_name:
        subtitle = f"{business_name} &nbsp;|&nbsp; {subtitle}"
    story.append(Paragraph(
        f"{subtitle}<br/>Scanned {_format_date(result.started_at)} &nbsp;|&nbsp; "
        f"{result.pages_scanned} pages examined &nbsp;|&nbsp; "
        f"{result.scan_type.title()} scan",
        st["subtitle"],
    ))

    story.append(_score_panel(result, st))
    story.append(Spacer(1, 10))

    story.append(Paragraph("What this means", st["h2"]))
    story.append(Paragraph(executive_summary(result), st["body"]))

    story.append(Paragraph("Issues found", st["h2"]))
    story.append(_severity_table(counts, st))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "Severity follows the CVSS v3.1 rating scale used across the security industry: "
        "Critical 9.0-10.0, High 7.0-8.9, Medium 4.0-6.9, Low 0.1-3.9.",
        st["muted"],
    ))

    # -- Action plan -----------------------------------------------------
    if findings:
        story.append(Paragraph("Your action plan", st["h2"]))
        story.append(Paragraph(
            "Work down this list from the top. Items marked "
            "<b>Professional help recommended</b> are worth passing to a web developer "
            "or IT provider rather than attempting yourself.",
            st["body"],
        ))
        story.append(Spacer(1, 4))
        story.append(_action_table(findings, st))

    # -- Detail ----------------------------------------------------------
    if findings:
        story.append(PageBreak())
        story.append(Paragraph("Detailed findings", st["h2"]))
        story.append(Paragraph(
            "Each issue below explains what was found, why it matters to your business, "
            "and the steps to resolve it.",
            st["muted"],
        ))
        story.append(Spacer(1, 8))
        for index, finding in enumerate(findings, start=1):
            story.extend(_finding_block(index, finding, st))

    story.append(PageBreak())
    story.extend(_methodology(result, st))

    doc.build(story)
    return output_path


# --------------------------------------------------------------------------
# Building blocks
# --------------------------------------------------------------------------

def _score_panel(result: ScanResult, st) -> Table:
    verdict = score_summary(result.score, result.findings)
    left = [
        Paragraph(f"{result.score}", st["score"]),
        Paragraph(f"out of {MAX_SCORE}", st["grade"]),
        Paragraph(f"Grade {result.grade}", st["grade"]),
    ]

    seconds = result.duration_seconds
    duration = "under a second" if seconds < 1 else f"{seconds} second{'s' if seconds != 1 else ''}"
    right = [
        Paragraph("OVERALL SECURITY SCORE", st["label"]),
        Paragraph(verdict, st["body"]),
        Paragraph(
            f"Scan completed in {duration} using {result.requests_sent} requests.",
            st["muted"],
        ),
    ]

    table = Table([[left, right]], colWidths=[50 * mm, 120 * mm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), PANEL),
        ("BOX", (0, 0), (-1, -1), 0.6, RULE),
        ("LINEAFTER", (0, 0), (0, 0), 0.6, RULE),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ("TOPPADDING", (0, 0), (-1, -1), 12),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
    ]))
    return table


def _severity_table(counts: dict[str, int], st) -> Table:
    header = [Paragraph("<b>Severity</b>", st["body"]),
              Paragraph("<b>Count</b>", st["body"]),
              Paragraph("<b>What it means for you</b>", st["body"])]

    meaning = {
        "critical": "Fix today. Could expose customer data or hand over control of your site.",
        "high": "Fix this week. A realistic route in for an attacker.",
        "medium": "Plan a fix. Weakens your defences but is not directly exploitable.",
        "low": "Housekeeping. Small improvements that add up.",
        "info": "For your awareness. No action strictly required.",
    }

    rows = [header]
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), PANEL),
        ("GRID", (0, 0), (-1, -1), 0.4, RULE),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]

    row_index = 1
    for severity in SEVERITY_ORDER:
        count = counts.get(severity, 0)
        if count == 0 and severity == "info":
            continue
        colour = SEVERITY_PDF_COLOURS[severity]
        rows.append([
            Paragraph(f'<font color="{_hex(colour)}"><b>{SEVERITY_LABELS[severity]}</b></font>', st["body"]),
            Paragraph(f"<b>{count}</b>", st["body"]),
            Paragraph(meaning[severity], st["muted"]),
        ])
        if count > 0:
            style.append(("LINEBEFORE", (0, row_index), (0, row_index), 3, colour))
        row_index += 1

    table = Table(rows, colWidths=[32 * mm, 18 * mm, 120 * mm])
    table.setStyle(TableStyle(style))
    return table


def _action_table(findings: list[Finding], st) -> Table:
    rows = [[
        Paragraph("<b>#</b>", st["body"]),
        Paragraph("<b>Issue</b>", st["body"]),
        Paragraph("<b>Severity</b>", st["body"]),
        Paragraph("<b>Effort</b>", st["body"]),
    ]]
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), PANEL),
        ("GRID", (0, 0), (-1, -1), 0.4, RULE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]

    for index, finding in enumerate(findings, start=1):
        colour = SEVERITY_PDF_COLOURS[finding.severity]
        effort = finding.difficulty
        if finding.needs_professional:
            effort += "<br/><font size=7>Professional help recommended</font>"
        rows.append([
            Paragraph(str(index), st["muted"]),
            Paragraph(finding.title, st["body"]),
            Paragraph(
                f'<font color="{_hex(colour)}"><b>{SEVERITY_LABELS[finding.severity]}</b></font>'
                f'<br/><font size=7 color="#7a8192">CVSS {finding.cvss}</font>',
                st["muted"],
            ),
            Paragraph(effort, st["muted"]),
        ])
        style.append(("LINEBEFORE", (0, index), (0, index), 3, colour))

    table = Table(rows, colWidths=[10 * mm, 96 * mm, 32 * mm, 32 * mm], repeatRows=1)
    table.setStyle(TableStyle(style))
    return table


def _finding_block(index: int, finding: Finding, st) -> list:
    colour = SEVERITY_PDF_COLOURS[finding.severity]
    hex_colour = _hex(colour)

    header = Table(
        [[
            Paragraph(f"<b>{index}. {finding.title}</b>", st["h3"]),
            Paragraph(
                f'<para align="right"><font color="{hex_colour}"><b>'
                f"{SEVERITY_LABELS[finding.severity]}</b></font><br/>"
                f'<font size=7 color="#7a8192">CVSS {finding.cvss}</font></para>',
                st["muted"],
            ),
        ]],
        colWidths=[130 * mm, 40 * mm],
    )
    header.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (0, 0), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("BACKGROUND", (0, 0), (-1, -1), PANEL),
        ("LINEBEFORE", (0, 0), (0, 0), 3, colour),
    ]))

    block: list = [header, Spacer(1, 5)]

    block.append(Paragraph("WHAT IT MEANS", st["label"]))
    block.append(Paragraph(finding.what_it_means, st["body"]))

    block.append(Paragraph("WHY IT MATTERS TO YOUR BUSINESS", st["label"]))
    block.append(Paragraph(finding.why_it_matters, st["body"]))

    block.append(Paragraph("HOW TO FIX IT", st["label"]))
    for step_number, step in enumerate(finding.how_to_fix, start=1):
        block.append(Paragraph(_escape(step), st["step"], bulletText=f"{step_number}."))

    meta = f"<b>Effort:</b> {finding.difficulty}"
    if finding.needs_professional:
        meta += " &nbsp;|&nbsp; <b>Professional help recommended</b>"
    meta += f" &nbsp;|&nbsp; <b>Category:</b> {finding.owasp}"
    if finding.confidence != "High":
        meta += f" &nbsp;|&nbsp; <b>Confidence:</b> {finding.confidence}"
    block.append(Spacer(1, 2))
    block.append(Paragraph(meta, st["muted"]))

    if finding.evidence:
        block.append(Paragraph("WHAT THE SCANNER SAW", st["label"]))
        evidence = Table(
            [[Paragraph(_escape(finding.evidence).replace("\n", "<br/>"), st["evidence"])]],
            colWidths=[170 * mm],
        )
        evidence.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), PANEL),
            ("BOX", (0, 0), (-1, -1), 0.4, RULE),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        block.append(evidence)

    if finding.reference:
        block.append(Paragraph(f"Further reading: {finding.reference}", st["muted"]))

    block.append(Spacer(1, 14))

    # Keep the header with at least the first paragraph so a finding does not
    # start at the very bottom of a page.
    return [KeepTogether(block[:4])] + block[4:]


def _methodology(result: ScanResult, st) -> list:
    return [
        Paragraph("How this assessment was carried out", st["h2"]),
        Paragraph(
            f"SiteScope performed a passive assessment of {result.target_url} on "
            f"{_format_date(result.started_at)}. It requested pages the same way a browser "
            f"or search engine would and analysed the responses. It did not attempt to "
            f"exploit any weakness, submit data, modify content or access any account. "
            f"A total of {result.requests_sent} requests were made across "
            f"{result.pages_scanned} page(s), rate limited to avoid affecting site performance.",
            st["body"],
        ),
        Paragraph("What was checked", st["h3"]),
        Paragraph(
            "Encryption and certificate validity; redirection of insecure traffic; HTTP "
            "security headers; cookie protection attributes; mixed content; form transmission "
            "security; publicly exposed files and folders; software version disclosure; "
            "cross-origin sharing policy; accepted request methods; and caching of private pages.",
            st["body"],
        ),
        Paragraph("Limitations you should know about", st["h3"]),
        Paragraph(
            "This assessment reviews what your website exposes publicly. It does not test "
            "logged-in areas, business logic, payment flows, or the security of your server "
            "and hosting account. It cannot detect weaknesses that only appear when data is "
            "submitted, such as injection flaws in a search or checkout process. A clear "
            "result here is a good sign, not a guarantee that your site cannot be attacked. "
            "For a site handling payments or sensitive personal information, an assessment "
            "by a qualified security professional is still recommended.",
            st["body"],
        ),
        Paragraph("Standards referenced", st["h3"]),
        Paragraph(
            "Severity ratings use the CVSS v3.1 qualitative scale. Issue categories reference "
            "the OWASP Top 10 (2021). Remediation guidance draws on the OWASP Web Security "
            "Testing Guide and the OWASP Secure Headers Project.",
            st["body"],
        ),
    ]


def _draw_footer(canvas, doc, result: ScanResult) -> None:
    canvas.saveState()
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(MUTED)

    canvas.setStrokeColor(RULE)
    canvas.setLineWidth(0.4)
    canvas.line(20 * mm, 14 * mm, A4[0] - 20 * mm, 14 * mm)

    canvas.drawString(20 * mm, 10 * mm, f"SiteScope security assessment - {result.target_url}")
    canvas.drawRightString(A4[0] - 20 * mm, 10 * mm, f"Page {canvas.getPageNumber()}")

    canvas.setFont("Helvetica-Oblique", 6.5)
    canvas.drawString(
        20 * mm, 6.5 * mm,
        "Confidential. Contains details of security weaknesses - share only with people who need it.",
    )
    canvas.restoreState()


def _format_date(iso: str) -> str:
    try:
        return datetime.fromisoformat(iso).strftime("%d %B %Y at %H:%M UTC")
    except (ValueError, TypeError):
        return iso


def _hex(colour) -> str:
    """reportlab paragraph markup needs colours as #rrggbb strings."""
    return "#" + colour.hexval()[2:]


def _escape(text: str) -> str:
    """Escape text for reportlab's mini-HTML paragraph parser."""
    return (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def estimate_page_count(path: Path) -> int:
    """Read back the page count of a generated PDF for display in the UI."""
    try:
        from pypdf import PdfReader
        return len(PdfReader(str(path)).pages)
    except Exception:
        return 0
