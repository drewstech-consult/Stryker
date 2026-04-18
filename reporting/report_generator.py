#!/usr/bin/env python3
"""
report_generator.py - Professional Pentest PDF Report Generator
Part of STRYKER by Andrews

LEGAL NOTICE: For authorized penetration testing ONLY.
"""

import argparse
import sys
import io
import json
import os
import html
from datetime import datetime

if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace", line_buffering=True)
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace", line_buffering=True)

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether
)
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.graphics import renderPDF
from rich.console import Console
from rich.panel import Panel

console = Console(highlight=False)

# ── Colors ─────────────────────────────────────────────────────────────────────

BLACK      = colors.HexColor("#0a0a0a")
DARK_RED   = colors.HexColor("#8b0000")
RED        = colors.HexColor("#cc1111")
LIGHT_RED  = colors.HexColor("#ffeaea")
ORANGE     = colors.HexColor("#cc5500")
LIGHT_ORG  = colors.HexColor("#fff3e8")
YELLOW_C   = colors.HexColor("#997700")
LIGHT_YEL  = colors.HexColor("#fffbe8")
GREEN_C    = colors.HexColor("#1a6b1a")
LIGHT_GRN  = colors.HexColor("#eafaea")
GRAY       = colors.HexColor("#555555")
LIGHT_GRAY = colors.HexColor("#f5f5f5")
MID_GRAY   = colors.HexColor("#cccccc")
WHITE      = colors.white

SEV_BG = {
    "CRITICAL": LIGHT_RED,
    "HIGH":     LIGHT_ORG,
    "MEDIUM":   LIGHT_YEL,
    "LOW":      LIGHT_GRN,
    "INFO":     LIGHT_GRAY,
}
SEV_FG = {
    "CRITICAL": RED,
    "HIGH":     ORANGE,
    "MEDIUM":   YELLOW_C,
    "LOW":      GREEN_C,
    "INFO":     GRAY,
}

# ── Styles ─────────────────────────────────────────────────────────────────────

def make_styles():
    base = getSampleStyleSheet()
    styles = {}

    styles["title"] = ParagraphStyle(
        "title", fontSize=28, fontName="Helvetica-Bold",
        textColor=BLACK, spaceAfter=4, leading=32
    )
    styles["subtitle"] = ParagraphStyle(
        "subtitle", fontSize=13, fontName="Helvetica",
        textColor=GRAY, spaceAfter=2
    )
    styles["section"] = ParagraphStyle(
        "section", fontSize=16, fontName="Helvetica-Bold",
        textColor=DARK_RED, spaceBefore=16, spaceAfter=8,
        borderPad=4
    )
    styles["subsection"] = ParagraphStyle(
        "subsection", fontSize=12, fontName="Helvetica-Bold",
        textColor=BLACK, spaceBefore=8, spaceAfter=4
    )
    styles["body"] = ParagraphStyle(
        "body", fontSize=10, fontName="Helvetica",
        textColor=BLACK, spaceAfter=6, leading=15
    )
    styles["code"] = ParagraphStyle(
        "code", fontSize=9, fontName="Courier",
        textColor=BLACK, backColor=LIGHT_GRAY,
        spaceAfter=6, leftIndent=12, rightIndent=12,
        borderPad=6, leading=13
    )
    styles["label"] = ParagraphStyle(
        "label", fontSize=9, fontName="Helvetica-Bold",
        textColor=GRAY, spaceAfter=2
    )
    styles["small"] = ParagraphStyle(
        "small", fontSize=8, fontName="Helvetica",
        textColor=GRAY, spaceAfter=4
    )
    styles["center"] = ParagraphStyle(
        "center", fontSize=10, fontName="Helvetica",
        textColor=GRAY, alignment=TA_CENTER
    )

    return styles


# ── Cover page ─────────────────────────────────────────────────────────────────

def build_cover(styles, meta):
    story = []

    story.append(Spacer(1, 40 * mm))

    # Red accent bar
    story.append(HRFlowable(
        width="100%", thickness=4,
        color=RED, spaceAfter=20
    ))

    story.append(Paragraph("PENETRATION TEST REPORT", styles["title"]))
    story.append(Paragraph(meta.get("target", "Target Organization"), ParagraphStyle(
        "target_name", fontSize=20, fontName="Helvetica-Bold",
        textColor=RED, spaceAfter=8
    )))

    story.append(HRFlowable(
        width="100%", thickness=1,
        color=MID_GRAY, spaceAfter=20
    ))

    # Meta table
    meta_data = [
        ["Prepared by",  meta.get("author", "Andrews — STRYKER Toolkit")],
        ["Date",         meta.get("date", datetime.now().strftime("%B %d, %Y"))],
        ["Engagement",   meta.get("engagement", "Web Application Security Assessment")],
        ["Classification", "CONFIDENTIAL"],
        ["Version",      meta.get("version", "1.0")],
    ]

    meta_table = Table(meta_data, colWidths=[50*mm, 110*mm])
    meta_table.setStyle(TableStyle([
        ("FONTNAME",  (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME",  (1, 0), (1, -1), "Helvetica"),
        ("FONTSIZE",  (0, 0), (-1, -1), 10),
        ("TEXTCOLOR", (0, 0), (0, -1), GRAY),
        ("TEXTCOLOR", (1, 0), (1, -1), BLACK),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LINEBELOW", (0, 0), (-1, -2), 0.3, MID_GRAY),
    ]))
    story.append(meta_table)

    story.append(Spacer(1, 30*mm))

    # STRYKER branding
    story.append(HRFlowable(width="100%", thickness=1, color=MID_GRAY, spaceAfter=8))
    story.append(Paragraph(
        "Generated by STRYKER Penetration Testing Framework",
        styles["center"]
    ))
    story.append(Paragraph(
        "For authorized security testing only",
        ParagraphStyle("disclaimer", fontSize=8, fontName="Helvetica",
                       textColor=GRAY, alignment=TA_CENTER)
    ))

    story.append(PageBreak())
    return story


# ── Executive summary ──────────────────────────────────────────────────────────

def build_executive_summary(styles, findings, meta):
    story = []
    story.append(Paragraph("Executive Summary", styles["section"]))
    story.append(HRFlowable(width="100%", thickness=1, color=RED, spaceAfter=10))

    # Count severities
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "INFO").upper()
        counts[sev] = counts.get(sev, 0) + 1

    total = len(findings)

    story.append(Paragraph(
        f"A security assessment was conducted against <b>{meta.get('target', 'the target')}</b> "
        f"on {meta.get('date', datetime.now().strftime('%B %d, %Y'))}. "
        f"The assessment identified a total of <b>{total} finding(s)</b> across multiple severity levels.",
        styles["body"]
    ))
    story.append(Spacer(1, 6))

    # Severity summary table
    sev_data = [["Severity", "Count", "Risk Level"]]
    sev_rows = [
        ("CRITICAL", counts["CRITICAL"],  "Immediate action required"),
        ("HIGH",     counts["HIGH"],      "Address within 7 days"),
        ("MEDIUM",   counts["MEDIUM"],    "Address within 30 days"),
        ("LOW",      counts["LOW"],       "Address in next cycle"),
        ("INFO",     counts["INFO"],      "Informational only"),
    ]
    for sev, count, guidance in sev_rows:
        sev_data.append([sev, str(count), guidance])

    sev_table = Table(sev_data, colWidths=[40*mm, 25*mm, 95*mm])
    sev_style = [
        ("BACKGROUND",  (0, 0), (-1, 0), BLACK),
        ("TEXTCOLOR",   (0, 0), (-1, 0), WHITE),
        ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, -1), 9),
        ("ALIGN",       (1, 0), (1, -1), "CENTER"),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("GRID",        (0, 0), (-1, -1), 0.3, MID_GRAY),
    ]
    for i, (sev, count, _) in enumerate(sev_rows, 1):
        if count > 0:
            sev_style.append(("BACKGROUND", (0, i), (0, i), SEV_BG.get(sev, LIGHT_GRAY)))
            sev_style.append(("TEXTCOLOR",  (0, i), (0, i), SEV_FG.get(sev, GRAY)))
            sev_style.append(("FONTNAME",   (0, i), (0, i), "Helvetica-Bold"))

    sev_table.setStyle(TableStyle(sev_style))
    story.append(sev_table)
    story.append(Spacer(1, 10))

    if meta.get("summary"):
        story.append(Paragraph(meta["summary"], styles["body"]))

    story.append(PageBreak())
    return story


# ── Findings ───────────────────────────────────────────────────────────────────

def build_findings(styles, findings):
    story = []
    story.append(Paragraph("Detailed Findings", styles["section"]))
    story.append(HRFlowable(width="100%", thickness=1, color=RED, spaceAfter=10))

    if not findings:
        story.append(Paragraph("No findings were identified during this assessment.", styles["body"]))
        return story

    for i, f in enumerate(findings, 1):
        sev     = f.get("severity", "INFO").upper()
        title   = f.get("title", f"Finding {i}")
        tool    = f.get("tool", "Manual")
        target  = f.get("target", "")
        desc    = f.get("description", "")
        payload = f.get("payload", "")
        evidence= f.get("evidence", "")
        rec     = f.get("recommendation", "")

        bg_color = SEV_BG.get(sev, LIGHT_GRAY)
        fg_color = SEV_FG.get(sev, GRAY)

        # Finding header
        header_data = [[
            Paragraph(f"<b>Finding {i:02d}</b>", ParagraphStyle(
                "fnum", fontSize=9, fontName="Helvetica-Bold", textColor=GRAY
            )),
            Paragraph(f"<b>{sev}</b>", ParagraphStyle(
                "fsev", fontSize=10, fontName="Helvetica-Bold",
                textColor=fg_color, alignment=TA_RIGHT
            )),
        ]]
        header_table = Table(header_data, colWidths=[130*mm, 30*mm])
        header_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), bg_color),
            ("TOPPADDING",    (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING",   (0, 0), (0, 0), 8),
            ("RIGHTPADDING",  (-1, 0), (-1, -1), 8),
        ]))

        finding_block = [
            header_table,
            Paragraph(title, ParagraphStyle(
                "ftitle", fontSize=13, fontName="Helvetica-Bold",
                textColor=BLACK, spaceBefore=6, spaceAfter=6,
                leftIndent=4
            )),
        ]

        # Details table
        details = []
        if tool:
            details.append(["Tool", tool])
        if target:
            details.append(["Target", target])

        if details:
            det_table = Table(details, colWidths=[25*mm, 135*mm])
            det_table.setStyle(TableStyle([
                ("FONTNAME",  (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTNAME",  (1, 0), (1, -1), "Helvetica"),
                ("FONTSIZE",  (0, 0), (-1, -1), 9),
                ("TEXTCOLOR", (0, 0), (0, -1), GRAY),
                ("TOPPADDING",    (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LINEBELOW", (0, 0), (-1, -1), 0.3, MID_GRAY),
            ]))
            finding_block.append(det_table)
            finding_block.append(Spacer(1, 6))

        if desc:
            finding_block.append(Paragraph("Description", styles["label"]))
            finding_block.append(Paragraph(html.escape(str(desc)), styles["body"]))

        if payload:
            finding_block.append(Paragraph("Payload / Proof", styles["label"]))
            finding_block.append(Paragraph(html.escape(str(payload)), styles["code"]))

        if evidence:
            finding_block.append(Paragraph("Evidence", styles["label"]))
            finding_block.append(Paragraph(html.escape(str(evidence)), styles["body"]))

        if rec:
            finding_block.append(Paragraph("Recommendation", styles["label"]))
            finding_block.append(Paragraph(html.escape(str(rec)), ParagraphStyle(
                "rec", fontSize=10, fontName="Helvetica",
                textColor=GREEN_C, spaceAfter=6,
                leftIndent=8, borderPad=4
            )))

        finding_block.append(HRFlowable(
            width="100%", thickness=0.5, color=MID_GRAY, spaceAfter=12
        ))

        story.append(KeepTogether(finding_block))
        story.append(Spacer(1, 4))

    return story


# ── Remediation table ──────────────────────────────────────────────────────────

def build_remediation(styles, findings):
    story = []
    story.append(PageBreak())
    story.append(Paragraph("Remediation Summary", styles["section"]))
    story.append(HRFlowable(width="100%", thickness=1, color=RED, spaceAfter=10))

    story.append(Paragraph(
        "The following table summarizes all findings and recommended actions, "
        "ordered by severity.",
        styles["body"]
    ))
    story.append(Spacer(1, 6))

    rem_data = [["#", "Severity", "Finding", "Recommendation"]]

    sorted_findings = sorted(
        findings,
        key=lambda f: ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].index(
            f.get("severity","INFO").upper()
        )
    )

    for i, f in enumerate(sorted_findings, 1):
        sev = f.get("severity", "INFO").upper()
        rem_data.append([
            str(i),
            sev,
            Paragraph(f.get("title", "")[:60], ParagraphStyle(
                "rem_title", fontSize=8, fontName="Helvetica", textColor=BLACK
            )),
            Paragraph(f.get("recommendation", "")[:120], ParagraphStyle(
                "rem_rec", fontSize=8, fontName="Helvetica", textColor=GREEN_C
            )),
        ])

    rem_table = Table(rem_data, colWidths=[8*mm, 22*mm, 65*mm, 65*mm])
    rem_style = [
        ("BACKGROUND",    (0, 0), (-1, 0), BLACK),
        ("TEXTCOLOR",     (0, 0), (-1, 0), WHITE),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, 0), 9),
        ("ALIGN",         (0, 0), (1, -1), "CENTER"),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("GRID",          (0, 0), (-1, -1), 0.3, MID_GRAY),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [WHITE, LIGHT_GRAY]),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
    ]
    for i, f in enumerate(sorted_findings, 1):
        sev = f.get("severity", "INFO").upper()
        rem_style.append(("BACKGROUND", (1, i), (1, i), SEV_BG.get(sev, LIGHT_GRAY)))
        rem_style.append(("TEXTCOLOR",  (1, i), (1, i), SEV_FG.get(sev, GRAY)))
        rem_style.append(("FONTNAME",   (1, i), (1, i), "Helvetica-Bold"))

    rem_table.setStyle(TableStyle(rem_style))
    story.append(rem_table)

    return story


# ── Page numbering ─────────────────────────────────────────────────────────────

def add_page_number(canvas_obj, doc):
    canvas_obj.saveState()
    canvas_obj.setFont("Helvetica", 8)
    canvas_obj.setFillColor(GRAY)

    # Footer line
    canvas_obj.setStrokeColor(MID_GRAY)
    canvas_obj.setLineWidth(0.5)
    canvas_obj.line(20*mm, 18*mm, A4[0] - 20*mm, 18*mm)

    # Page number
    canvas_obj.drawRightString(
        A4[0] - 20*mm, 12*mm,
        f"Page {doc.page}"
    )
    # Footer label
    canvas_obj.drawString(
        20*mm, 12*mm,
        "CONFIDENTIAL — STRYKER Pentest Report"
    )
    canvas_obj.restoreState()


# ── Main generator ─────────────────────────────────────────────────────────────

def generate_report(findings, meta, output_path):
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=20*mm,
        rightMargin=20*mm,
        topMargin=20*mm,
        bottomMargin=25*mm,
        title=f"Pentest Report — {meta.get('target', 'Target')}",
        author=meta.get("author", "Andrews — STRYKER"),
        subject="Penetration Test Report",
    )

    styles = make_styles()
    story  = []

    story += build_cover(styles, meta)
    story += build_executive_summary(styles, findings, meta)
    story += build_findings(styles, findings)
    story += build_remediation(styles, findings)

    doc.build(story, onFirstPage=add_page_number, onLaterPages=add_page_number)


# ── Sample data builder ────────────────────────────────────────────────────────

SAMPLE_FINDINGS = [
    {
        "severity":      "HIGH",
        "title":         "Reflected XSS in search parameter",
        "tool":          "XSS Scanner (use 3)",
        "target":        "https://example.com/search?q=",
        "description":   "The 'q' parameter reflects user input directly into the HTML response without encoding. An attacker can inject JavaScript that executes in the victim's browser.",
        "payload":       "<![CDATA[<script>alert(1)</script>]]>",
        "evidence":      "Dangerous token '<script>' reflected in response body",
        "recommendation":"Encode all user-supplied input before rendering in HTML. Use Content-Security-Policy headers.",
    },
    {
        "severity":      "MEDIUM",
        "title":         "Missing X-XSS-Protection security header",
        "tool":          "XSS Scanner (use 3)",
        "target":        "https://example.com",
        "description":   "The application does not set the X-XSS-Protection HTTP header, leaving users without browser-level XSS filtering.",
        "payload":       "N/A",
        "evidence":      "X-XSS-Protection header absent in all HTTP responses",
        "recommendation":"Add 'X-XSS-Protection: 1; mode=block' to all HTTP responses via next.config.js headers().",
    },
    {
        "severity":      "MEDIUM",
        "title":         "JWT token contains PII in payload",
        "tool":          "JWT Analyzer (use 5)",
        "target":        "auth-token cookie",
        "description":   "The JWT token payload contains the user's email address and email_verified status. JWT payloads are base64 encoded, not encrypted — anyone with the token can read this data.",
        "payload":       '{"email": "user@example.com", "email_verified": true}',
        "evidence":      "PII claims found: email, email_verified",
        "recommendation":"Minimize PII stored in JWT tokens. Store only a user ID and fetch user details server-side when needed.",
    },
]


# ── CLI ────────────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="Report Generator - part of STRYKER",
        epilog="""
Examples:
  # Generate report from JSON findings file
  python reporting/report_generator.py -f findings.json -t "Acme Corp" -o report.pdf

  # Generate sample report to see the format
  python reporting/report_generator.py --sample -t "Example Corp" -o sample_report.pdf

  # Full report with all metadata
  python reporting/report_generator.py -f findings.json -t "Client Name" \\
    -a "Andrews" -e "Web App Assessment" -o client_report.pdf
        """
    )
    parser.add_argument("-f", "--findings",   help="JSON file with findings")
    parser.add_argument("-t", "--target",     default="Target Organization", help="Target name")
    parser.add_argument("-a", "--author",     default="Andrews — STRYKER Toolkit", help="Author name")
    parser.add_argument("-e", "--engagement", default="Web Application Security Assessment", help="Engagement type")
    parser.add_argument("-s", "--summary",    help="Executive summary text")
    parser.add_argument("-o", "--output",     default="stryker_report.pdf", help="Output PDF path")
    parser.add_argument("--sample",           action="store_true", help="Generate a sample report")
    return parser.parse_args()


def main():
    args = parse_args()

    console.print(Panel.fit(
        "[bold red]STRYKER[/bold red] [white]//[/white] [cyan]Report Generator[/cyan]\n"
        "[dim]Professional PDF Pentest Reports | For authorized testing only[/dim]",
        border_style="red"
    ))
    console.print()

    # Load findings
    findings = []
    if args.sample:
        findings = SAMPLE_FINDINGS
        console.print("  [dim]Using sample findings...[/dim]")
    elif args.findings:
        try:
            with open(args.findings) as f:
                findings = json.load(f)
            console.print(f"  [dim]Loaded {len(findings)} finding(s) from {args.findings}[/dim]")
        except FileNotFoundError:
            console.print(f"  [red]Findings file not found: {args.findings}[/red]")
            sys.exit(1)
        except json.JSONDecodeError:
            console.print(f"  [red]Invalid JSON in findings file[/red]")
            sys.exit(1)
    else:
        console.print("  [yellow]No findings file provided. Use --sample to generate a demo report.[/yellow]")
        sys.exit(1)

    meta = {
        "target":     args.target,
        "author":     args.author,
        "engagement": args.engagement,
        "date":       datetime.now().strftime("%B %d, %Y"),
        "version":    "1.0",
        "summary":    args.summary or (
            f"This report presents the findings from a security assessment conducted against "
            f"{args.target}. The assessment used the STRYKER Penetration Testing Framework "
            f"to identify vulnerabilities across web application, authentication, and infrastructure layers."
        ),
    }

    console.print(f"  [dim]Target:[/dim]     [cyan]{meta['target']}[/cyan]")
    console.print(f"  [dim]Findings:[/dim]   [cyan]{len(findings)}[/cyan]")
    console.print(f"  [dim]Output:[/dim]     [cyan]{args.output}[/cyan]")
    console.print()
    console.print("  [dim]Generating PDF report...[/dim]")

    try:
        generate_report(findings, meta, args.output)
        console.print(f"\n  [green]Report generated successfully: {args.output}[/green]")
        console.print(f"  [dim]Open it with any PDF viewer.[/dim]\n")
    except Exception as e:
        console.print(f"\n  [red]Error generating report: {e}[/red]\n")
        raise


if __name__ == "__main__":
    main()