"""
report_generator.py - Multi-format scan report generation.

Generates TXT, JSON, and PDF reports from scan results and saves
them to the reports/ directory with timestamped filenames.

All report methods are pure functions that receive structured data
and produce files – no print statements, no side effects beyond I/O.
"""

import json
import os
import logging
from datetime import datetime
from typing import Dict, List, Optional

logger = logging.getLogger("vuln_scanner")

# ── PDF support (optional – graceful if reportlab missing) ──────────────
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.lib.colors import (
        HexColor,
        black,
        white,
    )
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import (
        SimpleDocTemplate,
        Paragraph,
        Spacer,
        Table,
        TableStyle,
    )

    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    logger.warning(
        "reportlab is not installed – PDF reports will be unavailable. "
        "Install with:  pip install reportlab"
    )


# ══════════════════════════════════════════════════════════════════════ #
#  Shared helpers
# ══════════════════════════════════════════════════════════════════════ #
def _reports_dir() -> str:
    """Return the absolute path to the reports/ directory (created if needed)."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
    os.makedirs(path, exist_ok=True)
    return path


def _timestamp_str() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def _base_name(target: str) -> str:
    """Sanitise a target string for safe use in filenames."""
    return target.replace(".", "_").replace(":", "-")


# ══════════════════════════════════════════════════════════════════════ #
#  Report data container
# ══════════════════════════════════════════════════════════════════════ #
class ScanReport:
    """
    Immutable data container holding everything needed to render a report.

    Create one instance after the scan finishes and pass it to each
    report generator.
    """

    def __init__(
        self,
        target: str,
        host_alive: bool,
        start_port: int,
        end_port: int,
        open_ports: List[int],
        services: Dict[int, Dict[str, str]],
        vulnerabilities: List[dict],
        risk: dict,
        scan_duration: str,
        phase_timings: Dict[str, str],
        scan_timestamp: Optional[str] = None,
    ) -> None:
        self.target = target
        self.host_alive = host_alive
        self.start_port = start_port
        self.end_port = end_port
        self.open_ports = open_ports
        self.services = services
        self.vulnerabilities = vulnerabilities
        self.risk = risk
        self.scan_duration = scan_duration
        self.phase_timings = phase_timings
        self.scan_timestamp = scan_timestamp or datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

    def to_dict(self) -> dict:
        """Serialisable dictionary representation of the entire scan."""
        return {
            "scan_metadata": {
                "target": self.target,
                "timestamp": self.scan_timestamp,
                "duration": self.scan_duration,
                "port_range": f"{self.start_port}-{self.end_port}",
                "phase_timings": self.phase_timings,
            },
            "host_discovery": {
                "target": self.target,
                "alive": self.host_alive,
            },
            "port_scan": {
                "total_scanned": self.end_port - self.start_port + 1,
                "open_count": len(self.open_ports),
                "open_ports": self.open_ports,
            },
            "services": {
                str(port): info for port, info in self.services.items()
            },
            "vulnerabilities": self.vulnerabilities,
            "risk_assessment": self.risk,
        }


# ══════════════════════════════════════════════════════════════════════ #
#  TXT report
# ══════════════════════════════════════════════════════════════════════ #
def generate_txt_report(report: ScanReport) -> str:
    """
    Generate a plain-text report file.

    Returns:
        Absolute path of the generated file.
    """
    ts = _timestamp_str()
    filename = f"scan_{_base_name(report.target)}_{ts}.txt"
    filepath = os.path.join(_reports_dir(), filename)

    sep = "=" * 72

    lines = [
        sep,
        "  VULNERABILITY SCAN REPORT",
        sep,
        f"  Target        : {report.target}",
        f"  Timestamp     : {report.scan_timestamp}",
        f"  Duration      : {report.scan_duration}",
        f"  Host Status   : {'UP' if report.host_alive else 'DOWN'}",
        f"  Port Range    : {report.start_port} – {report.end_port}",
        f"  Total Scanned : {report.end_port - report.start_port + 1}",
        sep,
        "",
        "  PHASE TIMINGS",
        "  " + "-" * 40,
    ]
    for phase, dur in report.phase_timings.items():
        lines.append(f"    {phase:<28} {dur}")

    # ── Open Ports ────────────────────────────────────
    lines += [
        "",
        sep,
        "  OPEN PORTS",
        sep,
        f"  {'PORT':<10} {'SERVICE':<20}",
        "  " + "-" * 30,
    ]
    for port in report.open_ports:
        svc = report.services.get(port, {})
        svc_name = svc.get("service", "unknown") if svc else "unknown"
        lines.append(f"  {port:<10} {svc_name:<20}")

    # ── Services ──────────────────────────────────────
    if report.services:
        lines += [
            "",
            sep,
            "  DETECTED SERVICES",
            sep,
            f"  {'PORT':<8} {'SERVICE':<12} {'PRODUCT':<24} {'VERSION'}",
            "  " + "-" * 60,
        ]
        for port, info in sorted(report.services.items()):
            lines.append(
                f"  {port:<8} {info.get('service',''):<12} "
                f"{info.get('product',''):<24} {info.get('version','')}"
            )

    # ── Vulnerabilities ───────────────────────────────
    lines += [
        "",
        sep,
        "  VULNERABILITIES",
        sep,
    ]
    if report.vulnerabilities:
        lines.append(
            f"  {'SEV':<10} {'PORT':<8} {'TITLE':<40} {'SOURCE'}"
        )
        lines.append("  " + "-" * 70)
        for v in report.vulnerabilities:
            lines.append(
                f"  {v['severity']:<10} {v['port']:<8} "
                f"{v['title'][:38]:<40} {v['source']}"
            )
        lines.append("")
        for i, v in enumerate(report.vulnerabilities, 1):
            lines.append(f"  [{v['severity']}] {v['title']}")
            lines.append(f"    Port {v['port']} · {v['service']} · {v['source']}")
            lines.append(f"    {v['description'][:160]}")
            lines.append("")
    else:
        lines.append("  No vulnerabilities detected.")

    # ── Risk Assessment ───────────────────────────────
    r = report.risk
    lines += [
        sep,
        "  RISK ASSESSMENT",
        sep,
        f"  Overall Score  : {r['score']}/10",
        f"  Rating         : {r['rating']}",
        f"  Total Findings : {r['total']}",
        "",
        f"    CRITICAL : {r['critical']}",
        f"    HIGH     : {r['high']}",
        f"    MEDIUM   : {r['medium']}",
        f"    LOW      : {r['low']}",
        f"    INFO     : {r['info']}",
        sep,
        "",
        f"  Report generated at {report.scan_timestamp}",
        sep,
    ]

    with open(filepath, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")

    logger.info("TXT report saved: %s", filepath)
    return filepath


# ══════════════════════════════════════════════════════════════════════ #
#  JSON report
# ══════════════════════════════════════════════════════════════════════ #
def generate_json_report(report: ScanReport) -> str:
    """
    Generate a JSON report file.

    Returns:
        Absolute path of the generated file.
    """
    ts = _timestamp_str()
    filename = f"scan_{_base_name(report.target)}_{ts}.json"
    filepath = os.path.join(_reports_dir(), filename)

    with open(filepath, "w", encoding="utf-8") as fh:
        json.dump(report.to_dict(), fh, indent=2, default=str)

    logger.info("JSON report saved: %s", filepath)
    return filepath


# ══════════════════════════════════════════════════════════════════════ #
#  PDF report  (requires reportlab)
# ══════════════════════════════════════════════════════════════════════ #
_DARK_BG = HexColor("#1a1a2e") if REPORTLAB_AVAILABLE else None
_ACCENT = HexColor("#e94560") if REPORTLAB_AVAILABLE else None
_HEADER_BG = HexColor("#16213e") if REPORTLAB_AVAILABLE else None
_ROW_ALT = HexColor("#0f3460") if REPORTLAB_AVAILABLE else None
_TEXT_LIGHT = HexColor("#eaeaea") if REPORTLAB_AVAILABLE else None

_SEV_COLORS = {}
if REPORTLAB_AVAILABLE:
    _SEV_COLORS = {
        "CRITICAL": HexColor("#ff1744"),
        "HIGH": HexColor("#ff5252"),
        "MEDIUM": HexColor("#ffab40"),
        "LOW": HexColor("#40c4ff"),
        "INFO": HexColor("#b0bec5"),
    }


def generate_pdf_report(report: ScanReport) -> Optional[str]:
    """
    Generate a professional PDF report using reportlab.

    Returns:
        Absolute path of the generated file, or None if reportlab unavailable.
    """
    if not REPORTLAB_AVAILABLE:
        logger.warning("PDF report skipped – reportlab not installed")
        return None

    ts = _timestamp_str()
    filename = f"scan_{_base_name(report.target)}_{ts}.pdf"
    filepath = os.path.join(_reports_dir(), filename)

    doc = SimpleDocTemplate(
        filepath,
        pagesize=A4,
        topMargin=20 * mm,
        bottomMargin=15 * mm,
        leftMargin=15 * mm,
        rightMargin=15 * mm,
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontSize=22,
        textColor=_ACCENT,
        spaceAfter=6 * mm,
    )
    heading_style = ParagraphStyle(
        "SectionHead",
        parent=styles["Heading2"],
        fontSize=14,
        textColor=_ACCENT,
        spaceBefore=8 * mm,
        spaceAfter=3 * mm,
    )
    body_style = ParagraphStyle(
        "BodyText2",
        parent=styles["BodyText"],
        fontSize=10,
        textColor=black,
        leading=14,
    )

    story = []

    # ── Title ─────────────────────────────────────────
    story.append(Paragraph("Vulnerability Scan Report", title_style))
    story.append(
        Paragraph(
            f"Target: <b>{report.target}</b> &nbsp;|&nbsp; "
            f"{report.scan_timestamp} &nbsp;|&nbsp; Duration: {report.scan_duration}",
            body_style,
        )
    )
    story.append(Spacer(1, 4 * mm))

    # ── Metadata table ────────────────────────────────
    story.append(Paragraph("Scan Overview", heading_style))
    meta_data = [
        ["Host Status", "UP" if report.host_alive else "DOWN"],
        ["Port Range", f"{report.start_port} – {report.end_port}"],
        ["Ports Scanned", str(report.end_port - report.start_port + 1)],
        ["Open Ports", str(len(report.open_ports))],
        ["Vulnerabilities", str(report.risk["total"])],
        ["Risk Score", f"{report.risk['score']}/10 ({report.risk['rating']})"],
    ]

    # Add phase timings
    for phase, dur in report.phase_timings.items():
        meta_data.append([f"⏱ {phase}", dur])

    meta_table = Table(meta_data, colWidths=[55 * mm, 115 * mm])
    meta_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), _HEADER_BG),
                ("TEXTCOLOR", (0, 0), (0, -1), white),
                ("TEXTCOLOR", (1, 0), (1, -1), black),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#cccccc")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.append(meta_table)
    story.append(Spacer(1, 4 * mm))

    # ── Open Ports table ──────────────────────────────
    if report.open_ports:
        story.append(Paragraph("Open Ports", heading_style))
        port_rows = [["Port", "Service", "Product", "Version"]]
        for port in report.open_ports:
            svc = report.services.get(port, {})
            port_rows.append(
                [
                    str(port),
                    svc.get("service", "—"),
                    svc.get("product", "—"),
                    svc.get("version", "—"),
                ]
            )

        port_table = Table(port_rows, colWidths=[25 * mm, 35 * mm, 55 * mm, 55 * mm])
        port_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), _HEADER_BG),
                    ("TEXTCOLOR", (0, 0), (-1, 0), white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#cccccc")),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [white, HexColor("#f4f4f4")]),
                    ("TOPPADDING", (0, 0), (-1, -1), 3),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ]
            )
        )
        story.append(port_table)
        story.append(Spacer(1, 4 * mm))

    # ── Vulnerabilities table ─────────────────────────
    story.append(Paragraph("Vulnerabilities", heading_style))
    if report.vulnerabilities:
        vuln_rows = [["Severity", "Port", "Title", "Source"]]
        for v in report.vulnerabilities:
            vuln_rows.append(
                [v["severity"], str(v["port"]), v["title"][:45], v["source"]]
            )

        vuln_table = Table(
            vuln_rows, colWidths=[22 * mm, 18 * mm, 95 * mm, 35 * mm]
        )

        # Build row-level severity colouring
        table_styles = [
            ("BACKGROUND", (0, 0), (-1, 0), _HEADER_BG),
            ("TEXTCOLOR", (0, 0), (-1, 0), white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#cccccc")),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]
        for idx, v in enumerate(report.vulnerabilities, start=1):
            sev_color = _SEV_COLORS.get(v["severity"].upper(), black)
            table_styles.append(("TEXTCOLOR", (0, idx), (0, idx), sev_color))

        vuln_table.setStyle(TableStyle(table_styles))
        story.append(vuln_table)
        story.append(Spacer(1, 3 * mm))

        # Detail paragraphs
        for v in report.vulnerabilities:
            sev_hex = _SEV_COLORS.get(v["severity"].upper(), black).hexval()
            story.append(
                Paragraph(
                    f'<font color="{sev_hex}"><b>[{v["severity"]}]</b></font> '
                    f"<b>{v['title']}</b><br/>"
                    f"<font size=8>Port {v['port']} · {v['service']} · {v['source']}<br/>"
                    f"{v['description'][:200]}</font>",
                    body_style,
                )
            )
            story.append(Spacer(1, 2 * mm))
    else:
        story.append(Paragraph("No vulnerabilities detected.", body_style))

    # ── Risk Assessment ───────────────────────────────
    story.append(Paragraph("Risk Assessment", heading_style))
    r = report.risk
    risk_data = [
        ["Metric", "Value"],
        ["Overall Score", f"{r['score']}/10"],
        ["Rating", r["rating"]],
        ["Critical", str(r["critical"])],
        ["High", str(r["high"])],
        ["Medium", str(r["medium"])],
        ["Low", str(r["low"])],
        ["Info", str(r["info"])],
        ["Total", str(r["total"])],
    ]
    risk_table = Table(risk_data, colWidths=[50 * mm, 50 * mm])
    risk_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), _HEADER_BG),
                ("TEXTCOLOR", (0, 0), (-1, 0), white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#cccccc")),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]
        )
    )
    story.append(risk_table)

    # ── Build PDF ─────────────────────────────────────
    try:
        doc.build(story)
        logger.info("PDF report saved: %s", filepath)
        return filepath
    except Exception as exc:
        logger.error("Failed to build PDF report: %s", exc)
        return None
