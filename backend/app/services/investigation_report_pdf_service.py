import uuid
from datetime import datetime
from html import escape
from io import BytesIO
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether,
    LongTable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from sqlalchemy.orm import Session

from app.schemas.investigation_report import (
    InvestigationReportExportResult,
    InvestigationReportFormat,
    InvestigationReportGenerationRequest,
    InvestigationReportStatus,
)
from app.services.investigation_report_export_service import (
    InvestigationReportArtifact,
    InvestigationReportFormatError,
    build_report_export_payload,
    calculate_bytes_sha256,
    safe_filename_component,
)
from app.services.investigation_report_service import (
    build_investigation_report_document,
)


PAGE_WIDTH = A4[0]
PAGE_HEIGHT = A4[1]

DARK_BLUE = colors.HexColor("#0F172A")
SLATE = colors.HexColor("#334155")
LIGHT_SLATE = colors.HexColor("#E2E8F0")
MUTED = colors.HexColor("#64748B")
CYAN = colors.HexColor("#0891B2")
LIGHT_CYAN = colors.HexColor("#ECFEFF")
GREEN = colors.HexColor("#047857")
LIGHT_GREEN = colors.HexColor("#ECFDF5")
RED = colors.HexColor("#B91C1C")
LIGHT_RED = colors.HexColor("#FEF2F2")
AMBER = colors.HexColor("#B45309")
LIGHT_AMBER = colors.HexColor("#FFFBEB")
WHITE = colors.white


def normalize_text(
    value: Any,
    fallback: str = "",
) -> str:
    if value is None:
        return fallback

    if isinstance(value, bool):
        return "Yes" if value else "No"

    normalized = str(value).strip()

    return normalized or fallback


def safe_text(
    value: Any,
    fallback: str = "",
) -> str:
    return escape(
        normalize_text(
            value,
            fallback,
        )
    )


def format_datetime(
    value: Any,
) -> str:
    normalized = normalize_text(
        value
    )

    if not normalized:
        return "Not recorded"

    try:
        parsed = datetime.fromisoformat(
            normalized.replace(
                "Z",
                "+00:00",
            )
        )

        return parsed.strftime(
            "%Y-%m-%d %H:%M:%S %Z"
        ).strip()

    except ValueError:
        return normalized


def format_identifier(
    value: Any,
) -> str:
    normalized = normalize_text(
        value
    )

    if not normalized:
        return "Not recorded"

    if len(normalized) <= 32:
        return normalized

    return (
        f"{normalized[:16]}"
        f"..."
        f"{normalized[-16:]}"
    )


def build_styles() -> dict[str, ParagraphStyle]:
    sample_styles = getSampleStyleSheet()

    return {
        "title": ParagraphStyle(
            "ReportTitle",
            parent=sample_styles["Title"],
            fontName="Helvetica-Bold",
            fontSize=25,
            leading=30,
            textColor=DARK_BLUE,
            alignment=TA_CENTER,
            spaceAfter=12,
        ),
        "subtitle": ParagraphStyle(
            "ReportSubtitle",
            parent=sample_styles["Normal"],
            fontName="Helvetica",
            fontSize=11,
            leading=16,
            textColor=MUTED,
            alignment=TA_CENTER,
            spaceAfter=10,
        ),
        "heading": ParagraphStyle(
            "ReportHeading",
            parent=sample_styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=15,
            leading=19,
            textColor=DARK_BLUE,
            spaceBefore=12,
            spaceAfter=8,
        ),
        "subheading": ParagraphStyle(
            "ReportSubheading",
            parent=sample_styles["Heading3"],
            fontName="Helvetica-Bold",
            fontSize=11,
            leading=15,
            textColor=SLATE,
            spaceBefore=8,
            spaceAfter=5,
        ),
        "body": ParagraphStyle(
            "ReportBody",
            parent=sample_styles["BodyText"],
            fontName="Helvetica",
            fontSize=9,
            leading=14,
            textColor=DARK_BLUE,
            spaceAfter=6,
        ),
        "small": ParagraphStyle(
            "ReportSmall",
            parent=sample_styles["BodyText"],
            fontName="Helvetica",
            fontSize=7.5,
            leading=11,
            textColor=SLATE,
        ),
        "metadata": ParagraphStyle(
            "ReportMetadata",
            parent=sample_styles["BodyText"],
            fontName="Helvetica",
            fontSize=7,
            leading=10,
            textColor=MUTED,
        ),
        "hash": ParagraphStyle(
            "ReportHash",
            parent=sample_styles["Code"],
            fontName="Courier",
            fontSize=6.5,
            leading=9,
            textColor=SLATE,
            wordWrap="CJK",
        ),
        "supported": ParagraphStyle(
            "SupportedClaim",
            parent=sample_styles["BodyText"],
            fontName="Helvetica",
            fontSize=8.5,
            leading=13,
            textColor=GREEN,
        ),
        "unsupported": ParagraphStyle(
            "UnsupportedClaim",
            parent=sample_styles["BodyText"],
            fontName="Helvetica",
            fontSize=8.5,
            leading=13,
            textColor=RED,
        ),
    }


def paragraph(
    value: Any,
    style: ParagraphStyle,
    fallback: str = "Not recorded",
) -> Paragraph:
    return Paragraph(
        safe_text(
            value,
            fallback,
        ).replace(
            "\n",
            "<br/>",
        ),
        style,
    )


def build_key_value_table(
    rows: list[tuple[str, Any]],
    styles: dict[str, ParagraphStyle],
    label_width: float = 47 * mm,
) -> Table:
    usable_width = (
        PAGE_WIDTH
        - 40 * mm
    )

    data = [
        [
            paragraph(
                label,
                styles["small"],
            ),
            paragraph(
                value,
                styles["body"],
            ),
        ]
        for label, value in rows
    ]

    table = Table(
        data,
        colWidths=[
            label_width,
            usable_width - label_width,
        ],
        hAlign="LEFT",
    )

    table.setStyle(
        TableStyle(
            [
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP",
                ),
                (
                    "BACKGROUND",
                    (0, 0),
                    (0, -1),
                    LIGHT_CYAN,
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (0, -1),
                    SLATE,
                ),
                (
                    "BOX",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    LIGHT_SLATE,
                ),
                (
                    "INNERGRID",
                    (0, 0),
                    (-1, -1),
                    0.25,
                    LIGHT_SLATE,
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    6,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    6,
                ),
            ]
        )
    )

    return table


def append_bullet_items(
    story: list[Any],
    values: list[Any],
    styles: dict[str, ParagraphStyle],
    empty_message: str,
) -> None:
    if not values:
        story.append(
            paragraph(
                empty_message,
                styles["body"],
            )
        )

        return

    for value in values:
        story.append(
            Paragraph(
                safe_text(
                    value,
                    "Not recorded",
                ),
                styles["body"],
                bulletText="•",
            )
        )


def draw_page_footer(
    canvas,
    document,
) -> None:
    canvas.saveState()

    canvas.setStrokeColor(
        LIGHT_SLATE
    )

    canvas.setLineWidth(
        0.5
    )

    canvas.line(
        20 * mm,
        15 * mm,
        PAGE_WIDTH - 20 * mm,
        15 * mm,
    )

    canvas.setFont(
        "Helvetica",
        7,
    )

    canvas.setFillColor(
        MUTED
    )

    canvas.drawString(
        20 * mm,
        10 * mm,
        "DFIR Assistant - Evidence-Linked Investigation Report",
    )

    canvas.drawRightString(
        PAGE_WIDTH - 20 * mm,
        10 * mm,
        f"Page {document.page}",
    )

    canvas.restoreState()


def append_title_page(
    story: list[Any],
    payload: dict[str, Any],
    styles: dict[str, ParagraphStyle],
) -> None:
    case_data = payload.get(
        "case",
        {},
    )

    summary = payload.get(
        "summary",
        {},
    )

    analyst_review = payload.get(
        "analyst_review",
        {},
    )

    story.append(
        Spacer(
            1,
            25 * mm,
        )
    )

    story.append(
        paragraph(
            "DFIR Assistant",
            styles["subtitle"],
        )
    )

    story.append(
        paragraph(
            "Evidence-Linked Investigation Report",
            styles["title"],
        )
    )

    story.append(
        Spacer(
            1,
            5 * mm,
        )
    )

    story.append(
        paragraph(
            case_data.get(
                "title"
            ),
            styles["heading"],
        )
    )

    story.append(
        paragraph(
            (
                f"Investigation summary version "
                f"{normalize_text(summary.get('version_number'), '1')}"
            ),
            styles["subtitle"],
        )
    )

    story.append(
        Spacer(
            1,
            10 * mm,
        )
    )

    story.append(
        build_key_value_table(
            [
                (
                    "Case ID",
                    case_data.get(
                        "case_id"
                    ),
                ),
                (
                    "Severity",
                    case_data.get(
                        "severity"
                    ),
                ),
                (
                    "Case status",
                    case_data.get(
                        "status"
                    ),
                ),
                (
                    "Summary review status",
                    analyst_review.get(
                        "review_status"
                    ),
                ),
                (
                    "Generated at",
                    format_datetime(
                        payload.get(
                            "generated_at"
                        )
                    ),
                ),
                (
                    "Report ID",
                    payload.get(
                        "report_id"
                    ),
                ),
            ],
            styles,
        )
    )

    story.append(
        Spacer(
            1,
            12 * mm,
        )
    )

    approval_required = (
        analyst_review.get(
            "analyst_approval_required",
            True,
        )
    )

    if approval_required:
        notice_text = (
            "This report contains automated or "
            "AI-assisted analysis. Analyst review "
            "and approval remain required before "
            "the report is treated as a final "
            "forensic conclusion."
        )

        notice_color = LIGHT_AMBER

    else:
        notice_text = (
            "This report includes the recorded "
            "analyst review state."
        )

        notice_color = LIGHT_GREEN

    notice = Table(
        [
            [
                paragraph(
                    notice_text,
                    styles["body"],
                )
            ]
        ],
        colWidths=[
            PAGE_WIDTH - 40 * mm
        ],
    )

    notice.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, -1),
                    notice_color,
                ),
                (
                    "BOX",
                    (0, 0),
                    (-1, -1),
                    0.8,
                    AMBER,
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    10,
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    10,
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    9,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    9,
                ),
            ]
        )
    )

    story.append(
        notice
    )

    story.append(
        PageBreak()
    )


def append_case_overview(
    story: list[Any],
    payload: dict[str, Any],
    styles: dict[str, ParagraphStyle],
) -> None:
    case_data = payload.get(
        "case",
        {},
    )

    story.append(
        paragraph(
            "1. Case Overview",
            styles["heading"],
        )
    )

    story.append(
        build_key_value_table(
            [
                (
                    "Case ID",
                    case_data.get(
                        "case_id"
                    ),
                ),
                (
                    "Title",
                    case_data.get(
                        "title"
                    ),
                ),
                (
                    "Severity",
                    case_data.get(
                        "severity"
                    ),
                ),
                (
                    "Status",
                    case_data.get(
                        "status"
                    ),
                ),
                (
                    "Created",
                    format_datetime(
                        case_data.get(
                            "created_at"
                        )
                    ),
                ),
                (
                    "Last updated",
                    format_datetime(
                        case_data.get(
                            "updated_at"
                        )
                    ),
                ),
            ],
            styles,
        )
    )

    story.append(
        Spacer(
            1,
            4 * mm,
        )
    )

    story.append(
        paragraph(
            case_data.get(
                "description"
            ),
            styles["body"],
            "No case description was recorded.",
        )
    )


def append_summary_sections(
    story: list[Any],
    payload: dict[str, Any],
    styles: dict[str, ParagraphStyle],
) -> None:
    summary = payload.get(
        "summary",
        {},
    )

    story.append(
        paragraph(
            "2. Investigation Summary",
            styles["heading"],
        )
    )

    story.append(
        paragraph(
            "Executive Summary",
            styles["subheading"],
        )
    )

    story.append(
        paragraph(
            summary.get(
                "executive_summary"
            ),
            styles["body"],
            "No executive summary was recorded.",
        )
    )

    story.append(
        paragraph(
            "Technical Narrative",
            styles["subheading"],
        )
    )

    story.append(
        paragraph(
            summary.get(
                "technical_narrative"
            ),
            styles["body"],
            "No technical narrative was recorded.",
        )
    )


def append_scope(
    story: list[Any],
    summary: dict[str, Any],
    styles: dict[str, ParagraphStyle],
) -> None:
    scope = summary.get(
        "incident_scope",
        {},
    )

    story.append(
        paragraph(
            "3. Incident Scope",
            styles["heading"],
        )
    )

    count_rows = [
        (
            "Timeline entries",
            scope.get(
                "total_timeline_entries",
                0,
            ),
        ),
        (
            "Log events",
            scope.get(
                "log_event_count",
                0,
            ),
        ),
        (
            "Security findings",
            scope.get(
                "security_finding_count",
                0,
            ),
        ),
        (
            "Event correlations",
            scope.get(
                "event_correlation_count",
                0,
            ),
        ),
        (
            "Evidence items",
            scope.get(
                "evidence_count",
                0,
            ),
        ),
        (
            "Critical records",
            scope.get(
                "critical_count",
                0,
            ),
        ),
        (
            "High-severity records",
            scope.get(
                "high_count",
                0,
            ),
        ),
        (
            "First activity",
            format_datetime(
                scope.get(
                    "first_activity_at"
                )
            ),
        ),
        (
            "Last activity",
            format_datetime(
                scope.get(
                    "last_activity_at"
                )
            ),
        ),
    ]

    story.append(
        build_key_value_table(
            count_rows,
            styles,
        )
    )

    entity_sections = [
        (
            "Affected Hosts",
            scope.get(
                "affected_hosts",
                [],
            ),
        ),
        (
            "Affected Users",
            scope.get(
                "affected_usernames",
                [],
            ),
        ),
        (
            "Observed Source IPs",
            scope.get(
                "observed_source_ips",
                [],
            ),
        ),
        (
            "Observed Destination IPs",
            scope.get(
                "observed_destination_ips",
                [],
            ),
        ),
        (
            "Observed Processes",
            scope.get(
                "observed_processes",
                [],
            ),
        ),
    ]

    for title, values in entity_sections:
        story.append(
            paragraph(
                title,
                styles["subheading"],
            )
        )

        append_bullet_items(
            story,
            values,
            styles,
            "None recorded.",
        )


def append_findings(
    story: list[Any],
    summary: dict[str, Any],
    styles: dict[str, ParagraphStyle],
) -> None:
    findings = summary.get(
        "technical_findings",
        [],
    )

    story.append(
        paragraph(
            "4. Technical Findings",
            styles["heading"],
        )
    )

    if not findings:
        story.append(
            paragraph(
                "No technical findings were recorded.",
                styles["body"],
            )
        )

        return

    for index, finding in enumerate(
        findings,
        start=1,
    ):
        if not isinstance(
            finding,
            dict,
        ):
            continue

        title = normalize_text(
            finding.get(
                "title"
            ),
            f"Finding {index}",
        )

        details = [
            (
                "Severity",
                finding.get(
                    "severity"
                ),
            ),
            (
                "Confidence",
                finding.get(
                    "confidence"
                ),
            ),
            (
                "Rule ID",
                finding.get(
                    "rule_id"
                ),
            ),
            (
                "Event code",
                finding.get(
                    "event_code"
                ),
            ),
            (
                "Event time",
                format_datetime(
                    finding.get(
                        "event_time"
                    )
                ),
            ),
            (
                "MITRE tactic",
                finding.get(
                    "mitre_tactic"
                ),
            ),
            (
                "MITRE technique",
                (
                    f"{normalize_text(finding.get('mitre_technique_id'))} "
                    f"{normalize_text(finding.get('mitre_technique_name'))}"
                ).strip(),
            ),
        ]

        finding_block = [
            paragraph(
                f"{index}. {title}",
                styles["subheading"],
            ),
            build_key_value_table(
                details,
                styles,
            ),
            Spacer(
                1,
                2 * mm,
            ),
            paragraph(
                finding.get(
                    "description"
                ),
                styles["body"],
                "No finding description was recorded.",
            ),
            Spacer(
                1,
                4 * mm,
            ),
        ]

        story.append(
            KeepTogether(
                finding_block
            )
        )


def append_mitre_coverage(
    story: list[Any],
    summary: dict[str, Any],
    styles: dict[str, ParagraphStyle],
) -> None:
    coverage = summary.get(
        "mitre_coverage",
        {},
    )

    techniques = coverage.get(
        "techniques",
        [],
    )

    story.append(
        paragraph(
            "5. MITRE ATT&CK Coverage",
            styles["heading"],
        )
    )

    story.append(
        build_key_value_table(
            [
                (
                    "Mapped tactics",
                    coverage.get(
                        "tactic_count",
                        0,
                    ),
                ),
                (
                    "Mapped techniques",
                    coverage.get(
                        "technique_count",
                        0,
                    ),
                ),
            ],
            styles,
        )
    )

    if not techniques:
        story.append(
            paragraph(
                "No MITRE ATT&CK techniques were mapped.",
                styles["body"],
            )
        )

        return

    rows = [
        [
            paragraph(
                "Technique",
                styles["small"],
            ),
            paragraph(
                "Tactic",
                styles["small"],
            ),
            paragraph(
                "Findings",
                styles["small"],
            ),
            paragraph(
                "Correlations",
                styles["small"],
            ),
        ]
    ]

    for technique in techniques:
        if not isinstance(
            technique,
            dict,
        ):
            continue

        technique_label = (
            f"{normalize_text(technique.get('technique_id'))} "
            f"{normalize_text(technique.get('technique_name'))}"
        ).strip()

        rows.append(
            [
                paragraph(
                    technique_label,
                    styles["small"],
                ),
                paragraph(
                    technique.get(
                        "tactic"
                    ),
                    styles["small"],
                ),
                paragraph(
                    technique.get(
                        "finding_count",
                        0,
                    ),
                    styles["small"],
                ),
                paragraph(
                    technique.get(
                        "correlation_count",
                        0,
                    ),
                    styles["small"],
                ),
            ]
        )

    table = LongTable(
        rows,
        colWidths=[
            65 * mm,
            48 * mm,
            24 * mm,
            28 * mm,
        ],
        repeatRows=1,
    )

    table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    DARK_BLUE,
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    WHITE,
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP",
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.35,
                    LIGHT_SLATE,
                ),
                (
                    "ROWBACKGROUNDS",
                    (0, 1),
                    (-1, -1),
                    [
                        colors.white,
                        colors.HexColor(
                            "#F8FAFC"
                        ),
                    ],
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    5,
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    5,
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    5,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    5,
                ),
            ]
        )
    )

    story.append(
        Spacer(
            1,
            4 * mm,
        )
    )

    story.append(
        table
    )


def append_evidence(
    story: list[Any],
    summary: dict[str, Any],
    styles: dict[str, ParagraphStyle],
) -> None:
    references = summary.get(
        "evidence_references",
        [],
    )

    story.append(
        paragraph(
            "6. Evidence References",
            styles["heading"],
        )
    )

    if not references:
        story.append(
            paragraph(
                "No evidence references were included.",
                styles["body"],
            )
        )

        return

    for index, reference in enumerate(
        references,
        start=1,
    ):
        if not isinstance(
            reference,
            dict,
        ):
            continue

        rows = [
            (
                "Evidence ID",
                reference.get(
                    "evidence_id"
                ),
            ),
            (
                "Filename",
                reference.get(
                    "original_filename"
                ),
            ),
            (
                "Evidence type",
                reference.get(
                    "evidence_type"
                ),
            ),
            (
                "Source",
                reference.get(
                    "source"
                ),
            ),
            (
                "Collected",
                format_datetime(
                    reference.get(
                        "collected_at"
                    )
                ),
            ),
            (
                "Size",
                (
                    f"{normalize_text(reference.get('size_bytes'), '0')} bytes"
                ),
            ),
            (
                "SHA-256",
                reference.get(
                    "sha256",
                    "Excluded from export",
                ),
            ),
        ]

        story.append(
            paragraph(
                (
                    f"{index}. "
                    f"{normalize_text(reference.get('original_filename'), 'Evidence item')}"
                ),
                styles["subheading"],
            )
        )

        story.append(
            build_key_value_table(
                rows,
                styles,
            )
        )

        story.append(
            Spacer(
                1,
                4 * mm,
            )
        )


def append_actions_and_notes(
    story: list[Any],
    summary: dict[str, Any],
    styles: dict[str, ParagraphStyle],
) -> None:
    actions = summary.get(
        "recommended_actions",
        [],
    )

    facts = summary.get(
        "verified_facts",
        [],
    )

    assumptions = summary.get(
        "assumptions",
        [],
    )

    limitations = summary.get(
        "limitations",
        [],
    )

    story.append(
        paragraph(
            "7. Recommended Actions",
            styles["heading"],
        )
    )

    if not actions:
        story.append(
            paragraph(
                "No recommended actions were included.",
                styles["body"],
            )
        )

    for index, action in enumerate(
        actions,
        start=1,
    ):
        if isinstance(
            action,
            dict,
        ):
            action_text = " ".join(
                part
                for part in [
                    normalize_text(
                        action.get(
                            "title"
                        )
                    ),
                    normalize_text(
                        action.get(
                            "description"
                        )
                    ),
                    normalize_text(
                        action.get(
                            "rationale"
                        )
                    ),
                ]
                if part
            )

        else:
            action_text = normalize_text(
                action
            )

        story.append(
            Paragraph(
                safe_text(
                    (
                        f"{index}. "
                        f"{action_text}"
                    )
                ),
                styles["body"],
            )
        )

    story.append(
        paragraph(
            "8. Verified Facts",
            styles["heading"],
        )
    )

    if not facts:
        story.append(
            paragraph(
                "No verified facts were included.",
                styles["body"],
            )
        )

    for fact in facts:
        if isinstance(
            fact,
            dict,
        ):
            fact_text = fact.get(
                "statement"
            )

        else:
            fact_text = fact

        story.append(
            Paragraph(
                safe_text(
                    fact_text
                ),
                styles["body"],
                bulletText="•",
            )
        )

    story.append(
        paragraph(
            "9. Assumptions",
            styles["heading"],
        )
    )

    if not assumptions:
        story.append(
            paragraph(
                "No assumptions were included.",
                styles["body"],
            )
        )

    for assumption in assumptions:
        if isinstance(
            assumption,
            dict,
        ):
            assumption_text = " ".join(
                part
                for part in [
                    normalize_text(
                        assumption.get(
                            "statement"
                        )
                    ),
                    normalize_text(
                        assumption.get(
                            "reason"
                        )
                    ),
                ]
                if part
            )

        else:
            assumption_text = (
                assumption
            )

        story.append(
            Paragraph(
                safe_text(
                    assumption_text
                ),
                styles["body"],
                bulletText="•",
            )
        )

    story.append(
        paragraph(
            "10. Limitations",
            styles["heading"],
        )
    )

    append_bullet_items(
        story,
        limitations,
        styles,
        "No limitations were included.",
    )


def append_traceability(
    story: list[Any],
    payload: dict[str, Any],
    styles: dict[str, ParagraphStyle],
) -> None:
    traceability = payload.get(
        "traceability"
    )

    story.append(
        paragraph(
            "11. Claim-Level Evidence Traceability",
            styles["heading"],
        )
    )

    if not isinstance(
        traceability,
        dict,
    ):
        story.append(
            paragraph(
                "Traceability was excluded from this export.",
                styles["body"],
            )
        )

        return

    story.append(
        build_key_value_table(
            [
                (
                    "Total claims",
                    traceability.get(
                        "total_claim_count",
                        0,
                    ),
                ),
                (
                    "Supported claims",
                    traceability.get(
                        "supported_claim_count",
                        0,
                    ),
                ),
                (
                    "Unsupported claims",
                    traceability.get(
                        "unsupported_claim_count",
                        0,
                    ),
                ),
                (
                    "Direct support",
                    traceability.get(
                        "direct_support_count",
                        0,
                    ),
                ),
                (
                    "Derived support",
                    traceability.get(
                        "derived_support_count",
                        0,
                    ),
                ),
                (
                    "Contextual support",
                    traceability.get(
                        "contextual_support_count",
                        0,
                    ),
                ),
                (
                    "Citation count",
                    traceability.get(
                        "citation_count",
                        0,
                    ),
                ),
                (
                    "Traceability hash",
                    traceability.get(
                        "report_sha256"
                    ),
                ),
            ],
            styles,
        )
    )

    claims = traceability.get(
        "claims",
        [],
    )

    for index, claim in enumerate(
        claims,
        start=1,
    ):
        if not isinstance(
            claim,
            dict,
        ):
            continue

        supported = bool(
            claim.get(
                "supported"
            )
        )

        claim_style = (
            styles["supported"]
            if supported
            else styles["unsupported"]
        )

        claim_block = [
            paragraph(
                (
                    f"Claim {index}: "
                    f"{normalize_text(claim.get('section'), 'Unclassified')}"
                ),
                styles["subheading"],
            ),
            paragraph(
                claim.get(
                    "text"
                ),
                claim_style,
            ),
            build_key_value_table(
                [
                    (
                        "Support level",
                        claim.get(
                            "support_level"
                        ),
                    ),
                    (
                        "Supported",
                        supported,
                    ),
                    (
                        "Unsupported reason",
                        claim.get(
                            "unsupported_reason",
                            "",
                        ),
                    ),
                ],
                styles,
            ),
        ]

        story.append(
            KeepTogether(
                claim_block
            )
        )

        citations = claim.get(
            "citations",
            [],
        )

        for citation_index, citation in enumerate(
            citations,
            start=1,
        ):
            if not isinstance(
                citation,
                dict,
            ):
                continue

            story.append(
                paragraph(
                    f"Citation {citation_index}",
                    styles["small"],
                )
            )

            story.append(
                build_key_value_table(
                    [
                        (
                            "Source type",
                            citation.get(
                                "source_type"
                            ),
                        ),
                        (
                            "Label",
                            citation.get(
                                "label"
                            ),
                        ),
                        (
                            "Relationship",
                            citation.get(
                                "relationship"
                            ),
                        ),
                        (
                            "Source ID",
                            citation.get(
                                "source_id"
                            ),
                        ),
                        (
                            "Evidence ID",
                            citation.get(
                                "evidence_id"
                            ),
                        ),
                        (
                            "Event time",
                            format_datetime(
                                citation.get(
                                    "event_time"
                                )
                            ),
                        ),
                        (
                            "Evidence hash",
                            citation.get(
                                "integrity_sha256",
                                "Excluded from export",
                            ),
                        ),
                    ],
                    styles,
                    label_width=38 * mm,
                )
            )

            story.append(
                Spacer(
                    1,
                    2 * mm,
                )
            )


def append_integrity_and_audit(
    story: list[Any],
    payload: dict[str, Any],
    styles: dict[str, ParagraphStyle],
) -> None:
    integrity = payload.get(
        "integrity"
    )

    audit = payload.get(
        "generation_audit",
        {},
    )

    review = payload.get(
        "analyst_review",
        {},
    )

    story.append(
        paragraph(
            "12. Integrity Verification",
            styles["heading"],
        )
    )

    if isinstance(
        integrity,
        dict,
    ):
        integrity_verified = bool(
            integrity.get(
                "integrity_verified"
            )
        )

        integrity_table = build_key_value_table(
            [
                (
                    "Integrity verified",
                    integrity_verified,
                ),
                (
                    "Source hash match",
                    integrity.get(
                        "source_hash_matches"
                    ),
                ),
                (
                    "Report hash match",
                    integrity.get(
                        "report_hash_matches"
                    ),
                ),
                (
                    "Stored report hash",
                    integrity.get(
                        "stored_report_sha256"
                    ),
                ),
                (
                    "Reconstructed report hash",
                    integrity.get(
                        "reconstructed_report_sha256"
                    ),
                ),
                (
                    "Verified at",
                    format_datetime(
                        integrity.get(
                            "verified_at"
                        )
                    ),
                ),
            ],
            styles,
        )

        story.append(
            integrity_table
        )

    else:
        story.append(
            paragraph(
                "Integrity verification was excluded from this export.",
                styles["body"],
            )
        )

    story.append(
        paragraph(
            "13. Analyst Review",
            styles["heading"],
        )
    )

    story.append(
        build_key_value_table(
            [
                (
                    "Review status",
                    review.get(
                        "review_status"
                    ),
                ),
                (
                    "Reviewed by",
                    review.get(
                        "reviewed_by_user_id"
                    ),
                ),
                (
                    "Reviewed at",
                    format_datetime(
                        review.get(
                            "reviewed_at"
                        )
                    ),
                ),
                (
                    "Approval required",
                    review.get(
                        "analyst_approval_required"
                    ),
                ),
                (
                    "Review notes",
                    review.get(
                        "review_notes"
                    ),
                ),
            ],
            styles,
        )
    )

    story.append(
        paragraph(
            "14. Generation Audit",
            styles["heading"],
        )
    )

    story.append(
        build_key_value_table(
            [
                (
                    "Generation source",
                    audit.get(
                        "generation_source"
                    ),
                ),
                (
                    "Provider",
                    audit.get(
                        "provider_name"
                    ),
                ),
                (
                    "Model",
                    audit.get(
                        "model_name"
                    ),
                ),
                (
                    "Prompt template version",
                    audit.get(
                        "prompt_template_version"
                    ),
                ),
                (
                    "Generation started",
                    format_datetime(
                        audit.get(
                            "generation_started_at"
                        )
                    ),
                ),
                (
                    "Generation completed",
                    format_datetime(
                        audit.get(
                            "generation_completed_at"
                        )
                    ),
                ),
                (
                    "Source snapshot hash",
                    audit.get(
                        "source_snapshot_sha256"
                    ),
                ),
                (
                    "Summary output hash",
                    audit.get(
                        "summary_output_sha256"
                    ),
                ),
            ],
            styles,
        )
    )

    story.append(
        paragraph(
            "15. Report Integrity",
            styles["heading"],
        )
    )

    story.append(
        build_key_value_table(
            [
                (
                    "Report ID",
                    payload.get(
                        "report_id"
                    ),
                ),
                (
                    "Report schema",
                    payload.get(
                        "schema_version"
                    ),
                ),
                (
                    "Report SHA-256",
                    payload.get(
                        "report_sha256"
                    ),
                ),
                (
                    "Generated by",
                    payload.get(
                        "generated_by_user_id"
                    ),
                ),
                (
                    "Generated at",
                    format_datetime(
                        payload.get(
                            "generated_at"
                        )
                    ),
                ),
            ],
            styles,
        )
    )


def render_investigation_report_pdf(
    payload: dict[str, Any],
) -> bytes:
    buffer = BytesIO()

    styles = build_styles()

    case_title = normalize_text(
        payload.get(
            "case",
            {},
        ).get(
            "title"
        ),
        "Investigation Report",
    )

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=20 * mm,
        leftMargin=20 * mm,
        topMargin=18 * mm,
        bottomMargin=22 * mm,
        title=case_title,
        author="DFIR Assistant",
        subject=(
            "Evidence-linked digital "
            "forensics investigation report"
        ),
    )

    story: list[Any] = []

    append_title_page(
        story,
        payload,
        styles,
    )

    append_case_overview(
        story,
        payload,
        styles,
    )

    append_summary_sections(
        story,
        payload,
        styles,
    )

    summary = payload.get(
        "summary",
        {},
    )

    append_scope(
        story,
        summary,
        styles,
    )

    append_findings(
        story,
        summary,
        styles,
    )

    append_mitre_coverage(
        story,
        summary,
        styles,
    )

    append_evidence(
        story,
        summary,
        styles,
    )

    append_actions_and_notes(
        story,
        summary,
        styles,
    )

    append_traceability(
        story,
        payload,
        styles,
    )

    append_integrity_and_audit(
        story,
        payload,
        styles,
    )

    document.build(
        story,
        onFirstPage=draw_page_footer,
        onLaterPages=draw_page_footer,
    )

    return buffer.getvalue()


def build_pdf_report_filename(
    case_title: str,
    version_number: Any,
    report_id: uuid.UUID,
) -> str:
    safe_case_title = (
        safe_filename_component(
            case_title
        )
    )

    safe_version = normalize_text(
        version_number,
        "1",
    )

    report_identifier = str(
        report_id
    )[:8]

    return (
        f"{safe_case_title}-"
        f"summary-v{safe_version}-"
        f"{report_identifier}.pdf"
    )


def export_investigation_report_pdf(
    db: Session,
    request: InvestigationReportGenerationRequest,
    generated_by_user_id:
        uuid.UUID | None,
    generated_at:
        datetime | None = None,
) -> InvestigationReportArtifact:
    if (
        request.format
        != InvestigationReportFormat.pdf
    ):
        raise InvestigationReportFormatError(
            "The PDF exporter only accepts "
            "the PDF report format."
        )

    report_document = (
        build_investigation_report_document(
            db=db,
            request=request,
            generated_by_user_id=(
                generated_by_user_id
            ),
            generated_at=generated_at,
        )
    )

    payload = build_report_export_payload(
        document=report_document,
        request=request,
    )

    content = (
        render_investigation_report_pdf(
            payload
        )
    )

    result = InvestigationReportExportResult(
        report_id=(
            report_document.report_id
        ),
        case_id=(
            report_document.case.case_id
        ),
        summary_id=(
            report_document.summary.id
        ),
        format=(
            InvestigationReportFormat.pdf
        ),
        status=(
            InvestigationReportStatus
            .completed
        ),
        filename=build_pdf_report_filename(
            case_title=(
                report_document.case.title
            ),
            version_number=(
                report_document
                .summary
                .version_number
            ),
            report_id=(
                report_document.report_id
            ),
        ),
        media_type="application/pdf",
        size_bytes=len(content),
        document_sha256=(
            calculate_bytes_sha256(
                content
            )
        ),
        generated_at=(
            report_document.generated_at
        ),
    )

    return InvestigationReportArtifact(
        content=content,
        result=result,
    )