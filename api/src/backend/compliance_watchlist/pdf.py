"""PDF reports of cross-provider and cross-account compliance views."""

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path

from config.django.base import DJANGO_TMP_OUTPUT_DIRECTORY
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    LongTable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

TASK_NAME = "compliance-aggregated-pdf"
CROSS_PROVIDER = "cross_provider"
CROSS_ACCOUNT = "cross_account"
STATUS_COLOR = {
    "PASS": colors.HexColor("#1f9d55"),
    "FAIL": colors.HexColor("#d64545"),
    "MANUAL": colors.HexColor("#8a8a8a"),
}
MAX_CELL = 300


def request_key(kind: str, params: dict) -> str:
    """Identifies a report by what it covers, to find the latest one again."""
    return hashlib.sha256(
        json.dumps({"kind": kind, **params}, sort_keys=True).encode()
    ).hexdigest()


def output_path(tenant_id: str, task_id: str) -> Path:
    return (
        Path(DJANGO_TMP_OUTPUT_DIRECTORY)
        / str(tenant_id)
        / "aggregated-compliance"
        / f"{task_id}.pdf"
    )


def safe_filename(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-.")
    return (cleaned or "compliance-report")[:120] + ".pdf"


def _cell(text, style):
    text = str(text or "")
    if len(text) > MAX_CELL:
        text = text[: MAX_CELL - 1] + "…"
    return Paragraph(text.replace("&", "&amp;").replace("<", "&lt;"), style)


def _status_table(header, rows, widths, status_columns, style):
    data = [header] + rows
    table = LongTable(data, colWidths=widths, repeatRows=1)
    commands = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1b1f24")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#c8ccd0")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        (
            "ROWBACKGROUNDS",
            (0, 1),
            (-1, -1),
            [colors.white, colors.HexColor("#f5f6f7")],
        ),
    ]
    for row_index, row in enumerate(rows, start=1):
        for column in status_columns:
            value = row[column] if isinstance(row[column], str) else ""
            if value in STATUS_COLOR:
                commands += [
                    (
                        "TEXTCOLOR",
                        (column, row_index),
                        (column, row_index),
                        STATUS_COLOR[value],
                    ),
                    (
                        "FONTNAME",
                        (column, row_index),
                        (column, row_index),
                        "Helvetica-Bold",
                    ),
                ]
    table.setStyle(TableStyle(commands))
    return table


def render(kind: str, payload: dict, path: Path, title: str) -> None:
    """Write the report of one cross-provider or cross-account payload."""
    path.parent.mkdir(parents=True, exist_ok=True)
    styles = getSampleStyleSheet()
    small = styles["BodyText"].clone("small", fontSize=8, leading=10)
    doc = SimpleDocTemplate(
        str(path),
        pagesize=landscape(A4),
        leftMargin=12 * mm,
        rightMargin=12 * mm,
        topMargin=12 * mm,
        bottomMargin=12 * mm,
        title=title,
        author="Prowler",
    )
    story = [
        Paragraph(title, styles["Title"]),
        Paragraph(
            f"{payload['name']} {payload.get('version') or ''} &middot; "
            f"generated {datetime.now(tz=UTC):%Y-%m-%d %H:%M} UTC",
            styles["Normal"],
        ),
        Spacer(1, 4 * mm),
    ]
    if payload.get("description"):
        story += [_cell(payload["description"], small), Spacer(1, 4 * mm)]

    total = payload["total_requirements"] or 1
    summary = Table(
        [
            ["Requirements", "Passed", "Failed", "Manual", "Pass rate"],
            [
                payload["total_requirements"],
                payload["requirements_passed"],
                payload["requirements_failed"],
                payload["requirements_manual"],
                f"{round(100 * payload['requirements_passed'] / total, 1)}%",
            ],
        ]
    )
    summary.setStyle(
        TableStyle(
            [
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#c8ccd0")),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ]
        )
    )
    story += [summary, Spacer(1, 5 * mm)]

    if kind == CROSS_PROVIDER:
        columns = payload["providers"]
        labels = [c.upper() for c in columns]
        story.append(
            Paragraph(
                f"Providers scanned: {', '.join(labels) or 'none'}", styles["Normal"]
            )
        )
        get_status = lambda req, col: req["providers"].get(col, "")  # noqa: E731
    else:
        accounts = payload["accounts"]
        columns = [a["id"] for a in accounts]
        labels = [a["alias"] or a["uid"] for a in accounts]
        story.append(
            Paragraph(
                f"{payload['provider_type'].upper()} accounts: {', '.join(labels) or 'none'}",
                styles["Normal"],
            )
        )
        get_status = lambda req, col: req["accounts"].get(col, "")  # noqa: E731
    story.append(Spacer(1, 3 * mm))

    usable = landscape(A4)[0] - 24 * mm
    status_width = 18 * mm
    shown = columns[:8]  # wider tables stop being readable on a page
    fixed = 22 * mm + status_width * (1 + len(shown))
    name_width = max(usable - fixed, 60 * mm)
    on_dark = small.clone("on_dark", textColor=colors.white, fontName="Helvetica-Bold")
    header = ["Requirement", "Name", "Status"] + [
        _cell(label, on_dark) for label in labels[:8]
    ]
    rows = [
        [
            _cell(req["id"], small),
            # Per-provider frameworks name requirements by id only.
            _cell(
                req["name"]
                if req["name"] and req["name"] != req["id"]
                else req.get("description") or req["id"],
                small,
            ),
            req["status"],
            *[get_status(req, col) or "-" for col in shown],
        ]
        for req in payload["requirements"]
    ]
    story.append(
        _status_table(
            header,
            rows,
            [22 * mm, name_width, status_width] + [status_width] * len(shown),
            list(range(2, 3 + len(shown))),
            small,
        )
    )
    if len(columns) > len(shown):
        story += [
            Spacer(1, 2 * mm),
            Paragraph(
                f"{len(columns) - len(shown)} more columns are left out of this table; "
                "the overall status still includes them.",
                small,
            ),
        ]
    doc.build(story)
