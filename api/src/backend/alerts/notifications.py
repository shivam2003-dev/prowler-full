"""Email delivery for alerts."""

from urllib.parse import urlencode

from django.conf import settings
from django.core.mail import EmailMultiAlternatives, get_connection
from django.utils.html import escape

SEVERITY_LABELS = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "informational": "Informational",
}


def _ui_url(path: str, params: dict | None = None) -> str:
    url = f"{settings.ALERTS_UI_BASE_URL.rstrip('/')}{path}"
    if params:
        url = f"{url}?{urlencode(params, doseq=True)}"
    return url


def findings_url(summary: dict) -> str:
    hint = summary.get("deep_link_filter_hint") or {}
    params = {key: ",".join(values) for key, values in hint.items()}
    params.setdefault("filter[status__in]", "FAIL")
    params.setdefault("filter[muted]", "false")
    return _ui_url("/findings", params)


def _alert_bodies(rule, summary: dict, unsubscribe_url: str) -> tuple[str, str]:
    total = summary.get("finding_count_total", 0)
    counts = summary.get("counts_by_severity") or {}
    top_findings = summary.get("top_findings") or []
    link = findings_url(summary)

    lines = [f'Prowler alert "{rule.name}" fired.', ""]
    if rule.description:
        lines += [rule.description, ""]
    lines.append(f"Matching failing findings: {total}")
    lines += [
        f"  {SEVERITY_LABELS.get(severity, severity)}: {count}"
        for severity, count in counts.items()
    ]
    if top_findings:
        lines += ["", "Top checks:"] + [f"  - {item}" for item in top_findings]
    lines += ["", f"Open in Prowler: {link}", "", f"Unsubscribe: {unsubscribe_url}"]
    text_body = "\n".join(lines)

    severity_rows = "".join(
        f"<tr><td style='padding:2px 12px 2px 0'>"
        f"{escape(SEVERITY_LABELS.get(severity, severity))}</td>"
        f"<td style='padding:2px 0'><b>{count}</b></td></tr>"
        for severity, count in counts.items()
    )
    top_items = "".join(f"<li>{escape(item)}</li>" for item in top_findings)
    description = (
        f"<p style='color:#555'>{escape(rule.description)}</p>"
        if rule.description
        else ""
    )
    html_body = (
        "<div style='font-family:Arial,Helvetica,sans-serif;font-size:14px;"
        "color:#111;max-width:560px'>"
        f"<h2 style='margin:0 0 8px'>Prowler alert: {escape(rule.name)}</h2>"
        f"{description}"
        f"<p><b>{total}</b> matching failing findings.</p>"
        f"<table style='border-collapse:collapse'>{severity_rows}</table>"
        + (
            f"<p style='margin-bottom:4px'>Top checks</p><ul>{top_items}</ul>"
            if top_items
            else ""
        )
        + f"<p><a href='{escape(link)}'>Open in Prowler</a></p>"
        "<hr style='border:none;border-top:1px solid #ddd'>"
        f"<p style='font-size:12px;color:#777'>You receive this because your address "
        f"is a recipient of this alert. <a href='{escape(unsubscribe_url)}'>"
        "Unsubscribe</a>.</p></div>"
    )
    return text_body, html_body


def send_alert_email(rule, recipients, summary: dict) -> int:
    """Send one message per recipient so each carries its own unsubscribe link."""
    total = summary.get("finding_count_total", 0)
    subject = f"[Prowler] {rule.name}: {total} failing findings"
    messages = []
    for recipient in recipients:
        unsubscribe_url = _ui_url("/alerts/unsubscribe", {"token": recipient.token})
        text_body, html_body = _alert_bodies(rule, summary, unsubscribe_url)
        message = EmailMultiAlternatives(
            subject=subject,
            body=text_body,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[recipient.email],
            headers={"List-Unsubscribe": f"<{unsubscribe_url}>"},
        )
        message.attach_alternative(html_body, "text/html")
        messages.append(message)

    with get_connection() as connection:
        return connection.send_messages(messages) or 0


def send_confirmation_email(recipient) -> None:
    confirm_url = _ui_url("/alerts/confirm", {"token": recipient.token})
    message = EmailMultiAlternatives(
        subject="[Prowler] Confirm your email to receive alerts",
        body=(
            "You were added as a recipient of Prowler alerts.\n\n"
            f"Confirm your email address: {confirm_url}\n\n"
            "If you did not expect this, ignore this message."
        ),
        from_email=settings.DEFAULT_FROM_EMAIL,
        to=[recipient.email],
    )
    message.send(fail_silently=True)
