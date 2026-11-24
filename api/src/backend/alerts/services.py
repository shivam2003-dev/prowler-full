"""Alert recipients and rule evaluation, shared by the API and Celery tasks."""

import secrets
from datetime import timedelta

from alerts import dsl, notifications
from alerts.evaluation import (
    alertable_findings,
    evaluate_condition,
    latest_completed_scan_ids,
)
from api.models import AlertEvent, AlertRecipient, AlertRule, AlertRuleRecipient
from celery.utils.log import get_task_logger
from django.conf import settings
from django.utils import timezone

logger = get_task_logger(__name__)

CONFIRMATION_TTL = timedelta(days=7)


def normalize_email(email: str) -> str:
    return email.strip().lower()


def _new_token() -> str:
    return secrets.token_urlsafe(32)


def _start_confirmation(recipient: AlertRecipient) -> None:
    now = timezone.now()
    recipient.status = AlertRecipient.StatusChoices.PENDING
    recipient.confirmation_sent_at = now
    recipient.confirmation_expires_at = now + CONFIRMATION_TTL
    recipient.save(
        update_fields=[
            "status",
            "confirmation_sent_at",
            "confirmation_expires_at",
            "updated_at",
        ]
    )
    notifications.send_confirmation_email(recipient)


def get_or_create_recipient(tenant_id: str, email: str) -> AlertRecipient:
    """Return the tenant's recipient for `email`, creating it if needed.

    Self-hosted deployments own their mail server, so a new address is trusted
    and confirmed at once unless ALERTS_RECIPIENT_CONFIRMATION_REQUIRED asks
    for a double opt-in. An address that unsubscribed stays unsubscribed.
    """
    email = normalize_email(email)
    recipient, created = AlertRecipient.objects.get_or_create(
        tenant_id=tenant_id,
        email=email,
        defaults={"token": _new_token()},
    )
    if not created:
        return recipient

    if settings.ALERTS_RECIPIENT_CONFIRMATION_REQUIRED:
        _start_confirmation(recipient)
    else:
        recipient.status = AlertRecipient.StatusChoices.CONFIRMED
        recipient.confirmed_at = timezone.now()
        recipient.save(update_fields=["status", "confirmed_at", "updated_at"])
    return recipient


def set_rule_recipients(rule: AlertRule, emails: list[str]) -> None:
    """Replace the rule's recipients with exactly `emails`."""
    tenant_id = str(rule.tenant_id)
    wanted = {
        recipient.id: recipient
        for recipient in (
            get_or_create_recipient(tenant_id, email)
            for email in dict.fromkeys(normalize_email(email) for email in emails)
        )
    }
    links = AlertRuleRecipient.objects.filter(tenant_id=tenant_id, rule=rule)
    current_ids = set(links.values_list("recipient_id", flat=True))

    links.exclude(recipient_id__in=wanted.keys()).delete()
    AlertRuleRecipient.objects.bulk_create(
        AlertRuleRecipient(tenant_id=tenant_id, rule=rule, recipient=recipient)
        for recipient_id, recipient in wanted.items()
        if recipient_id not in current_ids
    )


def confirm_recipient(recipient: AlertRecipient) -> tuple[str, str]:
    """Apply a confirmation link. Returns (state, message)."""
    if recipient.status == AlertRecipient.StatusChoices.CONFIRMED:
        return "already_confirmed", "This email address is already confirmed."
    if recipient.status == AlertRecipient.StatusChoices.UNSUBSCRIBED:
        return (
            "unsubscribed",
            "This email address unsubscribed from Prowler alerts.",
        )
    expires_at = recipient.confirmation_expires_at
    if expires_at is not None and expires_at < timezone.now():
        return "expired", "This confirmation link has expired."

    recipient.status = AlertRecipient.StatusChoices.CONFIRMED
    recipient.confirmed_at = timezone.now()
    recipient.save(update_fields=["status", "confirmed_at", "updated_at"])
    return "confirmed", "Your email address is confirmed. You will receive alerts."


def unsubscribe_recipient(recipient: AlertRecipient) -> tuple[str, str]:
    """Apply an unsubscribe link. Returns (state, message)."""
    if recipient.status == AlertRecipient.StatusChoices.UNSUBSCRIBED:
        return "already_unsubscribed", "This email address is already unsubscribed."

    recipient.status = AlertRecipient.StatusChoices.UNSUBSCRIBED
    recipient.unsubscribed_at = timezone.now()
    recipient.save(update_fields=["status", "unsubscribed_at", "updated_at"])
    return "unsubscribed", "You will no longer receive Prowler alerts at this address."


def preview_condition(tenant_id: str, condition: dict, providers=None) -> dict:
    """Evaluate a condition over the latest scans without notifying anyone."""
    try:
        scan_ids = latest_completed_scan_ids(tenant_id, providers)
        result = evaluate_condition(condition, alertable_findings(tenant_id, scan_ids))
    except Exception as error:  # noqa: BLE001 - reported to the caller, not raised
        logger.exception("Alert preview failed for tenant %s", tenant_id)
        return {
            "summary": {},
            "sample_finding_ids": [],
            "evaluation_failed": True,
            "last_error": str(error) or error.__class__.__name__,
            "summary_fallback": False,
            "duration_ms": 0,
        }
    return {
        "summary": {**result.summary, "triggered": result.triggered},
        "sample_finding_ids": result.sample_finding_ids,
        "evaluation_failed": False,
        "last_error": None,
        "summary_fallback": False,
        "duration_ms": result.duration_ms,
    }


def _fire(rule: AlertRule, trigger: str, summary: dict, scan_id=None) -> AlertEvent:
    recipients = list(
        rule.recipients.filter(status=AlertRecipient.StatusChoices.CONFIRMED)
    )
    status = AlertEvent.StatusChoices.SENT
    error = ""
    if not recipients:
        status = AlertEvent.StatusChoices.NO_RECIPIENTS
    else:
        try:
            notifications.send_alert_email(rule, recipients, summary)
        except Exception as send_error:  # noqa: BLE001 - recorded on the event
            logger.exception("Alert %s delivery failed", rule.id)
            status = AlertEvent.StatusChoices.FAILED
            error = str(send_error) or send_error.__class__.__name__

    rule.last_triggered_at = timezone.now()
    rule.save(update_fields=["last_triggered_at"])
    return AlertEvent.objects.create(
        tenant_id=rule.tenant_id,
        rule=rule,
        scan_id=scan_id,
        trigger=trigger,
        status=status,
        summary=summary,
        recipient_count=len(recipients),
        error=error,
    )


def evaluate_rules(tenant_id: str, trigger: str, scan_ids, scan_id=None) -> dict:
    """Evaluate every enabled rule of `trigger` over `scan_ids` and notify.

    Must run inside the tenant's RLS transaction. One broken rule is logged
    and skipped so it cannot silence the others.
    """
    rules = AlertRule.objects.filter(
        tenant_id=tenant_id,
        enabled=True,
        trigger__in=[trigger, AlertRule.TriggerChoices.BOTH],
    )
    findings = alertable_findings(tenant_id, scan_ids)
    evaluated = fired = failed = 0

    for rule in rules:
        evaluated += 1
        try:
            condition = dsl.validate_condition(rule.condition)
            result = evaluate_condition(condition, findings)
        except Exception:  # noqa: BLE001 - isolate one rule from the rest
            logger.exception("Alert rule %s could not be evaluated", rule.id)
            failed += 1
            continue

        rule.last_evaluated_at = timezone.now()
        rule.save(update_fields=["last_evaluated_at"])
        if result.triggered:
            _fire(rule, trigger, result.summary, scan_id=scan_id)
            fired += 1

    return {"evaluated": evaluated, "fired": fired, "failed": failed}
