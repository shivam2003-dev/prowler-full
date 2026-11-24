"""Read CloudTrail events for a provider and turn them into detections and actions."""

import json
from datetime import UTC, datetime, timedelta

from api.models import (
    AlertRecipient,
    Provider,
    RealtimeAction,
    RealtimeCredential,
    RealtimeDetection,
    RealtimeEvent,
    RealtimeFeed,
    RealtimePolicy,
)
from api.utils import initialize_prowler_provider
from celery.utils.log import get_task_logger
from django.conf import settings
from django.core.mail import send_mail
from realtime import remediations, rules

logger = get_task_logger(__name__)

LOOKUP_WINDOW = timedelta(hours=1)
LOOKUP_MAX_PAGES = 5
SQS_MAX_BATCHES = 10
GLOBAL_REGION = "us-east-1"

Status = RealtimeDetection.StatusChoices
ActionStatus = RealtimeAction.StatusChoices
ActionKind = RealtimeAction.KindChoices


def _parse_time(value) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def record_from_cloudtrail(raw: dict) -> dict:
    """Normalize one CloudTrail record (the JSON inside an event) for storage."""
    identity = raw.get("userIdentity") or {}
    return {
        "event_id": raw.get("eventID", ""),
        "event_time": _parse_time(raw.get("eventTime")),
        "region": raw.get("awsRegion", ""),
        "event_source": raw.get("eventSource", ""),
        "event_name": raw.get("eventName", ""),
        "user_type": identity.get("type", ""),
        "user_arn": identity.get("arn", "") or identity.get("principalId", ""),
        "source_ip": raw.get("sourceIPAddress", ""),
        "error_code": raw.get("errorCode", "") or "",
        "read_only": bool(raw.get("readOnly", False)),
        "request_parameters": raw.get("requestParameters"),
        "additional_data": raw.get("additionalEventData"),
    }


def _regions(feed: RealtimeFeed, policy: RealtimePolicy | None) -> list[str]:
    regions = list(policy.allow_regions) if policy and policy.allow_regions else []
    regions = regions or [feed.region or GLOBAL_REGION]
    # Global services (IAM, S3 account settings, sign-in) report to us-east-1.
    if GLOBAL_REGION not in regions:
        regions.append(GLOBAL_REGION)
    return regions


def read_lookup_events(session, regions, since: datetime) -> list[dict]:
    """CloudTrail LookupEvents (read-only API) for the watched write events."""
    records = []
    for region in regions:
        client = session.client("cloudtrail", region_name=region)
        token = None
        for _ in range(LOOKUP_MAX_PAGES):
            kwargs = {
                "LookupAttributes": [
                    {"AttributeKey": "ReadOnly", "AttributeValue": "false"}
                ],
                "StartTime": since,
                "MaxResults": 50,
            }
            if token:
                kwargs["NextToken"] = token
            page = client.lookup_events(**kwargs)
            for event in page.get("Events", []):
                if event.get("EventName") not in rules.WATCHED_EVENTS:
                    continue
                try:
                    records.append(json.loads(event.get("CloudTrailEvent") or "{}"))
                except ValueError:
                    continue
            token = page.get("NextToken")
            if not token:
                break
    return records


def read_sqs_events(session, queue_url: str, region: str) -> list[dict]:
    """EventBridge -> SQS feed. Deletes only the messages it has read."""
    sqs = session.client("sqs", region_name=region)
    records = []
    for _ in range(SQS_MAX_BATCHES):
        messages = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=1
        ).get("Messages", [])
        if not messages:
            break
        for message in messages:
            try:
                body = json.loads(message.get("Body") or "{}")
                records.append(body.get("detail") or {})
            except ValueError:
                pass
        sqs.delete_message_batch(
            QueueUrl=queue_url,
            Entries=[
                {"Id": str(index), "ReceiptHandle": message["ReceiptHandle"]}
                for index, message in enumerate(messages)
            ],
        )
    return records


def _decide_action(policy, verdict, detection, credential) -> dict | None:
    """What Realtime does about a violation, as RealtimeAction fields."""
    if (
        policy is None
        or not policy.enabled
        or policy.mode == RealtimePolicy.ModeChoices.MONITOR
    ):
        return None
    if any(check in policy.deny_checks for check in verdict.check_ids):
        return None
    base = {
        "check_id": verdict.check_ids[0] if verdict.check_ids else "",
        "resource_uid": verdict.resource,
        "region": detection.event.region,
        "severity": verdict.severity,
    }
    remediation = remediations.CATALOG.get(verdict.remediation_id)

    if policy.mode == RealtimePolicy.ModeChoices.AUTO and remediation:
        can_write = (
            not policy.dry_run
            and settings.REALTIME_REMEDIATION_ENABLED
            and credential is not None
            and bool(credential.role_arn)
        )
        return {
            **base,
            "kind": ActionKind.SELF_FIX,
            "status": ActionStatus.QUEUED if can_write else ActionStatus.DRY_RUN,
            "remediation_id": remediation.id,
            "revertible": remediation.revertible,
            "summary": (
                remediation.effect
                if can_write
                else f"Would apply: {remediation.effect}"
                + (
                    ""
                    if policy.dry_run
                    else " Writes to AWS are turned off on this server."
                    if not settings.REALTIME_REMEDIATION_ENABLED
                    else " Add the remediation role first."
                )
            ),
        }
    if policy.mode == RealtimePolicy.ModeChoices.PR:
        return {
            **base,
            "kind": ActionKind.CODE,
            "status": ActionStatus.PR_BLOCKED,
            "summary": (
                "Opening pull requests needs an IaC repository and a GitHub token."
                if not policy.iac_repo
                else "Pull requests are proposed here for review; nothing is pushed "
                "to GitHub from this server."
            ),
        }
    return {
        **base,
        "kind": ActionKind.PROPOSAL,
        "status": ActionStatus.QUEUED,
        "summary": f"{verdict.title}: needs a person to review.",
    }


def _notify(policy: RealtimePolicy, detection: RealtimeDetection) -> None:
    notifications = policy.notifications or {}
    email = notifications.get("email") or {}
    if not (policy.enabled and email.get("enabled")):
        return
    if not rules.at_least(
        detection.severity, notifications.get("min_severity", "high")
    ):
        return
    recipients = list(
        AlertRecipient.objects.filter(
            tenant_id=policy.tenant_id,
            id__in=email.get("recipient_ids") or [],
            status=AlertRecipient.StatusChoices.CONFIRMED,
        ).values_list("email", flat=True)
    )
    if not recipients:
        return
    send_mail(
        subject=f"[Prowler Realtime] {detection.severity.upper()}: {detection.title}",
        message=(
            f"{detection.title}\n\nAccount: {policy.provider.uid}\n"
            f"Region: {detection.region}\nActor: {detection.actor}\n"
            f"Resource: {detection.resource or '-'}\n"
            f"Checks: {', '.join(detection.check_ids)}\n\n"
            f"Open in Prowler: {settings.ALERTS_UI_BASE_URL.rstrip('/')}/realtime"
            f"?tab=detections"
        ),
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=recipients,
        fail_silently=True,
    )


def ingest(tenant_id: str, provider: Provider, records: list[dict]) -> dict:
    """Store new events, evaluate them, and record detections and actions.

    Must run inside the tenant's RLS transaction.
    """
    policy = RealtimePolicy.objects.filter(provider=provider).first()
    credential = RealtimeCredential.objects.filter(provider=provider).first()
    counts = {"events": 0, "detections": 0, "violations": 0, "actions": 0}

    for raw in records:
        fields = record_from_cloudtrail(raw)
        if not fields["event_id"] or not fields["event_name"]:
            continue
        event, created = RealtimeEvent.objects.get_or_create(
            tenant_id=tenant_id,
            provider=provider,
            event_id=fields.pop("event_id"),
            defaults=fields,
        )
        if not created:
            continue
        counts["events"] += 1

        verdict = rules.evaluate(event)
        if verdict is None:
            continue
        if event.error_code:
            status, note = (
                Status.OUT_OF_SCOPE,
                f"The call failed ({event.error_code}): nothing changed.",
            )
        elif (
            policy
            and policy.allow_regions
            and event.region not in policy.allow_regions + [GLOBAL_REGION]
        ):
            status, note = (
                Status.OUT_OF_SCOPE,
                "The region is outside the policy's scope.",
            )
        elif verdict.violation:
            status, note = Status.VIOLATION, verdict.note
        else:
            status, note = Status.COMPLIANT, verdict.note

        detection = RealtimeDetection.objects.create(
            tenant_id=tenant_id,
            provider=provider,
            event=event,
            rule_id=verdict.rule_id,
            title=verdict.title,
            severity=verdict.severity,
            actor=event.user_arn,
            resource=verdict.resource,
            check_ids=verdict.check_ids,
            requirements=[],
            status=status,
            note=note,
            verified_at=datetime.now(tz=UTC),
        )
        counts["detections"] += 1
        if status != Status.VIOLATION:
            continue
        counts["violations"] += 1

        decided = _decide_action(policy, verdict, detection, credential)
        if decided:
            RealtimeAction.objects.create(
                tenant_id=tenant_id, provider=provider, detection=detection, **decided
            )
            counts["actions"] += 1
        if policy:
            _notify(policy, detection)
    return counts


def poll_feed(tenant_id: str, feed: RealtimeFeed) -> dict:
    """Read new events of one feed with the provider's own (read-only) credentials."""
    policy = RealtimePolicy.objects.filter(provider=feed.provider).first()
    now = datetime.now(tz=UTC)
    try:
        session = initialize_prowler_provider(feed.provider).session.current_session
        if feed.queue_url:
            records = read_sqs_events(session, feed.queue_url, feed.region)
        else:
            since = max(
                feed.last_polled_at or now - LOOKUP_WINDOW, now - timedelta(days=1)
            )
            records = read_lookup_events(session, _regions(feed, policy), since)
    except Exception as error:  # noqa: BLE001 - recorded on the feed for the UI
        logger.warning("Realtime feed %s poll failed: %s", feed.id, error)
        feed.status = RealtimeFeed.StatusChoices.ERROR
        feed.last_error = str(error)[:1000] or error.__class__.__name__
        feed.last_polled_at = now
        feed.save(
            update_fields=["status", "last_error", "last_polled_at", "updated_at"]
        )
        return {"error": feed.last_error}

    counts = ingest(tenant_id, feed.provider, records)
    feed.status = RealtimeFeed.StatusChoices.CONNECTED
    feed.last_error = ""
    feed.last_polled_at = now
    if records:
        latest = max(
            _parse_time(r.get("eventTime")) for r in records if r.get("eventTime")
        )
        feed.last_event_at = max(feed.last_event_at or latest, latest)
    feed.save(
        update_fields=[
            "status",
            "last_error",
            "last_polled_at",
            "last_event_at",
            "updated_at",
        ]
    )
    return counts


def apply_action(action: RealtimeAction) -> None:
    """Run a queued fix through the remediation role. Writes to AWS."""
    credential = RealtimeCredential.objects.get(provider=action.provider)
    try:
        session = remediations.remediation_session(credential)
        action.undo_state = remediations.APPLY[action.remediation_id](
            session, action, action.detection.event if action.detection else None
        )
        action.status = ActionStatus.APPLIED
    except Exception as error:  # noqa: BLE001 - recorded on the action
        action.status = ActionStatus.FIX_FAILED
        action.summary = f"{action.summary} AWS refused the change: {error}"[:2000]
    action.save(update_fields=["status", "summary", "undo_state", "updated_at"])


def revert_action(action: RealtimeAction) -> None:
    """Undo an applied fix. Raises RemediationError when AWS refuses."""
    reverter = remediations.REVERT.get(action.remediation_id)
    if reverter is None or not action.revertible:
        raise remediations.RemediationError("This fix cannot be reverted.")
    if action.status not in (ActionStatus.APPLIED, ActionStatus.FIXED_VERIFIED):
        raise remediations.RemediationError("Only an applied fix can be reverted.")
    credential = RealtimeCredential.objects.get(provider=action.provider)
    try:
        reverter(remediations.remediation_session(credential), action)
    except Exception as error:  # noqa: BLE001
        raise remediations.RemediationError(
            f"AWS did not accept the change: {error}"
        ) from error
    action.status = ActionStatus.REVERTED
    action.save(update_fields=["status", "updated_at"])
