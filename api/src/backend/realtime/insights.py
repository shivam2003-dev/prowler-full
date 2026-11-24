"""Computed Realtime views of one AWS provider. Read-only, from the database."""

import hashlib
import json
from collections import Counter
from datetime import UTC, datetime, timedelta

from alerts.evaluation import latest_completed_scan_ids
from api.models import (
    Finding,
    Provider,
    RealtimeAction,
    RealtimeCredential,
    RealtimeDetection,
    RealtimeEvent,
    RealtimeFeed,
    RealtimePolicy,
    Scan,
    StateChoices,
    StatusChoices,
)
from django.db.models import Count, Q
from realtime import remediations, rules

SEVERITY_WEIGHT = {
    "critical": 40,
    "high": 25,
    "medium": 12,
    "low": 5,
    "informational": 1,
}
SEVERITIES = ["critical", "high", "medium", "low", "informational"]
RANKED_LIMIT = 25
TIMELINE_SCANS = 30


def _latest_findings(provider: Provider):
    scan_ids = latest_completed_scan_ids(
        str(provider.tenant_id), Provider.objects.filter(id=provider.id)
    )
    return Finding.all_objects.filter(
        tenant_id=provider.tenant_id, scan_id__in=scan_ids
    )


def _policy(provider):
    return RealtimePolicy.objects.filter(provider=provider).first()


def _cost_settings(policy):
    return {
        "min_ratio": policy.cost_anomaly_min_ratio if policy else 2.0,
        "min_delta": policy.cost_anomaly_min_delta if policy else 5.0,
    }


def posture(provider) -> dict:
    findings = _latest_findings(provider)
    counts = findings.aggregate(
        passed=Count("id", filter=Q(status=StatusChoices.PASS, muted=False)),
        failed=Count("id", filter=Q(status=StatusChoices.FAIL, muted=False)),
        muted=Count("id", filter=Q(muted=True)),
    )
    by_severity = dict(
        findings.filter(status=StatusChoices.FAIL, muted=False)
        .values_list("severity")
        .annotate(total=Count("id"))
        .order_by()
    )
    judged = counts["passed"] + counts["failed"]
    return {
        **counts,
        "score": round(100 * counts["passed"] / judged, 1) if judged else None,
        "failed_by_severity": {
            s: by_severity[s] for s in SEVERITIES if s in by_severity
        },
        "has_scan": findings.exists(),
    }


def overview(provider) -> dict:
    policy = _policy(provider)
    feed = RealtimeFeed.objects.filter(provider=provider).first()
    hour_ago = datetime.now(tz=UTC) - timedelta(hours=1)
    recent = RealtimeEvent.objects.filter(provider=provider, event_time__gte=hour_ago)
    return {
        "provider": {
            "id": str(provider.id),
            "uid": provider.uid,
            "alias": provider.alias,
        },
        "policy": (
            {
                "enabled": policy.enabled,
                "mode": policy.mode,
                "dry_run": policy.dry_run,
                "scope_tags": policy.scope_tags,
            }
            if policy
            else None
        ),
        "feed": (
            {
                "status": feed.status,
                "source": "sqs" if feed.queue_url else "lookup",
                "last_event_at": feed.last_event_at,
                "last_error": feed.last_error,
            }
            if feed
            else None
        ),
        "data_store": "ok",
        "events_last_hour": {
            "events": recent.count(),
            "changes": recent.filter(read_only=False).count(),
        },
        "cost": (
            {"enabled": True, "available": False, "anomaly_count": 0, "anomalies": []}
            if policy and policy.cost_anomaly_enabled
            else {"enabled": False}
        ),
        "posture": posture(provider),
        "detections": dict(
            RealtimeDetection.objects.filter(provider=provider)
            .values_list("status")
            .annotate(total=Count("id"))
            .order_by()
        ),
        "actions": dict(
            RealtimeAction.objects.filter(provider=provider)
            .values_list("status")
            .annotate(total=Count("id"))
            .order_by()
        ),
    }


def _route(policy, check_id: str) -> str:
    if policy is None or not policy.enabled or check_id in policy.deny_checks:
        return "not_enforced"
    if (
        policy.mode == RealtimePolicy.ModeChoices.AUTO
        and check_id in remediations.CHECK_TO_REMEDIATION
    ):
        return "auto"
    if policy.mode == RealtimePolicy.ModeChoices.PR:
        return "pr"
    return "manual"


def _signals(provider, since) -> list[dict]:
    rows = (
        RealtimeEvent.objects.filter(
            provider=provider, event_time__gte=since, read_only=False
        )
        .values("event_name", "event_source", "region")
        .annotate(count=Count("id"))
        .order_by("-count")[:20]
    )
    return [
        {
            "signal": row["event_name"],
            "service": row["event_source"].split(".")[0],
            "region": row["region"],
            "count": row["count"],
        }
        for row in rows
    ]


def ranked_findings(provider, service: str | None = None) -> list[dict]:
    policy = _policy(provider)
    since = datetime.now(tz=UTC) - timedelta(days=1)
    signals = _signals(provider, since)
    active = {(s["service"], s["region"]) for s in signals}
    failing = _latest_findings(provider).filter(status=StatusChoices.FAIL, muted=False)
    if service:
        failing = failing.filter(resource_services__overlap=[service])
    rows = []
    for finding in failing.prefetch_related("resources")[:500]:
        resource = next(iter(finding.resources.all()), None)
        svc = (finding.resource_services or [""])[0]
        region = (finding.resource_regions or [""])[0]
        score = SEVERITY_WEIGHT.get(finding.severity, 0)
        reasons = [f"{finding.severity} severity"]
        if (svc, region) in active:
            score += 30
            reasons.append("recent changes in this service and region")
        if finding.delta == "new":
            score += 10
            reasons.append("new in the latest scan")
        if "internet-exposed" in (finding.categories or []):
            score += 15
            reasons.append("internet exposed")
        rows.append(
            {
                "finding_id": str(finding.id),
                "check_id": finding.check_id,
                "severity": finding.severity,
                "title": (finding.check_metadata or {}).get("checktitle")
                or finding.check_id,
                "service": svc,
                "resource_uid": resource.uid if resource else "",
                "region": region,
                "status_extended": (finding.status_extended or "")[:300],
                "score": min(score, 100),
                "reasons": reasons,
                "route": _route(policy, finding.check_id),
            }
        )
    rows.sort(key=lambda row: (-row["score"], row["check_id"]))
    return rows[:RANKED_LIMIT]


def findings_view(provider) -> dict:
    since = datetime.now(tz=UTC) - timedelta(days=1)
    return {"signals": _signals(provider, since), "findings": ranked_findings(provider)}


def cost_view(provider) -> dict:
    policy = _policy(provider)
    if not (policy and policy.cost_anomaly_enabled):
        return {"enabled": False}
    # Cost Explorer bills every request, so this server does not call it; the
    # view stays empty rather than inventing numbers.
    return {
        "enabled": True,
        "total": {"total": 0, "today": 0},
        "series": [],
        "anomalies": [],
        "thresholds": _cost_settings(policy),
    }


def anomaly_view(provider, service: str, region: str) -> dict:
    since = datetime.now(tz=UTC) - timedelta(days=3)
    events = RealtimeEvent.objects.filter(
        provider=provider,
        event_time__gte=since,
        region=region,
        event_source__startswith=service,
    ).order_by("-event_time")[:50]
    return {
        "anomaly": None,
        "short_service": service,
        "series": [],
        "thresholds": _cost_settings(_policy(provider)),
        "events": [
            {
                "event_id": event.event_id,
                "event_time": event.event_time,
                "region": event.region,
                "event_source": event.event_source,
                "event_name": event.event_name,
                "user_type": event.user_type,
                "user_arn": event.user_arn,
                "source_ip": event.source_ip,
                "error_code": event.error_code,
            }
            for event in events
        ],
        "findings": ranked_findings(provider, service=service),
    }


def simulation_view(provider) -> dict:
    policy = _policy(provider)
    failing = _latest_findings(provider).filter(status=StatusChoices.FAIL, muted=False)
    by_check = Counter(failing.values_list("check_id", flat=True))
    frameworks = list(policy.frameworks) if policy else []
    outside = 0
    if frameworks:
        in_scope = set(
            failing.filter(
                Q(*[Q(compliance__has_key=f) for f in frameworks], _connector=Q.OR)
            ).values_list("check_id", flat=True)
        )
        outside = sum(n for check, n in by_check.items() if check not in in_scope)
    mode = policy.mode if policy else RealtimePolicy.ModeChoices.MONITOR
    auto = sum(
        n
        for check, n in by_check.items()
        if check in remediations.CHECK_TO_REMEDIATION
        and mode == RealtimePolicy.ModeChoices.AUTO
    )
    open_total = sum(by_check.values())
    in_code = (
        (open_total - auto - outside) if mode == RealtimePolicy.ModeChoices.PR else 0
    )
    effects = [
        {
            "check_id": check,
            "effect": remediations.CATALOG[
                remediations.CHECK_TO_REMEDIATION[check]
            ].effect,
            "resources": n,
        }
        for check, n in sorted(by_check.items())
        if check in remediations.CHECK_TO_REMEDIATION
    ]
    return {
        "open": open_total,
        "would_fix_in_account": auto,
        "would_propose_in_code": max(in_code, 0),
        "needs_a_person": max(open_total - auto - max(in_code, 0) - outside, 0),
        "outside_frameworks": outside,
        "frameworks": frameworks,
        "dry_run": policy.dry_run if policy else True,
        "mode": mode,
        "effects": effects,
        "projected_open_after_auto": open_total - auto,
        "automation_share": round(auto / open_total, 3) if open_total else 0,
    }


def timeline_view(provider) -> dict:
    scans = Scan.objects.filter(
        provider=provider, state=StateChoices.COMPLETED
    ).order_by("-completed_at")[:TIMELINE_SCANS]
    points = []
    for scan in reversed(list(scans)):
        counts = Finding.all_objects.filter(
            tenant_id=provider.tenant_id, scan_id=scan.id, muted=False
        ).aggregate(
            passed=Count("id", filter=Q(status=StatusChoices.PASS)),
            failed=Count("id", filter=Q(status=StatusChoices.FAIL)),
        )
        points.append({"at": scan.completed_at, **counts})
    actions = RealtimeAction.objects.filter(provider=provider).order_by("-inserted_at")[
        :50
    ]
    return {
        "points": points,
        "actions": [
            {
                "at": a.inserted_at,
                "kind": a.kind,
                "status": a.status,
                "summary": a.summary,
            }
            for a in actions
        ],
    }


def status_view(provider) -> dict:
    policy = _policy(provider)
    findings = _latest_findings(provider).filter(muted=False)
    passing = set(
        findings.filter(status=StatusChoices.PASS).values_list("check_id", flat=True)
    )
    failing = set(
        findings.filter(status=StatusChoices.FAIL).values_list("check_id", flat=True)
    )
    month_ago = datetime.now(tz=UTC) - timedelta(days=30)
    body = {
        "generated_on": datetime.now(tz=UTC).date().isoformat(),
        "mode": policy.mode if policy and policy.enabled else "off",
        "scope": ", ".join(policy.allow_regions)
        if policy and policy.allow_regions
        else "All regions",
        "checks_passing": len(passing - failing),
        "checks_failing": len(failing),
        "failing_by_severity": posture(provider)["failed_by_severity"],
        "fixed_and_verified_last_30_days": RealtimeAction.objects.filter(
            provider=provider,
            status=RealtimeAction.StatusChoices.FIXED_VERIFIED,
            inserted_at__gte=month_ago,
        ).count(),
    }
    body["sha256"] = hashlib.sha256(
        json.dumps(body, sort_keys=True).encode()
    ).hexdigest()
    return body


def setup_view(provider) -> dict:
    policy = _policy(provider)
    feed = RealtimeFeed.objects.filter(provider=provider).first()
    credential = RealtimeCredential.objects.filter(provider=provider).first()
    notifications = (policy.notifications or {}) if policy else {}
    needs_role = bool(
        policy and policy.mode == RealtimePolicy.ModeChoices.AUTO and not policy.dry_run
    )
    steps = [
        {
            "id": "feed",
            "required": True,
            "done": feed is not None,
            "detail": (
                ("SQS queue" if feed.queue_url else "CloudTrail LookupEvents")
                if feed
                else None
            ),
        },
        {
            "id": "enforcement",
            "required": True,
            "done": policy is not None,
            "detail": policy.mode if policy else None,
        },
        {
            "id": "remediation",
            "required": needs_role,
            "done": bool(credential and credential.role_arn),
            "detail": credential.role_arn
            if credential and credential.role_arn
            else None,
        },
        {
            "id": "alerts",
            "required": False,
            "done": bool((notifications.get("email") or {}).get("enabled")),
            "detail": None,
        },
        {
            "id": "cost",
            "required": False,
            "done": bool(policy and policy.cost_anomaly_enabled),
            "detail": None,
        },
        {
            "id": "activate",
            "required": True,
            "done": bool(policy and policy.enabled),
            "detail": None,
        },
    ]
    pending = [s for s in steps if s["required"] and not s["done"]]
    return {
        "activated": bool(policy and policy.enabled),
        "next_step": pending[0]["id"] if pending else None,
        "steps": steps,
    }


VIEWS = {
    "overview": overview,
    "findings": findings_view,
    "cost": cost_view,
    "simulation": simulation_view,
    "timeline": timeline_view,
    "status": status_view,
}

__all__ = ["VIEWS", "anomaly_view", "setup_view", "rules"]
