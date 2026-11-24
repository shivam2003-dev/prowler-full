"""Made-up Realtime data, shown before an account has a policy."""

from datetime import UTC, datetime, timedelta

DEMO_PROVIDER = {
    "id": "00000000-0000-4000-8000-000000000001",
    "uid": "123456789012",
    "alias": "demo-account",
}


def _at(minutes: int) -> str:
    return (datetime.now(tz=UTC) - timedelta(minutes=minutes)).isoformat()


_EVENTS = [
    (
        "AuthorizeSecurityGroupIngress",
        "ec2.amazonaws.com",
        "eu-west-1",
        "violation",
        "sg_open_ingress",
        4,
    ),
    (
        "PutBucketPublicAccessBlock",
        "s3.amazonaws.com",
        "us-east-1",
        "violation",
        "s3_bucket_public_access_block",
        18,
    ),
    (
        "StopLogging",
        "cloudtrail.amazonaws.com",
        "us-east-1",
        "violation",
        "cloudtrail_stopped",
        41,
    ),
    (
        "RunInstances",
        "ec2.amazonaws.com",
        "eu-west-1",
        "compliant",
        "ec2_instance_launch",
        63,
    ),
    (
        "ConsoleLogin",
        "signin.amazonaws.com",
        "us-east-1",
        "compliant",
        "console_login_without_mfa",
        90,
    ),
]


def _events():
    return [
        {
            "id": f"00000000-0000-4000-8000-00000000010{i}",
            "event_time": _at(minutes),
            "region": region,
            "event_source": source,
            "event_name": name,
            "user_type": "IAMUser",
            "user_arn": "arn:aws:iam::123456789012:user/demo-engineer",
            "source_ip": "203.0.113.10",
            "error_code": "",
            "read_only": False,
            "provider_id": DEMO_PROVIDER["id"],
            "detection_status": status,
            "rule_id": rule,
        }
        for i, (name, source, region, status, rule, minutes) in enumerate(_EVENTS)
    ]


def _detections():
    titles = {
        "sg_open_ingress": (
            "Security group opened to the internet",
            "high",
            "sg-0demo",
            ["ec2_securitygroup_allow_ingress_from_internet_to_all_ports"],
        ),
        "s3_bucket_public_access_block": (
            "S3 bucket public access block weakened",
            "high",
            "demo-bucket",
            ["s3_bucket_level_public_access_block"],
        ),
        "cloudtrail_stopped": (
            "CloudTrail logging stopped",
            "critical",
            "management-trail",
            ["cloudtrail_multi_region_enabled"],
        ),
        "ec2_instance_launch": (
            "EC2 instance launched",
            "medium",
            "",
            ["ec2_instance_imdsv2_enabled"],
        ),
        "console_login_without_mfa": (
            "Console sign-in",
            "informational",
            "",
            ["iam_user_mfa_enabled_console_access"],
        ),
    }
    rows = []
    for i, event in enumerate(_events()):
        title, severity, resource, checks = titles[event["rule_id"]]
        rows.append(
            {
                "id": f"00000000-0000-4000-8000-00000000020{i}",
                "provider_id": DEMO_PROVIDER["id"],
                "event_id": event["id"],
                "event_time": event["event_time"],
                "region": event["region"],
                "rule_id": event["rule_id"],
                "title": title,
                "severity": severity,
                "actor": event["user_arn"],
                "resource": resource,
                "check_ids": checks,
                "requirements": [],
                "status": event["detection_status"],
                "note": "",
                "verified_at": event["event_time"],
            }
        )
    return rows


def _actions():
    return [
        {
            "id": "00000000-0000-4000-8000-000000000300",
            "provider_id": DEMO_PROVIDER["id"],
            "detection_id": "00000000-0000-4000-8000-000000000200",
            "kind": "self_fix",
            "status": "fixed_verified",
            "check_id": "ec2_securitygroup_allow_ingress_from_internet_to_all_ports",
            "resource_uid": "sg-0demo",
            "region": "eu-west-1",
            "severity": "high",
            "summary": "Revoked 0.0.0.0/0 on all ports.",
            "pr_url": "",
            "branch": "",
            "revertible": True,
            "inserted_at": _at(3),
        },
        {
            "id": "00000000-0000-4000-8000-000000000301",
            "provider_id": DEMO_PROVIDER["id"],
            "detection_id": "00000000-0000-4000-8000-000000000201",
            "kind": "code",
            "status": "pr_opened",
            "check_id": "s3_bucket_level_public_access_block",
            "resource_uid": "demo-bucket",
            "region": "us-east-1",
            "severity": "high",
            "summary": "Set block_public_acls and friends on aws_s3_bucket_public_access_block.demo.",
            "pr_url": "https://github.com/example/infra/pull/42",
            "branch": "prowler/realtime-demo-bucket",
            "revertible": False,
            "inserted_at": _at(17),
        },
    ]


def _posture():
    return {
        "passed": 412,
        "failed": 57,
        "muted": 6,
        "score": 87.8,
        "failed_by_severity": {"critical": 3, "high": 11, "medium": 25, "low": 18},
        "has_scan": True,
    }


def _anomaly():
    return {
        "id": "demo-anomaly",
        "service": "Amazon Elastic Compute Cloud - Compute",
        "region": "eu-west-1",
        "short_service": "ec2",
        "today": 182.4,
        "base": 41.2,
        "delta": 141.2,
        "ratio": 4.43,
    }


def _series():
    return [
        {
            "day": (datetime.now(tz=UTC) - timedelta(days=d)).date().isoformat(),
            "amount": a,
        }
        for d, a in zip(
            range(13, -1, -1),
            [40, 42, 39, 41, 44, 40, 43, 41, 42, 40, 39, 41, 45, 182.4],
        )
    ]


def payload(kind: str) -> dict | None:
    thresholds = {"min_ratio": 2.0, "min_delta": 5.0}
    if kind in ("events", "detections", "actions"):
        items = {"events": _events, "detections": _detections, "actions": _actions}[
            kind
        ]()
        return {"items": items}
    if kind == "overview":
        return {
            "provider": DEMO_PROVIDER,
            "policy": {
                "enabled": True,
                "mode": "auto",
                "dry_run": False,
                "scope_tags": {},
            },
            "feed": {
                "status": "connected",
                "source": "sqs",
                "last_event_at": _at(4),
                "last_error": "",
            },
            "data_store": "ok",
            "events_last_hour": {"events": 132, "changes": 9},
            "cost": {
                "enabled": True,
                "available": True,
                "total": 612.3,
                "today": 182.4,
                "anomaly_count": 1,
                "anomalies": [_anomaly()],
            },
            "posture": _posture(),
            "detections": {"violation": 3, "compliant": 2},
            "actions": {"fixed_verified": 1, "pr_opened": 1},
        }
    if kind == "findings":
        return {
            "signals": [
                {
                    "signal": e["event_name"],
                    "service": e["event_source"].split(".")[0],
                    "region": e["region"],
                    "count": 1,
                }
                for e in _events()
            ],
            "findings": [
                {
                    "finding_id": "00000000-0000-4000-8000-000000000400",
                    "check_id": "cloudtrail_multi_region_enabled",
                    "severity": "critical",
                    "title": "Ensure CloudTrail is enabled in all regions",
                    "service": "cloudtrail",
                    "resource_uid": "management-trail",
                    "region": "us-east-1",
                    "status_extended": "Trail management-trail is not logging.",
                    "score": 95,
                    "reasons": [
                        "critical severity",
                        "recent changes in this service and region",
                    ],
                    "route": "auto",
                }
            ],
        }
    if kind == "cost":
        return {
            "enabled": True,
            "total": {"total": 612.3, "today": 182.4},
            "series": [
                {
                    "service": _anomaly()["service"],
                    "region": "eu-west-1",
                    "days": _series(),
                    "latest": 182.4,
                    "base": 41.2,
                }
            ],
            "anomalies": [_anomaly()],
            "thresholds": thresholds,
        }
    if kind == "anomaly":
        return {
            "anomaly": _anomaly(),
            "short_service": "ec2",
            "series": _series(),
            "thresholds": thresholds,
            "events": [],
            "findings": [],
        }
    if kind == "simulation":
        return {
            "open": 57,
            "would_fix_in_account": 14,
            "would_propose_in_code": 21,
            "needs_a_person": 18,
            "outside_frameworks": 4,
            "frameworks": ["cis_3.0_aws"],
            "dry_run": False,
            "mode": "auto",
            "effects": [
                {
                    "check_id": "s3_bucket_level_public_access_block",
                    "effect": "Turns on the four public access block settings of the bucket.",
                    "resources": 9,
                }
            ],
            "projected_open_after_auto": 43,
            "automation_share": 0.246,
        }
    if kind == "timeline":
        return {
            "points": [
                {
                    "at": _at(60 * 24 * d),
                    "passed": 380 + 5 * (7 - d),
                    "failed": 70 - 2 * (7 - d),
                }
                for d in range(7, -1, -1)
            ],
            "actions": [
                {
                    "at": a["inserted_at"],
                    "kind": a["kind"],
                    "status": a["status"],
                    "summary": a["summary"],
                }
                for a in _actions()
            ],
        }
    if kind == "status":
        return {
            "generated_on": datetime.now(tz=UTC).date().isoformat(),
            "mode": "auto",
            "scope": "All regions",
            "checks_passing": 268,
            "checks_failing": 31,
            "failing_by_severity": _posture()["failed_by_severity"],
            "fixed_and_verified_last_30_days": 22,
            "sha256": "0" * 64,
        }
    return None
