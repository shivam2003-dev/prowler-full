"""Build issues from a provider's latest scan."""

import uuid

from api.models import Finding, Issue, Scan, StatusChoices
from issues.patterns import LEGS, MODELLED_CHECKS, PATTERNS, UNMODELLED

VERDICT_RANK = {
    "exploitable": 5,
    "likely": 4,
    "conditional": 3,
    "unknown": 2,
    "not_exploitable": 1,
}
SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1}
ISSUE_NAMESPACE = uuid.UUID("6e0c5b3f-0b4e-4d8f-9a85-7f1c4a9d2e11")


def issue_id(tenant_id, provider_id, pattern_id) -> uuid.UUID:
    return uuid.uuid5(ISSUE_NAMESPACE, f"{tenant_id}:{provider_id}:{pattern_id}")


def _leg(pattern, leg, failing_by_check, passing_checks, resources_by_check):
    checks = pattern.legs.get(leg, ())
    failing = [check for check in checks if check in failing_by_check]
    if failing:
        evidence = (
            failing
            + sorted(
                {uid for check in failing for uid in resources_by_check.get(check, ())}
            )[:10]
        )
        return {
            "state": "yes",
            "text": f"Failing: {', '.join(failing)}.",
            "evidence": evidence,
        }
    passed = [check for check in checks if check in passing_checks]
    if checks and passed and len(passed) == len(checks):
        return {
            "state": "no",
            "text": "Every check on this leg passed.",
            "evidence": passed,
        }
    if passed:
        return {
            "state": "partial",
            "text": f"Passed: {', '.join(passed)}; others were not evaluated.",
            "evidence": passed,
        }
    return {
        "state": "unknown",
        "text": "Prowler has no finding that answers this leg.",
        "evidence": [],
    }


def _verdict(pattern, legs) -> str:
    if pattern.hygiene:
        return "unknown"
    states = {name: leg["state"] for name, leg in legs.items()}
    if "no" in (states["reachability"], states["access"]):
        return "not_exploitable"
    if states["reachability"] == "yes" and states["access"] == "yes":
        return "exploitable" if states["controls"] != "no" else "likely"
    if states["reachability"] == "yes" or states["access"] == "yes":
        return "likely" if states["target"] == "yes" else "conditional"
    return "conditional"


def rebuild(tenant_id: str, scan: Scan) -> list[Issue]:
    """Replace the provider's issues with what this scan shows.

    Must run inside the tenant's RLS transaction.
    """
    findings = Finding.all_objects.filter(
        tenant_id=tenant_id, scan_id=scan.id, muted=False
    ).prefetch_related("resources")
    failing_by_check: dict[str, list] = {}
    passing_checks: set[str] = set()
    resources_by_check: dict[str, set] = {}
    for finding in findings:
        if finding.status == StatusChoices.FAIL:
            failing_by_check.setdefault(finding.check_id, []).append(finding)
            resources_by_check.setdefault(finding.check_id, set()).update(
                resource.uid for resource in finding.resources.all()
            )
        elif finding.status == StatusChoices.PASS:
            passing_checks.add(finding.check_id)

    kept = []
    unmodelled = {
        check: rows
        for check, rows in failing_by_check.items()
        if check not in MODELLED_CHECKS
    }
    for pattern in (*PATTERNS, UNMODELLED):
        if pattern is UNMODELLED:
            matched = [f for rows in unmodelled.values() for f in rows]
            legs = {
                leg: {
                    "state": "unknown",
                    "text": "Not part of a modelled path.",
                    "evidence": [],
                }
                for leg in LEGS
            }
        else:
            matched = [
                f for check in pattern.checks for f in failing_by_check.get(check, [])
            ]
            legs = {
                leg: _leg(
                    pattern, leg, failing_by_check, passing_checks, resources_by_check
                )
                for leg in LEGS
            }
        if not matched:
            continue
        unique = {f.uid: f for f in matched}
        severity = max(
            unique.values(), key=lambda f: SEVERITY_RANK.get(f.severity, 0)
        ).severity
        verdict = _verdict(pattern, legs)
        issue, _ = Issue.objects.update_or_create(
            id=issue_id(tenant_id, scan.provider_id, pattern.id),
            defaults={
                "tenant_id": tenant_id,
                "provider_id": scan.provider_id,
                "scan": scan,
                "pattern": pattern.id,
                "title": pattern.title,
                "verdict": verdict,
                "verdict_rank": VERDICT_RANK[verdict],
                "severity": severity,
                "severity_rank": SEVERITY_RANK.get(severity, 0),
                "outcome": pattern.outcome,
                "attacker_start": pattern.attacker_start,
                "legs": legs,
                "fix": pattern.fix,
                "finding_uids": sorted(unique),
                "resource_uids": sorted(
                    {r.uid for f in unique.values() for r in f.resources.all()}
                ),
                "findings_count": len(unique),
            },
        )
        kept.append(issue)

    # Paths this scan no longer shows are closed: drop them (their triage goes too).
    Issue.objects.filter(tenant_id=tenant_id, provider_id=scan.provider_id).exclude(
        id__in=[issue.id for issue in kept]
    ).delete()
    return kept
