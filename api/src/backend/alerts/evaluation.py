"""Evaluate an alert condition against a set of findings."""

import time
from dataclasses import dataclass, field

from alerts import dsl
from api.models import Finding, Scan, StateChoices, StatusChoices
from django.db.models import Count, Q, QuerySet

SEVERITY_RANK = ["critical", "high", "medium", "low", "informational"]
TOP_FINDINGS_LIMIT = 5
SAMPLE_FINDINGS_LIMIT = 10


@dataclass
class EvaluationResult:
    triggered: bool
    summary: dict = field(default_factory=dict)
    sample_finding_ids: list = field(default_factory=list)
    duration_ms: int = 0


def latest_completed_scan_ids(tenant_id: str, providers=None) -> list:
    """Id of the most recent completed scan of each provider."""
    scans = Scan.objects.filter(tenant_id=tenant_id, state=StateChoices.COMPLETED)
    if providers is not None:
        scans = scans.filter(provider__in=providers)
    return list(
        scans.order_by("provider_id", "-inserted_at")
        .distinct("provider_id")
        .values_list("id", flat=True)
    )


def alertable_findings(tenant_id: str, scan_ids) -> QuerySet:
    """Failing, unmuted findings of the given scans: what alerts reason about."""
    return Finding.all_objects.filter(
        tenant_id=tenant_id,
        scan_id__in=list(scan_ids),
        status=StatusChoices.FAIL,
        muted=False,
    )


def _count(findings: QuerySet, leaf_filter: dict) -> int:
    matched = findings.filter(dsl.filter_to_q(leaf_filter))
    if dsl.filter_needs_distinct(leaf_filter):
        return matched.values("id").distinct().count()
    return matched.count()


def _holds(node: dict, findings: QuerySet) -> bool:
    op = node["op"]
    if op == dsl.OP_AND:
        return all(_holds(child, findings) for child in node["children"])
    if op == dsl.OP_OR:
        return any(_holds(child, findings) for child in node["children"])
    if op == dsl.OP_NOT:
        return not _holds(node["child"], findings)

    count = _count(findings, node["filter"])
    if op == dsl.OP_COUNT_GTE:
        return count >= node["value"]
    if op == dsl.OP_COUNT_LTE:
        return count <= node["value"]
    if op == dsl.OP_ANY:
        return count > 0
    return count == 0  # OP_NONE


def _matched_findings(condition: dict, findings: QuerySet) -> QuerySet:
    """Findings a notification should report: the union of positive leaves."""
    query = Q()
    needs_distinct = False
    has_positive_leaf = False
    for leaf in dsl.iter_leaves(condition):
        if leaf["op"] not in dsl.POSITIVE_LEAF_OPS:
            continue
        has_positive_leaf = True
        query |= dsl.filter_to_q(leaf["filter"])
        needs_distinct = needs_distinct or dsl.filter_needs_distinct(leaf["filter"])

    if not has_positive_leaf:
        return findings.none()

    matched = findings.filter(query)
    if needs_distinct:
        # Collapse join duplicates through an id subquery so later aggregates
        # count each finding once.
        matched = findings.filter(id__in=matched.values("id"))
    return matched


def _summarize(condition: dict, findings: QuerySet) -> tuple[dict, list]:
    matched = _matched_findings(condition, findings)

    by_severity = {
        row["severity"]: row["total"]
        for row in matched.values("severity").annotate(total=Count("id")).order_by()
    }
    counts_by_severity = {
        severity: by_severity[severity]
        for severity in SEVERITY_RANK
        if by_severity.get(severity)
    }
    total = sum(counts_by_severity.values())

    top_checks = (
        matched.values("check_id")
        .annotate(total=Count("id"))
        .order_by("-total", "check_id")[:TOP_FINDINGS_LIMIT]
    )
    summary = {
        "finding_count_total": total,
        "counts_by_severity": counts_by_severity,
        "top_findings": [f"{row['check_id']} ({row['total']})" for row in top_checks],
        "deep_link_filter_hint": dsl.findings_filter_hint(condition),
    }
    if counts_by_severity:
        summary["top_severity"] = next(iter(counts_by_severity))

    sample_ids = [
        str(finding_id)
        for finding_id in matched.order_by("-id").values_list("id", flat=True)[
            :SAMPLE_FINDINGS_LIMIT
        ]
    ]
    return summary, sample_ids


def evaluate_condition(condition: dict, findings: QuerySet) -> EvaluationResult:
    """Decide whether `condition` holds over `findings` and summarize matches."""
    started = time.monotonic()
    triggered = _holds(condition, findings)
    summary, sample_ids = _summarize(condition, findings)
    return EvaluationResult(
        triggered=triggered,
        summary=summary,
        sample_finding_ids=sample_ids,
        duration_ms=int((time.monotonic() - started) * 1000),
    )
