"""Tools the Lighthouse AI agent can call. All read-only, all tenant-scoped.

Every tool runs inside the tenant's RLS transaction and only sees providers
the requesting user's role can see.
"""

import json
from uuid import UUID

from alerts.evaluation import latest_completed_scan_ids
from api.models import (
    ComplianceOverviewSummary,
    Finding,
    Provider,
    Resource,
    Scan,
    StatusChoices,
)
from django.db.models import Count, Q

MAX_ROWS = 25
MAX_RESULT_CHARS = 12_000
SEVERITIES = ["critical", "high", "medium", "low", "informational"]
STATUSES = ["FAIL", "PASS", "MANUAL"]


class ToolContext:
    def __init__(self, tenant_id: str, providers=None):
        self.tenant_id = tenant_id
        # None means the role sees every provider of the tenant.
        self.providers = providers

    def provider_queryset(self):
        if self.providers is not None:
            return self.providers
        return Provider.objects.filter(tenant_id=self.tenant_id)

    def latest_findings(self):
        scan_ids = latest_completed_scan_ids(self.tenant_id, self.providers)
        return Finding.all_objects.filter(
            tenant_id=self.tenant_id, scan_id__in=scan_ids
        )


def _limit(arguments: dict) -> int:
    try:
        return max(1, min(int(arguments.get("limit") or 10), MAX_ROWS))
    except (TypeError, ValueError):
        return 10


def _strings(arguments: dict, key: str, allowed=None) -> list[str]:
    values = arguments.get(key) or []
    if isinstance(values, str):
        values = [values]
    values = [value for value in values if isinstance(value, str) and value]
    if allowed is not None:
        allowed_by_lower = {item.lower(): item for item in allowed}
        values = [
            allowed_by_lower[value.lower()]
            for value in values
            if value.lower() in allowed_by_lower
        ]
    return values


def _finding_filter(arguments: dict) -> Q:
    query = Q()
    if severities := _strings(arguments, "severity", SEVERITIES):
        query &= Q(severity__in=severities)
    if statuses := _strings(arguments, "status", STATUSES):
        query &= Q(status__in=statuses)
    if provider_types := _strings(arguments, "provider_type"):
        query &= Q(scan__provider__provider__in=provider_types)
    if services := _strings(arguments, "service"):
        query &= Q(resource_services__overlap=services)
    if regions := _strings(arguments, "region"):
        query &= Q(resource_regions__overlap=regions)
    if check_ids := _strings(arguments, "check_id"):
        query &= Q(check_id__in=check_ids)
    if not arguments.get("include_muted"):
        query &= Q(muted=False)
    return query


def _finding_row(finding: Finding) -> dict:
    metadata = finding.check_metadata or {}
    return {
        "id": str(finding.id),
        "check_id": finding.check_id,
        "title": metadata.get("checktitle") or finding.check_id,
        "severity": finding.severity,
        "status": finding.status,
        "muted": finding.muted,
        "delta": finding.delta,
        "regions": finding.resource_regions,
        "services": finding.resource_services,
        "status_extended": (finding.status_extended or "")[:400],
    }


def get_findings_overview(context: ToolContext, arguments: dict) -> dict:
    findings = context.latest_findings().filter(muted=False)
    by_status = dict(
        findings.values_list("status").annotate(total=Count("id")).order_by()
    )
    failing = findings.filter(status=StatusChoices.FAIL)
    by_severity = dict(
        failing.values_list("severity").annotate(total=Count("id")).order_by()
    )
    by_provider = list(
        failing.values("scan__provider__provider", "scan__provider__alias")
        .annotate(total=Count("id"))
        .order_by("-total")[:MAX_ROWS]
    )
    return {
        "scope": "latest completed scan of each provider, muted findings excluded",
        "findings_by_status": by_status,
        "failing_by_severity": {
            severity: by_severity[severity]
            for severity in SEVERITIES
            if severity in by_severity
        },
        "failing_by_provider": [
            {
                "provider_type": row["scan__provider__provider"],
                "alias": row["scan__provider__alias"],
                "failing": row["total"],
            }
            for row in by_provider
        ],
    }


def search_security_findings(context: ToolContext, arguments: dict) -> dict:
    findings = context.latest_findings().filter(_finding_filter(arguments))
    limit = _limit(arguments)
    rows = [_finding_row(finding) for finding in findings.order_by("-id")[:limit]]
    return {"total_matching": findings.count(), "returned": len(rows), "findings": rows}


def get_finding_details(context: ToolContext, arguments: dict) -> dict:
    try:
        finding_id = UUID(str(arguments.get("finding_id")))
    except ValueError:
        return {"error": "finding_id must be a UUID."}
    finding = (
        Finding.all_objects.filter(tenant_id=context.tenant_id, id=finding_id)
        .filter(scan__provider__in=context.provider_queryset())
        .select_related("scan__provider")
        .first()
    )
    if finding is None:
        return {"error": "Finding not found."}

    metadata = finding.check_metadata or {}
    remediation = (metadata.get("remediation") or {}).get("recommendation") or {}
    return {
        **_finding_row(finding),
        "provider": {
            "type": finding.scan.provider.provider,
            "uid": finding.scan.provider.uid,
            "alias": finding.scan.provider.alias,
        },
        "description": metadata.get("description"),
        "risk": metadata.get("risk"),
        "remediation": remediation.get("text"),
        "remediation_url": remediation.get("url"),
        "categories": finding.categories,
        "compliance": finding.compliance,
        "first_seen_at": finding.first_seen_at,
        "resources": [
            {"uid": resource.uid, "name": resource.name, "type": resource.type}
            for resource in finding.resources.all()[:5]
        ],
    }


def get_top_failing_checks(context: ToolContext, arguments: dict) -> dict:
    failing = context.latest_findings().filter(
        _finding_filter({**arguments, "status": ["FAIL"]})
    )
    rows = (
        failing.values("check_id", "severity")
        .annotate(failing=Count("id"))
        .order_by("-failing", "check_id")[: _limit(arguments)]
    )
    return {"checks": list(rows)}


def list_providers(context: ToolContext, arguments: dict) -> dict:
    providers = context.provider_queryset().order_by("provider", "alias")[:MAX_ROWS]
    return {
        "providers": [
            {
                "id": str(provider.id),
                "type": provider.provider,
                "uid": provider.uid,
                "alias": provider.alias,
                "connected": provider.connected,
            }
            for provider in providers
        ]
    }


def list_scans(context: ToolContext, arguments: dict) -> dict:
    scans = (
        Scan.objects.filter(
            tenant_id=context.tenant_id, provider__in=context.provider_queryset()
        )
        .select_related("provider")
        .order_by("-inserted_at")[: _limit(arguments)]
    )
    return {
        "scans": [
            {
                "id": str(scan.id),
                "name": scan.name,
                "provider": scan.provider.alias or scan.provider.uid,
                "provider_type": scan.provider.provider,
                "state": scan.state,
                "trigger": scan.trigger,
                "resources": scan.unique_resource_count,
                "completed_at": scan.completed_at,
            }
            for scan in scans
        ]
    }


def list_resources(context: ToolContext, arguments: dict) -> dict:
    resources = Resource.objects.filter(
        tenant_id=context.tenant_id, provider__in=context.provider_queryset()
    )
    if services := _strings(arguments, "service"):
        resources = resources.filter(service__in=services)
    if regions := _strings(arguments, "region"):
        resources = resources.filter(region__in=regions)
    rows = resources.order_by("-failed_findings_count", "name")[: _limit(arguments)]
    return {
        "total_matching": resources.count(),
        "resources": [
            {
                "uid": resource.uid,
                "name": resource.name,
                "type": resource.type,
                "service": resource.service,
                "region": resource.region,
                "failed_findings": resource.failed_findings_count,
            }
            for resource in rows
        ],
    }


def get_compliance_overview(context: ToolContext, arguments: dict) -> dict:
    scan_ids = latest_completed_scan_ids(context.tenant_id, context.providers)
    summaries = ComplianceOverviewSummary.objects.filter(
        tenant_id=context.tenant_id, scan_id__in=scan_ids
    ).select_related("scan__provider")
    if frameworks := _strings(arguments, "framework"):
        query = Q()
        for framework in frameworks:
            query |= Q(compliance_id__icontains=framework)
        summaries = summaries.filter(query)
    rows = summaries.order_by("-requirements_failed", "compliance_id")[
        : _limit(arguments)
    ]
    return {
        "frameworks": [
            {
                "compliance_id": row.compliance_id,
                "provider": row.scan.provider.alias or row.scan.provider.uid,
                "requirements_passed": row.requirements_passed,
                "requirements_failed": row.requirements_failed,
                "requirements_manual": row.requirements_manual,
                "total_requirements": row.total_requirements,
            }
            for row in rows
        ]
    }


_STRING_LIST = {"type": "array", "items": {"type": "string"}}
_LIMIT = {"type": "integer", "minimum": 1, "maximum": MAX_ROWS}
_FINDING_FILTERS = {
    "severity": {**_STRING_LIST, "description": f"Any of {SEVERITIES}."},
    "provider_type": {**_STRING_LIST, "description": "e.g. aws, azure, gcp."},
    "service": {**_STRING_LIST, "description": "e.g. s3, iam, ec2."},
    "region": _STRING_LIST,
    "check_id": _STRING_LIST,
}

_TOOLS = {
    "prowler_get_findings_overview": (
        get_findings_overview,
        "Counts of findings by status, and of failing findings by severity and "
        "provider, over the latest scan of each provider. Start here.",
        {},
    ),
    "prowler_search_security_findings": (
        search_security_findings,
        "List findings from the latest scans, newest first, with optional filters.",
        {
            **_FINDING_FILTERS,
            "status": {**_STRING_LIST, "description": f"Any of {STATUSES}."},
            "include_muted": {"type": "boolean"},
            "limit": _LIMIT,
        },
    ),
    "prowler_get_finding_details": (
        get_finding_details,
        "Full detail of one finding: risk, remediation, compliance, resources.",
        {"finding_id": {"type": "string", "description": "Finding UUID."}},
    ),
    "prowler_get_top_failing_checks": (
        get_top_failing_checks,
        "Checks with the most failing findings in the latest scans.",
        {**_FINDING_FILTERS, "limit": _LIMIT},
    ),
    "prowler_get_compliance_overview": (
        get_compliance_overview,
        "Passed and failed requirements per compliance framework in the latest "
        "scans, worst first.",
        {
            "framework": {
                **_STRING_LIST,
                "description": "Substrings to match, e.g. cis, soc2, iso27001.",
            },
            "limit": _LIMIT,
        },
    ),
    "prowler_list_providers": (
        list_providers,
        "Cloud accounts connected to Prowler.",
        {},
    ),
    "prowler_list_scans": (list_scans, "Most recent scans.", {"limit": _LIMIT}),
    "prowler_list_resources": (
        list_resources,
        "Resources ordered by number of failing findings.",
        {"service": _STRING_LIST, "region": _STRING_LIST, "limit": _LIMIT},
    ),
}

TOOL_SPECS = [
    {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {
                "type": "object",
                "properties": properties,
                "required": ["finding_id"] if "finding_id" in properties else [],
            },
        },
    }
    for name, (_, description, properties) in _TOOLS.items()
]


def run_tool(context: ToolContext, name: str, raw_arguments: str) -> tuple[str, str]:
    """Execute a tool call. Returns (json result for the model, outcome)."""
    entry = _TOOLS.get(name)
    if entry is None:
        return json.dumps({"error": f"Unknown tool {name!r}."}), "error"
    try:
        arguments = json.loads(raw_arguments) if raw_arguments else {}
        if not isinstance(arguments, dict):
            raise ValueError("Tool arguments must be a JSON object.")
        result = entry[0](context, arguments)
    except Exception as error:  # noqa: BLE001 - reported to the model, which can retry
        return json.dumps({"error": str(error) or error.__class__.__name__}), "error"

    outcome = "error" if "error" in result else "success"
    return json.dumps(result, default=str)[:MAX_RESULT_CHARS], outcome
