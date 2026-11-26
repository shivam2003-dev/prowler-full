"""Compliance catalog and watchlist."""

from functools import lru_cache

from api.compliance import get_prowler_provider_compliance
from api.models import ComplianceWatchlistEntry, Provider, TenantComplianceSummary

UNIVERSAL = "*"
MAX_BULK = 50


@lru_cache(maxsize=32)
def _frameworks(provider_type: str) -> dict:
    """compliance_id -> descriptor (with the checks it maps) for one provider type."""
    try:
        loaded = get_prowler_provider_compliance(provider_type)
    except Exception:  # noqa: BLE001 - unknown provider type: nothing to offer
        return {}
    frameworks = {}
    for compliance_id, framework in loaded.items():
        checks = set()
        for requirement in getattr(framework, "requirements", None) or []:
            value = getattr(requirement, "checks", None) or []
            if isinstance(value, dict):
                value = value.get(provider_type) or []
            checks.update(value)
        universal = (
            not getattr(framework, "provider", None)
            or str(framework.provider) == "None"
        )
        frameworks[compliance_id] = {
            "compliance_id": compliance_id,
            "provider_type": UNIVERSAL if universal else provider_type,
            "scope": "universal" if universal else "provider",
            "framework": str(getattr(framework, "framework", "") or ""),
            "name": str(getattr(framework, "name", "") or compliance_id),
            "version": str(getattr(framework, "version", "") or ""),
            "description": str(getattr(framework, "description", "") or ""),
            "checks": frozenset(checks),
        }
    return frameworks


def eligible_provider_types(tenant_id: str) -> list[str]:
    return sorted(
        set(
            Provider.objects.filter(tenant_id=tenant_id).values_list(
                "provider", flat=True
            )
        )
    )


def catalog(tenant_id: str, provider_types: list[str]) -> list[dict]:
    """One entry per (framework, provider type); universal ones once."""
    entries = {
        (row.compliance_id, row.provider_type): row.id
        for row in ComplianceWatchlistEntry.objects.filter(tenant_id=tenant_id)
    }
    scores = {
        row.compliance_id: row
        for row in TenantComplianceSummary.objects.filter(tenant_id=tenant_id)
    }
    merged: dict[tuple, dict] = {}
    for provider_type in provider_types:
        for compliance_id, framework in _frameworks(provider_type).items():
            key = (compliance_id, framework["provider_type"])
            item = merged.setdefault(
                key,
                {
                    **{k: v for k, v in framework.items() if k != "checks"},
                    "provider_types": [],
                },
            )
            item["provider_types"].append(provider_type)
    rows = []
    for (compliance_id, provider_type), item in sorted(merged.items()):
        score = scores.get(compliance_id)
        judged = (score.requirements_passed + score.requirements_failed) if score else 0
        entry_id = entries.get((compliance_id, provider_type))
        rows.append(
            {
                **item,
                "total_requirements": score.total_requirements if score else 0,
                "requirements_passed": score.requirements_passed if score else 0,
                "requirements_failed": score.requirements_failed if score else 0,
                "requirements_manual": score.requirements_manual if score else 0,
                "score": round(100 * score.requirements_passed / judged, 1)
                if judged
                else None,
                "has_data": score is not None,
                "in_watchlist": entry_id is not None,
                "watchlist_entry_id": str(entry_id) if entry_id else None,
            }
        )
    return rows


def is_known(compliance_id: str, provider_type: str) -> bool:
    if provider_type == UNIVERSAL:
        return any(
            framework["provider_type"] == UNIVERSAL and cid == compliance_id
            for pt in Provider.ProviderChoices.values
            for cid, framework in _frameworks(pt).items()
        )
    framework = _frameworks(provider_type).get(compliance_id)
    return framework is not None and framework["provider_type"] == provider_type


def frameworks_for_check(provider_type: str, check_id: str) -> list[dict]:
    return [
        {k: v for k, v in framework.items() if k != "checks"}
        for framework in _frameworks(provider_type).values()
        if check_id in framework["checks"]
    ]


def watchlisted_ids(tenant_id: str) -> set[str]:
    return set(
        ComplianceWatchlistEntry.objects.filter(tenant_id=tenant_id).values_list(
            "compliance_id", flat=True
        )
    )
