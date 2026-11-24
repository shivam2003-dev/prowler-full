"""Cross-provider compliance: one universal framework, every provider's latest scan."""

from api.compliance import get_prowler_provider_compliance
from api.models import ComplianceRequirementOverview, Scan, StateChoices

STATUS_RANK = {"FAIL": 3, "MANUAL": 2, "PASS": 1}


def _worst(statuses) -> str:
    statuses = [s for s in statuses if s in STATUS_RANK]
    return max(statuses, key=STATUS_RANK.get) if statuses else "MANUAL"


def _framework(compliance_id: str, provider_types):
    """The universal framework and, per provider type, its requirement checks."""
    framework, checks_by_type = None, {}
    for provider_type in provider_types:
        try:
            loaded = get_prowler_provider_compliance(provider_type)
        except Exception:  # noqa: BLE001
            continue
        found = loaded.get(compliance_id)
        if found is None:
            continue
        framework = framework or found
        checks_by_type[provider_type] = {
            req.id: list((req.checks or {}).get(provider_type, []))
            if isinstance(req.checks, dict)
            else list(req.checks or [])
            for req in found.requirements
        }
    return framework, checks_by_type


def overview(
    tenant_id: str, compliance_id: str, providers, scan_ids=None
) -> dict | None:
    """None when no provider type offers the framework."""
    compatible = sorted(set(providers.values_list("provider", flat=True)))
    framework, checks_by_type = _framework(compliance_id, compatible)
    if framework is None:
        return None
    compatible = sorted(checks_by_type)

    scans = Scan.objects.filter(
        tenant_id=tenant_id, provider__in=providers, state=StateChoices.COMPLETED
    ).select_related("provider")
    if scan_ids:
        scans = scans.filter(id__in=scan_ids)
    latest = {}
    for scan in scans.order_by("provider_id", "-completed_at"):
        latest.setdefault(scan.provider_id, scan)
    scan_ids_by_type: dict[str, list[str]] = {}
    for scan in latest.values():
        scan_ids_by_type.setdefault(scan.provider.provider, []).append(str(scan.id))

    rows = ComplianceRequirementOverview.objects.filter(
        tenant_id=tenant_id, compliance_id=compliance_id, scan__in=latest.values()
    ).values_list("requirement_id", "requirement_status", "scan__provider__provider")
    statuses: dict[str, dict[str, list]] = {}
    for requirement_id, status, provider_type in rows:
        statuses.setdefault(requirement_id, {}).setdefault(provider_type, []).append(
            status
        )

    requirements, counts = [], {"PASS": 0, "FAIL": 0, "MANUAL": 0}
    for requirement in framework.requirements:
        per_type = {
            provider_type: _worst(values)
            for provider_type, values in statuses.get(requirement.id, {}).items()
        }
        overall = _worst(per_type.values()) if per_type else "MANUAL"
        counts[overall] += 1
        requirements.append(
            {
                "id": requirement.id,
                "name": requirement.name or requirement.id,
                "description": requirement.description or "",
                "attributes": requirement.attributes
                if isinstance(requirement.attributes, dict)
                else {},
                "status": overall,
                "providers": per_type,
                "check_ids_by_provider": {
                    provider_type: checks[requirement.id]
                    for provider_type, checks in checks_by_type.items()
                    if checks.get(requirement.id)
                },
            }
        )
    return {
        "compliance_id": compliance_id,
        "framework": str(framework.framework or ""),
        "name": str(framework.name or compliance_id),
        "version": str(framework.version or ""),
        "description": str(framework.description or ""),
        "compatible_providers": compatible,
        "requested_providers": compatible,
        "providers": sorted(scan_ids_by_type),
        "scan_ids": [sid for ids in scan_ids_by_type.values() for sid in ids],
        "scan_ids_by_provider": scan_ids_by_type,
        "requirements_passed": counts["PASS"],
        "requirements_failed": counts["FAIL"],
        "requirements_manual": counts["MANUAL"],
        "total_requirements": len(requirements),
        "requirements": requirements,
    }


def _metadata(attributes) -> list:
    """Per-provider templates keep requirement metadata as a list of objects."""
    if isinstance(attributes, list):
        return [a.dict() if hasattr(a, "dict") else a for a in attributes]
    if isinstance(attributes, dict):
        return [attributes]
    return []


def cross_account(
    tenant_id: str, compliance_id: str, provider_type: str, providers, scan_ids=None
) -> dict | None:
    """One per-provider framework across every account of that provider type."""
    framework, checks_by_type = _framework(compliance_id, [provider_type])
    if framework is None:
        return None
    checks = checks_by_type[provider_type]
    providers = providers.filter(provider=provider_type)

    scans = Scan.objects.filter(
        tenant_id=tenant_id, provider__in=providers, state=StateChoices.COMPLETED
    ).select_related("provider")
    if scan_ids:
        scans = scans.filter(id__in=scan_ids)
    latest = {}
    for scan in scans.order_by("provider_id", "-completed_at"):
        latest.setdefault(scan.provider_id, scan)

    rows = ComplianceRequirementOverview.objects.filter(
        tenant_id=tenant_id, compliance_id=compliance_id, scan__in=latest.values()
    ).values_list("requirement_id", "requirement_status", "scan__provider_id")
    statuses: dict[str, dict[str, list]] = {}
    for requirement_id, status, provider_id in rows:
        statuses.setdefault(requirement_id, {}).setdefault(str(provider_id), []).append(
            status
        )

    requirements, counts = [], {"PASS": 0, "FAIL": 0, "MANUAL": 0}
    for requirement in framework.requirements:
        per_account = {
            account: _worst(values)
            for account, values in statuses.get(requirement.id, {}).items()
        }
        overall = _worst(per_account.values()) if per_account else "MANUAL"
        counts[overall] += 1
        requirements.append(
            {
                "id": requirement.id,
                "name": getattr(requirement, "name", None) or requirement.id,
                "description": requirement.description or "",
                "attributes": _metadata(requirement.attributes),
                "status": overall,
                "accounts": per_account,
                "check_ids": checks.get(requirement.id, []),
            }
        )
    return {
        "compliance_id": compliance_id,
        "provider_type": provider_type,
        "framework": str(framework.framework or ""),
        "name": str(framework.name or compliance_id),
        "version": str(framework.version or ""),
        "description": str(framework.description or ""),
        "accounts": [
            {"id": str(s.provider_id), "uid": s.provider.uid, "alias": s.provider.alias}
            for s in latest.values()
        ],
        "scan_ids": [str(s.id) for s in latest.values()],
        "scan_ids_by_account": {
            str(s.provider_id): [str(s.id)] for s in latest.values()
        },
        "requirements_passed": counts["PASS"],
        "requirements_failed": counts["FAIL"],
        "requirements_manual": counts["MANUAL"],
        "total_requirements": len(requirements),
        "requirements": requirements,
    }
