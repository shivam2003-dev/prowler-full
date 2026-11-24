"""Read Prowler OCSF detection findings back into scan findings.

The inverse of prowler.lib.outputs.ocsf.ocsf.OCSF.transform, limited to the
fields the scan persistence code reads from an SDK finding.
"""

from functools import lru_cache

from prowler.lib.check.models import Severity

SEVERITIES = frozenset({"critical", "high", "medium", "low", "informational"})
STATUSES = frozenset({"PASS", "FAIL", "MANUAL"})
SUPPRESSED_STATUS_ID = 3
KUBERNETES = "kubernetes"


class InvalidRecord(ValueError):
    """The record is not a Prowler OCSF finding that can be imported."""


@lru_cache(maxsize=32)
def _sdk_checks_metadata(provider_type: str) -> dict:
    """Lowercased SDK metadata of every check of a provider, by check id."""
    from prowler.lib.check.models import CheckMetadata
    from prowler.lib.utils.utils import dict_to_lowercase

    try:
        return {
            check_id: dict_to_lowercase(metadata.dict())
            for check_id, metadata in CheckMetadata.get_bulk(provider_type).items()
        }
    except Exception:  # noqa: BLE001 - unknown provider: fall back to the report
        return {}


def _text(value) -> str:
    return value if isinstance(value, str) else ""


def _labels_to_tags(labels) -> dict:
    tags = {}
    for label in labels if isinstance(labels, list) else []:
        if not isinstance(label, str):
            continue
        key, _, value = label.partition(":")
        if key:
            tags[key] = value
    return tags


class OcsfFinding:
    """Duck-typed stand-in for prowler.lib.outputs.finding.Finding."""

    def __init__(self, record: dict):
        if not isinstance(record, dict):
            raise InvalidRecord("Record is not an object.")

        metadata = record.get("metadata") or {}
        unmapped = record.get("unmapped") or {}
        cloud = record.get("cloud") or {}
        account = cloud.get("account") or {}
        finding_info = record.get("finding_info") or {}
        resources = record.get("resources") or []
        resource = resources[0] if resources and isinstance(resources[0], dict) else {}
        resource_data = resource.get("data") or {}

        self.provider = _text(unmapped.get("provider")) or _text(cloud.get("provider"))
        self.account_uid = _text(unmapped.get("provider_uid")) or _text(
            account.get("uid")
        )
        self.account_name = _text(account.get("name"))
        self.check_id = _text(metadata.get("event_code"))
        self.uid = _text(finding_info.get("uid"))
        self.status = _text(record.get("status_code")).upper()
        severity = _text(record.get("severity")).lower()
        self.resource_uid = _text(resource.get("uid"))

        required = {
            "provider": self.provider,
            "provider_uid": self.account_uid,
            "metadata.event_code": self.check_id,
            "finding_info.uid": self.uid,
            "resources[0].uid": self.resource_uid,
        }
        missing = [name for name, value in required.items() if not value]
        if missing:
            raise InvalidRecord(f"Missing {', '.join(missing)}.")
        if self.status not in STATUSES:
            raise InvalidRecord(f"Unsupported status_code {self.status!r}.")
        if severity not in SEVERITIES:
            raise InvalidRecord(f"Unsupported severity {severity!r}.")
        # The scan job reads `.value`, as it does on the SDK's own findings.
        self.severity = Severity(severity)

        self.status_extended = _text(record.get("status_detail")) or _text(
            record.get("message")
        )
        self.muted = (
            record.get("status_id") == SUPPRESSED_STATUS_ID
            or _text(record.get("status")).lower() == "suppressed"
        )
        self.resource_name = _text(resource.get("name"))
        self.resource_type = _text(resource.get("type"))
        self.service_name = _text((resource.get("group") or {}).get("name"))
        self.resource_tags = _labels_to_tags(resource.get("labels"))
        self.partition = resource.get("cloud_partition") or None
        if self.provider == KUBERNETES:
            self.region = f"namespace: {_text(resource.get('namespace'))}"
        else:
            self.region = _text(resource.get("region")) or _text(cloud.get("region"))
        self.resource_details = _text(resource_data.get("details"))
        resource_metadata = resource_data.get("metadata")
        self.resource_metadata = (
            resource_metadata if isinstance(resource_metadata, dict) else {}
        )
        compliance = unmapped.get("compliance")
        self.compliance = compliance if isinstance(compliance, dict) else {}
        self.raw = {}

        self._report_metadata = {
            "provider": self.provider,
            "checkid": self.check_id,
            "checktitle": _text(finding_info.get("title")),
            "checktype": finding_info.get("types") or [],
            "servicename": self.service_name,
            "severity": severity,
            "resourcetype": self.resource_type,
            "description": _text(finding_info.get("desc")),
            "risk": _text(record.get("risk_details")),
            "relatedurl": _text(unmapped.get("related_url")),
            "remediation": {
                "recommendation": {
                    "text": _text((record.get("remediation") or {}).get("desc")),
                    "url": next(
                        iter((record.get("remediation") or {}).get("references") or []),
                        "",
                    ),
                },
                "code": {"cli": "", "nativeiac": "", "other": "", "terraform": ""},
            },
            "categories": unmapped.get("categories") or [],
            "dependson": unmapped.get("depends_on") or [],
            "relatedto": unmapped.get("related_to") or [],
            "additionalurls": unmapped.get("additional_urls") or [],
            "notes": _text(unmapped.get("notes")),
        }

    def get_metadata(self) -> dict:
        """Check metadata, preferring this server's SDK over the report's copy.

        The report keeps only part of the metadata (no resource group, no
        remediation code), so the SDK's is richer when it knows the check.
        """
        sdk_metadata = _sdk_checks_metadata(self.provider).get(self.check_id)
        if sdk_metadata is not None:
            return {**sdk_metadata, "severity": self.severity.value}
        return dict(self._report_metadata)


def parse_records(records) -> tuple[dict, int]:
    """Group valid findings by (provider type, account uid); count the rest."""
    groups: dict[tuple[str, str], list[OcsfFinding]] = {}
    invalid = 0
    for record in records:
        try:
            finding = OcsfFinding(record)
        except InvalidRecord:
            invalid += 1
            continue
        groups.setdefault((finding.provider, finding.account_uid), []).append(finding)
    return groups, invalid
