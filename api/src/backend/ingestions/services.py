"""Turn an uploaded Prowler OCSF report into providers, scans and findings."""

import json
import os
import time
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path

from api.db_utils import rls_transaction
from api.models import Ingestion, MuteRule, Provider, Scan, StateChoices
from celery.utils.log import get_task_logger
from config.django.base import DJANGO_FINDINGS_BATCH_SIZE, DJANGO_TMP_OUTPUT_DIRECTORY
from django.conf import settings
from ingestions.ocsf import parse_records

logger = get_task_logger(__name__)

SCAN_NAME = "CLI import"


class InvalidReport(ValueError):
    """The upload is not a Prowler OCSF finding report."""


def report_path(tenant_id: str, ingestion_id: str) -> Path:
    return (
        Path(DJANGO_TMP_OUTPUT_DIRECTORY)
        / str(tenant_id)
        / "ingestions"
        / f"{ingestion_id}.ocsf.json"
    )


def store_report(tenant_id: str, ingestion_id: str, upload) -> Path:
    """Write the upload where the worker can read it (shared output volume)."""
    path = report_path(tenant_id, ingestion_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as destination:
        for chunk in upload.chunks():
            destination.write(chunk)
    return path


def looks_like_ocsf_report(upload) -> bool:
    """Cheap check before queueing: Prowler writes a JSON array of objects."""
    head = upload.read(4096).lstrip()
    upload.seek(0)
    return head.startswith(b"[")


def load_report(path: Path) -> list:
    try:
        with open(path, "rb") as report:
            records = json.load(report)
    except (OSError, ValueError) as error:
        raise InvalidReport("The report is not valid JSON.") from error
    if not isinstance(records, list):
        raise InvalidReport("The report must be a JSON array of OCSF findings.")
    return records


def _get_or_create_provider(tenant_id: str, provider_type: str, uid: str, alias: str):
    provider = Provider.all_objects.filter(
        tenant_id=tenant_id, provider=provider_type, uid=uid, is_deleted=False
    ).first()
    if provider is not None:
        return provider
    provider = Provider(
        tenant_id=tenant_id,
        provider=provider_type,
        uid=uid,
        alias=(alias or f"{uid} (imported)")[:100],
    )
    # Applies the per-provider uid validators, so a malformed account id is
    # rejected here instead of creating a provider the UI cannot manage.
    provider.full_clean(exclude=["tenant"])
    provider.save()
    return provider


def _import_group(tenant_id: str, provider, findings: list, on_progress) -> Scan:
    """Persist one provider's findings as a completed scan."""
    # Imported lazily: tasks.jobs.scan pulls in the whole SDK scan machinery.
    from tasks.jobs import scan as scan_job

    started = time.time()
    with rls_transaction(tenant_id):
        scan = Scan.objects.create(
            tenant_id=tenant_id,
            provider=provider,
            name=SCAN_NAME,
            trigger=Scan.TriggerChoices.IMPORTED,
            state=StateChoices.EXECUTING,
            started_at=datetime.now(tz=UTC),
        )
        mute_rules_cache = {
            uid: reason
            for finding_uids, reason in MuteRule.objects.filter(
                tenant_id=tenant_id, enabled=True
            ).values_list("finding_uids", "reason")
            for uid in finding_uids
        }

    scan_id = str(scan.id)
    caches = {
        "resource_cache": {},
        "tag_cache": {},
        "last_status_cache": {},
        "resource_failed_findings_cache": defaultdict(int),
        "unique_resources": set(),
        "scan_resource_cache": set(),
        "scan_categories_cache": {},
        "scan_resource_groups_cache": {},
        "group_resources_cache": {},
    }
    try:
        for start in range(0, len(findings), DJANGO_FINDINGS_BATCH_SIZE):
            batch = findings[start : start + DJANGO_FINDINGS_BATCH_SIZE]
            scan_job._process_finding_micro_batch(
                tenant_id=tenant_id,
                findings_batch=batch,
                scan_instance=scan,
                provider_instance=provider,
                mute_rules_cache=mute_rules_cache,
                **caches,
            )
            on_progress(len(batch))

        scan_job._store_final_scan_summaries(
            tenant_id,
            scan_id,
            caches["scan_resource_cache"],
            caches["scan_categories_cache"],
        )
        resources_to_update = []
        for uid, failed_count in caches["resource_failed_findings_cache"].items():
            resource = caches["resource_cache"].get(uid)
            if resource is not None:
                resource.failed_findings_count = failed_count
                resources_to_update.append(resource)
        if resources_to_update:
            scan_job._bulk_update_resource_failed_findings_counts(
                tenant_id=tenant_id,
                scan_id=scan_id,
                resources_to_update=resources_to_update,
            )
        state = StateChoices.COMPLETED
    except Exception:
        state = StateChoices.FAILED
        raise
    finally:
        with rls_transaction(tenant_id):
            scan.state = state
            scan.progress = 100 if state == StateChoices.COMPLETED else scan.progress
            scan.duration = time.time() - started
            scan.completed_at = datetime.now(tz=UTC)
            scan.unique_resource_count = len(caches["unique_resources"])
            scan.save(
                update_fields=[
                    "state",
                    "progress",
                    "duration",
                    "completed_at",
                    "unique_resource_count",
                    "updated_at",
                ]
            )
    return scan


def process_ingestion(tenant_id: str, ingestion_id: str) -> dict:
    """Import the stored report. Returns the scans created, per provider."""
    path = report_path(tenant_id, ingestion_id)
    with rls_transaction(tenant_id):
        ingestion = Ingestion.objects.get(id=ingestion_id)
        ingestion.status = Ingestion.StatusChoices.PROCESSING
        ingestion.save(update_fields=["status", "updated_at"])

    imported: list[dict] = []
    try:
        records = load_report(path)
        groups, invalid = parse_records(records)
        with rls_transaction(tenant_id):
            ingestion.total_records = len(records)
            ingestion.invalid_records = invalid
            ingestion.save(
                update_fields=["total_records", "invalid_records", "updated_at"]
            )
        if not groups:
            raise InvalidReport("The report has no Prowler OCSF findings to import.")

        def on_progress(count: int) -> None:
            with rls_transaction(tenant_id):
                ingestion.processed_records += count
                ingestion.save(update_fields=["processed_records", "updated_at"])

        for (provider_type, account_uid), findings in groups.items():
            try:
                with rls_transaction(tenant_id):
                    provider = _get_or_create_provider(
                        tenant_id, provider_type, account_uid, findings[0].account_name
                    )
            except Exception as error:  # noqa: BLE001 - e.g. malformed account id
                logger.warning(
                    "Ingestion %s: skipping %s %s: %s",
                    ingestion_id,
                    provider_type,
                    account_uid,
                    error,
                )
                with rls_transaction(tenant_id):
                    ingestion.invalid_records += len(findings)
                    ingestion.save(update_fields=["invalid_records", "updated_at"])
                continue

            scan = _import_group(tenant_id, provider, findings, on_progress)
            imported.append({"scan_id": str(scan.id), "provider_id": str(provider.id)})

        if not imported:
            raise InvalidReport("None of the report's accounts could be imported.")

        with rls_transaction(tenant_id):
            ingestion.status = Ingestion.StatusChoices.COMPLETED
            ingestion.scan_ids = [item["scan_id"] for item in imported]
            ingestion.save(update_fields=["status", "scan_ids", "updated_at"])
    except Exception as error:
        logger.exception("Ingestion %s failed", ingestion_id)
        with rls_transaction(tenant_id):
            ingestion.status = Ingestion.StatusChoices.FAILED
            ingestion.error = str(error) or error.__class__.__name__
            ingestion.scan_ids = [item["scan_id"] for item in imported]
            ingestion.save(update_fields=["status", "error", "scan_ids", "updated_at"])
        if not isinstance(error, InvalidReport):
            raise
    finally:
        try:
            os.remove(path)
        except OSError:
            pass
    return {"scans": imported}


def max_upload_bytes() -> int:
    return settings.INGESTION_MAX_UPLOAD_BYTES
