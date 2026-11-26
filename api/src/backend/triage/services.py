"""Finding triage: workflow status and notes, plus its automatic transitions."""

from datetime import UTC, datetime, timedelta

from api.models import Finding, FindingTriage, FindingTriageNote, StatusChoices
from django.db.models import Count, OuterRef, Subquery

Status = FindingTriage.StatusChoices

NOTE_MAX_LENGTH = 500
MANUAL_PASS_TTL = timedelta(days=90)
# Statuses a person may set. RESOLVED and REOPENED belong to automation, except
# RESOLVED through a manual pass of a MANUAL finding.
MANUAL_STATUSES = frozenset(
    {
        Status.OPEN,
        Status.UNDER_REVIEW,
        Status.REMEDIATING,
        Status.RISK_ACCEPTED,
        Status.FALSE_POSITIVE,
    }
)


class TriageError(ValueError):
    def __init__(self, detail: str, pointer: str = "/data/attributes/status"):
        super().__init__(detail)
        self.detail = detail
        self.pointer = pointer


def latest_finding(tenant_id: str, finding_uid: str, providers=None):
    findings = Finding.all_objects.filter(tenant_id=tenant_id, uid=finding_uid)
    if providers is not None:
        findings = findings.filter(scan__provider__in=providers)
    return findings.order_by("-inserted_at").only("id", "uid", "status").first()


def default_status(finding_status: str | None) -> str:
    return Status.RESOLVED if finding_status == StatusChoices.PASS else Status.OPEN


def detail(tenant_id: str, finding, triage: FindingTriage | None) -> dict:
    """The `finding-triages` representation of a finding's triage."""
    notes = (
        list(triage.notes.order_by("-id").values("id", "body")[:1]) if triage else []
    )
    notes_count = triage.notes.count() if triage else 0
    latest_note = notes[0] if notes else None
    return {
        "id": str(triage.id) if triage else None,
        "status": triage.status if triage else default_status(finding.status),
        "finding_id": str(finding.id),
        "finding_uid": finding.uid,
        "raw_finding_status": finding.status,
        "triage_notes_count": notes_count,
        "has_note": notes_count > 0,
        "current_note": latest_note["body"] if latest_note else "",
        "note_id": str(latest_note["id"]) if latest_note else None,
        "manual_pass_active": triage.manual_pass_active if triage else None,
        "manual_pass_evidence": triage.manual_pass_evidence if triage else None,
        "manual_pass_created_by_name": (
            triage.manual_pass_created_by.name
            if triage and triage.manual_pass_created_by
            else None
        ),
        "manual_pass_created_at": triage.manual_pass_created_at if triage else None,
        "manual_pass_expires_at": triage.manual_pass_expires_at if triage else None,
        "manual_pass_deactivated_at": (
            triage.manual_pass_deactivated_at if triage else None
        ),
    }


def _clean_note(note) -> str | None:
    if note is None:
        return None
    if not isinstance(note, str):
        raise TriageError("A note must be text.", "/data/attributes/note")
    note = note.strip()
    if len(note) > NOTE_MAX_LENGTH:
        raise TriageError(
            f"A note cannot exceed {NOTE_MAX_LENGTH} characters.",
            "/data/attributes/note",
        )
    return note or None


def update(
    tenant_id: str, finding, triage: FindingTriage | None, user, status, note
) -> FindingTriage:
    """Apply a status and/or a first note. Creates the triage when missing."""
    note = _clean_note(note)
    if status is None and note is None:
        raise TriageError("Send a status, a note, or both.", "/data/attributes")
    if status is not None and status not in Status.values:
        raise TriageError(f"Unknown triage status {status!r}.")

    now = datetime.now(tz=UTC)
    if triage is None:
        triage = FindingTriage(
            tenant_id=tenant_id,
            finding_uid=finding.uid,
            status=default_status(finding.status),
        )

    if status == Status.RESOLVED and status != triage.status:
        if finding.status != StatusChoices.MANUAL:
            raise TriageError(
                "Only a MANUAL finding can be resolved by hand. Others resolve "
                "when a scan finds them passing."
            )
        if note is None:
            raise TriageError(
                "Fresh evidence is required to pass a MANUAL finding.",
                "/data/attributes/note",
            )
        triage.manual_pass_active = True
        triage.manual_pass_evidence = note
        triage.manual_pass_created_by = user
        triage.manual_pass_created_at = now
        triage.manual_pass_expires_at = now + MANUAL_PASS_TTL
        triage.manual_pass_deactivated_at = None
    elif status is not None and status != triage.status:
        if triage.status == Status.RESOLVED:
            raise TriageError(
                "Triage status is managed automatically once the finding is resolved."
            )
        if status not in MANUAL_STATUSES:
            raise TriageError(f"{Status(status).label} is set automatically.")

    if status is not None:
        triage.status = status
    triage.updated_by = user
    triage.save()
    if note is not None:
        FindingTriageNote.objects.create(
            tenant_id=tenant_id, triage=triage, body=note, author=user
        )
    return triage


def summaries_by_uid(tenant_id: str | None, finding_uids) -> dict[str, dict]:
    """Triage fields of many findings at once, for list endpoints."""
    finding_uids = {uid for uid in finding_uids if uid}
    if not finding_uids:
        return {}
    rows = FindingTriage.objects.filter(finding_uid__in=finding_uids)
    # Without a tenant the request's RLS transaction scopes the rows.
    if tenant_id:
        rows = rows.filter(tenant_id=tenant_id)
    rows = rows.annotate(notes_total=Count("notes"))
    return {
        row.finding_uid: {
            "triage_id": str(row.id),
            "triage_status": row.status,
            "triage_notes_count": row.notes_total,
            "triage_has_note": row.notes_total > 0,
        }
        for row in rows
    }


def triage_fields(summary: dict | None, finding_status: str | None) -> dict:
    if summary is not None:
        return summary
    return {
        "triage_id": None,
        "triage_status": default_status(finding_status),
        "triage_notes_count": 0,
        "triage_has_note": False,
    }


def apply_scan_results(tenant_id: str, scan_id: str) -> dict:
    """Move triages to follow what a finished scan observed.

    - RESOLVED findings that fail again become REOPENED.
    - Findings now passing become RESOLVED.
    - Manual passes past their expiry are withdrawn; the finding is REOPENED.
    Must run inside the tenant's RLS transaction.
    """
    now = datetime.now(tz=UTC)
    scan_status = Finding.all_objects.filter(
        tenant_id=tenant_id, scan_id=scan_id, uid=OuterRef("finding_uid")
    ).values("status")[:1]
    triages = FindingTriage.objects.filter(
        tenant_id=tenant_id,
        finding_uid__in=Finding.all_objects.filter(
            tenant_id=tenant_id, scan_id=scan_id
        ).values("uid"),
    ).annotate(scan_status=Subquery(scan_status))

    changed = {"reopened": 0, "resolved": 0, "manual_pass_expired": 0}
    for triage in triages:
        manual_pass_live = bool(triage.manual_pass_active) and (
            triage.manual_pass_expires_at is None or triage.manual_pass_expires_at > now
        )
        update_fields = ["status", "updated_at"]
        if triage.manual_pass_active and not manual_pass_live:
            triage.manual_pass_active = False
            triage.manual_pass_deactivated_at = now
            triage.status = Status.REOPENED
            update_fields += ["manual_pass_active", "manual_pass_deactivated_at"]
            changed["manual_pass_expired"] += 1
        elif triage.scan_status == StatusChoices.FAIL:
            if triage.status != Status.RESOLVED:
                continue
            triage.status = Status.REOPENED
            changed["reopened"] += 1
        elif triage.scan_status == StatusChoices.PASS:
            if triage.status == Status.RESOLVED:
                continue
            triage.status = Status.RESOLVED
            changed["resolved"] += 1
        else:
            continue
        triage.save(update_fields=update_fields)
    return changed
