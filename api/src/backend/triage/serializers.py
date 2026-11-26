"""Triage fields for list serializers, loaded once per page."""

from api.models import Finding
from rest_framework import serializers as drf_serializers
from rest_framework_json_api import serializers
from triage import services


def _get(item, key):
    return item.get(key) if isinstance(item, dict) else getattr(item, key, None)


class TriageListSerializer(drf_serializers.ListSerializer):
    """Looks up the triage of every row of the page in two queries."""

    def to_representation(self, data):
        items = list(data.all() if hasattr(data, "all") else data)
        self.child._triage_rows = self.child.load_triage_rows(items)
        try:
            return super().to_representation(items)
        finally:
            self.child._triage_rows = None


class TriageFieldsMixin(metaclass=serializers.SerializerMetaclass):
    """Adds `finding_uid` and `triage_*` attributes to a finding-like row."""

    finding_uid = serializers.SerializerMethodField()
    triage_id = serializers.SerializerMethodField()
    triage_status = serializers.SerializerMethodField()
    triage_notes_count = serializers.SerializerMethodField()
    triage_has_note = serializers.SerializerMethodField()

    TRIAGE_FIELDS = [
        "finding_uid",
        "triage_id",
        "triage_status",
        "triage_notes_count",
        "triage_has_note",
    ]

    _triage_rows = None

    # Subclasses describe how to read a row.
    def row_key(self, item):
        raise NotImplementedError

    def row_finding_status(self, item):
        return _get(item, "status")

    def row_uids(self, items) -> dict:
        """Map of row key -> finding uid."""
        raise NotImplementedError

    def load_triage_rows(self, items) -> dict:
        uids = self.row_uids(items)
        tenant_id = next(
            (_get(item, "tenant_id") for item in items if _get(item, "tenant_id")),
            None,
        )
        summaries = services.summaries_by_uid(tenant_id, uids.values())
        return {key: (uid, summaries.get(uid)) for key, uid in uids.items()}

    def _triage_row(self, item):
        rows = self._triage_rows
        if rows is None:
            rows = self.load_triage_rows([item])
        uid, summary = rows.get(self.row_key(item), (None, None))
        return uid, services.triage_fields(summary, self.row_finding_status(item))

    def get_finding_uid(self, item) -> str | None:
        return self._triage_row(item)[0]

    def get_triage_id(self, item) -> str | None:
        return self._triage_row(item)[1]["triage_id"]

    def get_triage_status(self, item) -> str:
        return self._triage_row(item)[1]["triage_status"]

    def get_triage_notes_count(self, item) -> int:
        return self._triage_row(item)[1]["triage_notes_count"]

    def get_triage_has_note(self, item) -> bool:
        return self._triage_row(item)[1]["triage_has_note"]


class FindingRowTriageMixin(TriageFieldsMixin):
    """For Finding model instances, which carry their own uid."""

    def row_key(self, item):
        return item.id

    def row_uids(self, items) -> dict:
        return {item.id: item.uid for item in items}


class FindingIdRowTriageMixin(TriageFieldsMixin):
    """For dict rows that only know the `finding_id`."""

    def row_key(self, item):
        return str(_get(item, "finding_id"))

    def row_uids(self, items) -> dict:
        finding_ids = {_get(item, "finding_id") for item in items} - {None}
        # Runs inside the request's RLS transaction, which scopes the tenant.
        return {
            str(finding_id): uid
            for finding_id, uid in Finding.all_objects.filter(
                id__in=finding_ids
            ).values_list("id", "uid")
        }
