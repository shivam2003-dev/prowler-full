import json

from api.base_views import BaseRLSViewSet
from api.models import FindingTriage, FindingTriageNote
from api.rbac.permissions import Permissions, get_providers
from api.v1.serializers import BaseSerializerV1
from drf_spectacular.utils import extend_schema
from rest_framework import status
from rest_framework.exceptions import NotFound, ParseError, ValidationError
from rest_framework.parsers import BaseParser
from rest_framework.permissions import SAFE_METHODS
from rest_framework.response import Response
from rest_framework_json_api import serializers
from triage import services


class AttributesParser(BaseParser):
    """Read `data.attributes` of a JSON:API document.

    The UI sends triage updates without a resource `id` (the triage may not
    exist yet), which the strict JSON:API parser rejects for PATCH.
    """

    media_type = "application/vnd.api+json"

    def parse(self, stream, media_type=None, parser_context=None):
        try:
            document = json.loads(stream.read() or b"{}")
        except ValueError as error:
            raise ParseError("Malformed JSON.") from error
        data = document.get("data") if isinstance(document, dict) else None
        attributes = data.get("attributes") if isinstance(data, dict) else None
        if not isinstance(attributes, dict):
            raise ParseError("Send a JSON:API document with `data.attributes`.")
        return attributes


class FindingTriageSerializer(BaseSerializerV1):
    id = serializers.CharField(allow_null=True)
    status = serializers.CharField()
    finding_id = serializers.CharField()
    finding_uid = serializers.CharField()
    raw_finding_status = serializers.CharField(allow_null=True)
    triage_notes_count = serializers.IntegerField()
    has_note = serializers.BooleanField()
    current_note = serializers.CharField(allow_blank=True)
    note_id = serializers.CharField(allow_null=True)
    manual_pass_active = serializers.BooleanField(allow_null=True)
    manual_pass_evidence = serializers.CharField(allow_null=True)
    manual_pass_created_by_name = serializers.CharField(allow_null=True)
    manual_pass_created_at = serializers.DateTimeField(allow_null=True)
    manual_pass_expires_at = serializers.DateTimeField(allow_null=True)
    manual_pass_deactivated_at = serializers.DateTimeField(allow_null=True)

    class Meta:
        resource_name = "finding-triages"


class FindingTriageNoteSerializer(serializers.ModelSerializer):
    author_name = serializers.SerializerMethodField()

    class Meta:
        model = FindingTriageNote
        fields = ["id", "inserted_at", "updated_at", "body", "author_name"]

    def get_author_name(self, note) -> str | None:
        return note.author.name if note.author else None


class _TriageBaseView(BaseRLSViewSet):
    parser_classes = [AttributesParser]
    filter_backends = []
    pagination_class = None

    def set_required_permissions(self):
        # Mirrors mute rules: changing a finding's workflow is scan management.
        self.required_permissions = (
            [] if self.request.method in SAFE_METHODS else [Permissions.MANAGE_SCANS]
        )

    def get_queryset(self):
        return FindingTriage.objects.filter(tenant_id=self.request.tenant_id)

    def _providers(self):
        role = self.user_role
        return None if role.unlimited_visibility else get_providers(role)

    def _finding(self, finding_uid: str):
        finding = services.latest_finding(
            str(self.request.tenant_id), finding_uid, self._providers()
        )
        if finding is None:
            raise NotFound("Finding not found.")
        return finding

    def _triage_by_uid(self, finding_uid: str):
        return self.get_queryset().filter(finding_uid=finding_uid).first()

    def _triage_by_id(self, triage_id):
        triage = self.get_queryset().filter(id=triage_id).first()
        if triage is None:
            raise NotFound("Triage not found.")
        # A triage is visible only through a finding the role can see.
        return triage, self._finding(triage.finding_uid)

    def _detail_response(self, finding, triage, response_status=status.HTTP_200_OK):
        data = services.detail(str(self.request.tenant_id), finding, triage)
        return Response(
            data=FindingTriageSerializer(data, context={"request": self.request}).data,
            status=response_status,
        )

    def _apply(self, finding, triage):
        try:
            triage = services.update(
                str(self.request.tenant_id),
                finding,
                triage,
                self.request.user,
                self.request.data.get("status"),
                self.request.data.get("note"),
            )
        except services.TriageError as error:
            raise ValidationError({error.pointer.rsplit("/", 1)[-1]: [error.detail]})
        return self._detail_response(finding, triage)

    def _notes_response(self, triage):
        notes = (
            triage.notes.select_related("author").order_by("-id")
            if triage
            else FindingTriageNote.objects.none()
        )
        return Response(
            data=FindingTriageNoteSerializer(
                notes, many=True, context={"request": self.request}
            ).data
        )


@extend_schema(tags=["Findings"])
class FindingTriageByUidView(_TriageBaseView):
    """`/findings/<uid>/triage`: works whether or not a triage exists yet."""

    resource_name = "finding-triages"

    def retrieve_triage(self, request, finding_uid):
        return self._detail_response(
            self._finding(finding_uid), self._triage_by_uid(finding_uid)
        )

    def update_triage(self, request, finding_uid):
        return self._apply(self._finding(finding_uid), self._triage_by_uid(finding_uid))

    def list_notes(self, request, finding_uid):
        self._finding(finding_uid)
        return self._notes_response(self._triage_by_uid(finding_uid))


@extend_schema(tags=["Findings"])
class FindingTriageView(_TriageBaseView):
    """`/finding-triages/<id>`."""

    resource_name = "finding-triages"

    def retrieve_triage(self, request, pk):
        triage, finding = self._triage_by_id(pk)
        return self._detail_response(finding, triage)

    def update_triage(self, request, pk):
        triage, finding = self._triage_by_id(pk)
        return self._apply(finding, triage)

    def list_notes(self, request, pk):
        triage, _ = self._triage_by_id(pk)
        return self._notes_response(triage)


@extend_schema(tags=["Findings"])
class FindingTriageNoteView(_TriageBaseView):
    """Edit or delete one note, reached through either triage path."""

    resource_name = "finding-triage-notes"

    def _note(self, note_id, pk=None, finding_uid=None):
        triage = self._triage_by_id(pk)[0] if pk else self._triage_by_uid(finding_uid)
        if finding_uid:
            self._finding(finding_uid)
        note = triage.notes.filter(id=note_id).first() if triage else None
        if note is None:
            raise NotFound("Note not found.")
        return note

    def update_note(self, request, note_id, pk=None, finding_uid=None):
        note = self._note(note_id, pk, finding_uid)
        try:
            body = services._clean_note(request.data.get("body"))
        except services.TriageError as error:
            raise ValidationError({"body": [error.detail]})
        if body is None:
            raise ValidationError({"body": ["A note cannot be empty."]})
        note.body = body
        note.save(update_fields=["body", "updated_at"])
        return Response(
            data=FindingTriageNoteSerializer(note, context={"request": request}).data
        )

    def delete_note(self, request, note_id, pk=None, finding_uid=None):
        self._note(note_id, pk, finding_uid).delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
