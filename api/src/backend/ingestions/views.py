from api.base_views import BaseRLSViewSet
from api.models import Ingestion
from api.rbac.permissions import Permissions
from api.v1.serializers import RLSSerializer
from django.db import transaction
from django_filters.rest_framework import ChoiceFilter, FilterSet
from drf_spectacular.utils import extend_schema, extend_schema_view
from ingestions import services
from rest_framework import status
from rest_framework.exceptions import APIException, ValidationError
from rest_framework.parsers import MultiPartParser
from rest_framework.response import Response
from rest_framework_json_api import serializers
from tasks.tasks import process_ingestion_task


class FileTooLarge(APIException):
    status_code = status.HTTP_413_REQUEST_ENTITY_TOO_LARGE
    default_detail = "The selected file exceeds the allowed upload size."
    default_code = "file_too_large"


class IngestionSerializer(RLSSerializer):
    summary = serializers.SerializerMethodField()

    class Meta:
        model = Ingestion
        fields = [
            "id",
            "inserted_at",
            "updated_at",
            "status",
            "file_name",
            "summary",
            "error",
            "scan_ids",
        ]

    def get_summary(self, ingestion) -> dict:
        return {
            "total": ingestion.total_records,
            "processed": ingestion.processed_records,
            "invalid": ingestion.invalid_records,
        }


class IngestionFilter(FilterSet):
    status = ChoiceFilter(choices=Ingestion.StatusChoices.choices)

    class Meta:
        model = Ingestion
        fields = {"id": ["exact", "in"], "inserted_at": ["gte", "lte"]}


@extend_schema_view(
    list=extend_schema(tags=["Ingestions"], summary="List finding imports"),
    retrieve=extend_schema(
        tags=["Ingestions"], summary="Retrieve the status of a finding import"
    ),
    create=extend_schema(
        tags=["Ingestions"],
        summary="Import a Prowler CLI OCSF report",
        description="Upload a `.ocsf.json` report produced by the Prowler CLI as "
        "multipart field `file`. It is imported in the background into one scan "
        "per account found in the report.",
        request={"multipart/form-data": {"type": "object"}},
        responses={202: IngestionSerializer},
    ),
)
class IngestionViewSet(BaseRLSViewSet):
    queryset = Ingestion.objects.all()
    serializer_class = IngestionSerializer
    filterset_class = IngestionFilter
    http_method_names = ["get", "post"]
    parser_classes = [MultiPartParser]
    ordering = ["-inserted_at"]
    ordering_fields = ["inserted_at", "updated_at", "status"]
    required_permissions = [Permissions.MANAGE_SCANS]

    def get_queryset(self):
        return Ingestion.objects.filter(tenant_id=self.request.tenant_id)

    def create(self, request, *args, **kwargs):
        upload = request.FILES.get("file")
        if upload is None:
            raise ValidationError({"file": ["Upload the report as `file`."]})
        if upload.size > services.max_upload_bytes():
            raise FileTooLarge()
        if not services.looks_like_ocsf_report(upload):
            raise ValidationError(
                {"file": ["The report is not a valid Prowler OCSF finding report."]}
            )

        tenant_id = str(request.tenant_id)
        ingestion = Ingestion.objects.create(
            tenant_id=tenant_id,
            file_name=(upload.name or "")[:255],
            created_by=request.user,
        )
        services.store_report(tenant_id, str(ingestion.id), upload)
        transaction.on_commit(
            lambda: process_ingestion_task.apply_async(
                kwargs={"tenant_id": tenant_id, "ingestion_id": str(ingestion.id)}
            )
        )
        return Response(
            data=self.get_serializer(ingestion).data, status=status.HTTP_202_ACCEPTED
        )
