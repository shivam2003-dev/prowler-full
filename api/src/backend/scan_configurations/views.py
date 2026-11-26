from api.base_views import BaseRLSViewSet
from api.models import Provider, ScanConfiguration
from api.rbac.permissions import Permissions, get_providers
from django_filters.rest_framework import FilterSet
from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework import status
from rest_framework.response import Response
from scan_configurations.serializers import (
    ScanConfigurationSerializer,
    ScanConfigurationUpdateSerializer,
    ScanConfigurationWriteSerializer,
)


class ScanConfigurationFilter(FilterSet):
    class Meta:
        model = ScanConfiguration
        fields = {
            "id": ["exact", "in"],
            "name": ["exact", "icontains"],
            "inserted_at": ["gte", "lte"],
            "updated_at": ["gte", "lte"],
        }


@extend_schema_view(
    list=extend_schema(
        tags=["Scan Configurations"], summary="List scan configurations"
    ),
    retrieve=extend_schema(
        tags=["Scan Configurations"], summary="Retrieve a scan configuration"
    ),
    create=extend_schema(
        tags=["Scan Configurations"],
        summary="Create a scan configuration",
        request=ScanConfigurationWriteSerializer,
        responses={201: ScanConfigurationSerializer},
    ),
    partial_update=extend_schema(
        tags=["Scan Configurations"],
        summary="Update a scan configuration",
        request=ScanConfigurationUpdateSerializer,
        responses={200: ScanConfigurationSerializer},
    ),
    destroy=extend_schema(
        tags=["Scan Configurations"],
        summary="Delete a scan configuration",
        description="Its providers go back to the default Prowler configuration.",
    ),
)
class ScanConfigurationViewSet(BaseRLSViewSet):
    queryset = ScanConfiguration.objects.all()
    serializer_class = ScanConfigurationSerializer
    filterset_class = ScanConfigurationFilter
    http_method_names = ["get", "post", "patch", "delete"]
    search_fields = ["name"]
    ordering = ["name"]
    ordering_fields = ["name", "inserted_at", "updated_at"]
    required_permissions = [Permissions.MANAGE_SCANS]

    def _provider_queryset(self):
        role = self.user_role
        if role.unlimited_visibility:
            return Provider.objects.filter(tenant_id=self.request.tenant_id)
        return get_providers(role)

    def get_queryset(self):
        return ScanConfiguration.objects.filter(
            tenant_id=self.request.tenant_id
        ).prefetch_related("providers")

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context["provider_queryset"] = self._provider_queryset()
        return context

    def get_serializer_class(self):
        if self.action == "create":
            return ScanConfigurationWriteSerializer
        if self.action == "partial_update":
            return ScanConfigurationUpdateSerializer
        return super().get_serializer_class()

    def _read_response(self, scan_configuration, response_status):
        scan_configuration = self.get_queryset().get(id=scan_configuration.id)
        serializer = ScanConfigurationSerializer(
            scan_configuration, context=self.get_serializer_context()
        )
        return Response(data=serializer.data, status=response_status)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return self._read_response(serializer.save(), status.HTTP_201_CREATED)

    def partial_update(self, request, *args, **kwargs):
        serializer = self.get_serializer(
            self.get_object(), data=request.data, partial=True
        )
        serializer.is_valid(raise_exception=True)
        return self._read_response(serializer.save(), status.HTTP_200_OK)
