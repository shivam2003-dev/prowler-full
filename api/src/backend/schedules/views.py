"""Advanced scan schedules (`/schedules`, `/schedules/<provider_id>`, `/schedules/bulk`).

The id of a schedule is its provider's id: one schedule per provider.
"""

from api.base_views import BaseRLSViewSet
from api.models import Provider
from api.rbac.permissions import Permissions, get_providers
from api.v1.serializers import ProviderIncludeSerializer
from drf_spectacular.utils import extend_schema
from realtime.views import DocumentParser
from rest_framework import status
from rest_framework.exceptions import NotFound, ValidationError
from rest_framework.permissions import SAFE_METHODS
from rest_framework.response import Response
from schedules import services

SORTS = {
    "next_scan_at": lambda row: (row["next_scan_at"] is None, row["next_scan_at"] or 0),
    "last_scan_at": lambda row: (row["last_scan_at"] is None, row["last_scan_at"] or 0),
    "provider": lambda row: row["_alias"],
}


@extend_schema(tags=["Schedule"], exclude=True)
class ScheduleAdvancedViewSet(BaseRLSViewSet):
    resource_name = False
    parser_classes = [DocumentParser]
    filter_backends = []
    pagination_class = None

    def set_required_permissions(self):
        self.required_permissions = (
            [] if self.request.method in SAFE_METHODS else [Permissions.MANAGE_SCANS]
        )

    def get_queryset(self):
        role = self.user_role
        providers = Provider.objects.filter(tenant_id=self.request.tenant_id)
        if not role.unlimited_visibility:
            providers = providers.filter(id__in=get_providers(role).values("id"))
        return providers

    def _provider(self, pk) -> Provider:
        provider = self.get_queryset().filter(id=pk).first()
        if provider is None:
            raise NotFound("Provider not found.")
        return provider

    def _resource(self, provider: Provider, described: dict) -> dict:
        attributes = {k: v for k, v in described.items() if not k.startswith("_")}
        return {
            "type": "schedules",
            "id": str(provider.id),
            "attributes": attributes,
            "relationships": {
                "provider": {"data": {"type": "providers", "id": str(provider.id)}}
            },
        }

    def _included(self, providers) -> list:
        data = ProviderIncludeSerializer(
            providers, many=True, context={"request": self.request}
        ).data
        return [
            {
                "type": "providers",
                "id": str(row["id"]),
                "attributes": {k: v for k, v in row.items() if k != "id"},
            }
            for row in data
        ]

    def _wants_provider(self) -> bool:
        return "provider" in self.request.query_params.get("include", "").split(",")

    def list_schedules(self, request):
        rows = []
        for provider in self.get_queryset().order_by("alias", "uid"):
            described = services.describe(provider)
            rows.append(
                {
                    **described,
                    "_provider": provider,
                    "_alias": (provider.alias or provider.uid).lower(),
                }
            )
        if request.query_params.get("filter[configured]") == "true":
            rows = [row for row in rows if row["_configured"]]
        if provider_types := request.query_params.get("filter[provider_type__in]"):
            wanted = set(provider_types.split(","))
            rows = [row for row in rows if row["_provider"].provider in wanted]
        sort = request.query_params.get("sort", "")
        if sort.lstrip("-") in SORTS:
            rows.sort(key=SORTS[sort.lstrip("-")], reverse=sort.startswith("-"))
        try:
            number = max(int(request.query_params.get("page[number]", 1)), 1)
            size = min(max(int(request.query_params.get("page[size]", 10)), 1), 100)
        except ValueError as error:
            raise ValidationError({"page": ["Page values must be numbers."]}) from error
        page = rows[(number - 1) * size : number * size]
        document = {
            "data": [self._resource(row["_provider"], row) for row in page],
            "meta": {
                "pagination": {
                    "page": number,
                    "pages": max((len(rows) + size - 1) // size, 1),
                    "count": len(rows),
                }
            },
        }
        if self._wants_provider():
            document["included"] = self._included([row["_provider"] for row in page])
        return Response(document)

    def retrieve_schedule(self, request, pk):
        provider = self._provider(pk)
        document = {"data": self._resource(provider, services.describe(provider))}
        if self._wants_provider():
            document["included"] = self._included([provider])
        return Response(document)

    def update_schedule(self, request, pk):
        provider = self._provider(pk)
        try:
            services.save(
                str(request.tenant_id), provider, request.data.get("attributes") or {}
            )
        except services.ScheduleError as error:
            raise ValidationError({error.field: [error.detail]}) from error
        return Response({"data": self._resource(provider, services.describe(provider))})

    def delete_schedule(self, request, pk):
        services.remove(self._provider(pk))
        return Response(status=status.HTTP_204_NO_CONTENT)

    def bulk(self, request):
        attributes = request.data.get("attributes") or {}
        provider_ids = attributes.get("provider_ids") or []
        if not isinstance(provider_ids, list) or not provider_ids:
            raise ValidationError({"provider_ids": ["Select at least one provider."]})
        try:
            services.validate(attributes.get("schedule") or {})
        except services.ScheduleError as error:
            raise ValidationError({error.field: [error.detail]}) from error
        providers = {
            str(p.id): p for p in self.get_queryset().filter(id__in=provider_ids)
        }
        updated, failed = [], []
        for provider_id in dict.fromkeys(map(str, provider_ids)):
            provider = providers.get(provider_id)
            if provider is None:
                failed.append({"id": provider_id, "error": "Provider not found."})
                continue
            services.save(str(request.tenant_id), provider, attributes["schedule"])
            updated.append(provider_id)
        return Response({"data": {"updated": updated, "failed": failed}})
