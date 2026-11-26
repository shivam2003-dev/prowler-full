from api.base_views import BaseRLSViewSet
from api.models import (
    ComplianceWatchlistEntry,
    Finding,
    Provider,
    ProviderGroupMembership,
    Task,
)
from api.rbac.permissions import get_providers
from api.v1.serializers import TaskSerializer
from compliance_watchlist import cross_provider, services
from compliance_watchlist import pdf as compliance_pdf
from django.db import transaction
from django.http import FileResponse
from drf_spectacular.utils import extend_schema
from realtime.views import DocumentParser
from rest_framework import status
from rest_framework.exceptions import NotFound, ValidationError
from rest_framework.response import Response


def _entry_doc(entry):
    return {
        "type": "compliance-watchlist-entries",
        "id": str(entry.id),
        "attributes": {
            "compliance_id": entry.compliance_id,
            "provider_type": entry.provider_type,
            "inserted_at": entry.inserted_at,
        },
    }


@extend_schema(tags=["Compliance Overview"], exclude=True)
class ComplianceWatchlistViewSet(BaseRLSViewSet):
    """Following a framework is a view preference, open to every role."""

    resource_name = False
    parser_classes = [DocumentParser]
    filter_backends = []
    pagination_class = None

    def get_queryset(self):
        return ComplianceWatchlistEntry.objects.filter(tenant_id=self.request.tenant_id)

    def catalog(self, request):
        tenant_id = str(request.tenant_id)
        eligible = services.eligible_provider_types(tenant_id)
        wanted = [
            v
            for v in request.query_params.get("filter[provider_type__in]", "").split(
                ","
            )
            if v
        ]
        types = [t for t in eligible if not wanted or t in wanted]
        rows = services.catalog(tenant_id, types)
        if search := request.query_params.get("filter[search]", "").lower():
            rows = [
                r
                for r in rows
                if search in r["name"].lower() or search in r["compliance_id"]
            ]
        if request.query_params.get("filter[in_watchlist]") == "true":
            rows = [r for r in rows if r["in_watchlist"]]
        try:
            number = max(int(request.query_params.get("page[number]", 1)), 1)
            size = min(max(int(request.query_params.get("page[size]", 100)), 1), 500)
        except ValueError as error:
            raise ValidationError({"page": ["Page values must be numbers."]}) from error
        page = rows[(number - 1) * size : number * size]
        return Response(
            {
                "data": [
                    {
                        "type": "compliance-catalog-entries",
                        "id": f"{row['compliance_id']}:{row['provider_type']}",
                        "attributes": row,
                    }
                    for row in page
                ],
                "meta": {
                    "pagination": {
                        "page": number,
                        "pages": max((len(rows) + size - 1) // size, 1),
                        "count": len(rows),
                    },
                    "total_entries": len(rows),
                    "watchlist_count": self.get_queryset().count(),
                    "eligible_provider_types": eligible,
                },
            }
        )

    def _target(self, item):
        if not isinstance(item, dict):
            raise ValidationError(
                {
                    "attributes": [
                        "Each framework needs compliance_id and provider_type."
                    ]
                }
            )
        compliance_id = str(item.get("compliance_id") or "")
        provider_type = str(item.get("provider_type") or "")
        if not services.is_known(compliance_id, provider_type):
            raise ValidationError(
                {
                    "compliance_id": [
                        f"Unknown framework {compliance_id!r} for {provider_type!r}."
                    ]
                }
            )
        return compliance_id, provider_type

    def add(self, request):
        compliance_id, provider_type = self._target(
            request.data.get("attributes") or {}
        )
        entry, created = ComplianceWatchlistEntry.objects.get_or_create(
            tenant_id=request.tenant_id,
            compliance_id=compliance_id,
            provider_type=provider_type,
            defaults={"created_by": request.user},
        )
        return Response(
            {"data": _entry_doc(entry)},
            status=status.HTTP_201_CREATED if created else status.HTTP_200_OK,
        )

    def remove(self, request, pk):
        entry = self.get_queryset().filter(id=pk).first()
        if entry is None:
            raise NotFound("Not in the watchlist.")
        entry.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

    def bulk(self, request):
        attributes = request.data.get("attributes") or {}
        add, remove = attributes.get("add") or [], attributes.get("remove") or []
        if len(add) + len(remove) > services.MAX_BULK:
            raise ValidationError(
                {"attributes": [f"At most {services.MAX_BULK} frameworks per update."]}
            )
        counts = {"added": 0, "already_present": 0, "removed": 0, "not_present": 0}
        for item in add:
            compliance_id, provider_type = self._target(item)
            _, created = ComplianceWatchlistEntry.objects.get_or_create(
                tenant_id=request.tenant_id,
                compliance_id=compliance_id,
                provider_type=provider_type,
                defaults={"created_by": request.user},
            )
            counts["added" if created else "already_present"] += 1
        for item in remove:
            compliance_id, provider_type = self._target(item)
            deleted, _ = (
                self.get_queryset()
                .filter(compliance_id=compliance_id, provider_type=provider_type)
                .delete()
            )
            counts["removed" if deleted else "not_present"] += 1
        return Response(
            {
                "data": [],
                "meta": {**counts, "watchlist_count": self.get_queryset().count()},
            }
        )

    def finding_frameworks(self, request, pk):
        findings = Finding.all_objects.filter(tenant_id=request.tenant_id, id=pk)
        role = self.user_role
        if not role.unlimited_visibility:
            findings = findings.filter(scan__provider__in=get_providers(role))
        finding = (
            findings.select_related("scan__provider")
            .only("id", "check_id", "scan__provider__provider")
            .first()
        )
        if finding is None:
            raise NotFound("Finding not found.")
        provider_type = finding.scan.provider.provider
        watched = {(e.compliance_id, e.provider_type) for e in self.get_queryset()}
        rows = []
        for framework in services.frameworks_for_check(provider_type, finding.check_id):
            in_watchlist = (
                framework["compliance_id"],
                framework["provider_type"],
            ) in watched
            if (
                request.query_params.get("filter[in_watchlist]") == "true"
                and not in_watchlist
            ):
                continue
            rows.append(
                {
                    "type": "finding-compliance-frameworks",
                    "id": framework["compliance_id"],
                    "attributes": {**framework, "in_watchlist": in_watchlist},
                }
            )
        return Response({"data": rows})


@extend_schema(tags=["Compliance Overview"], exclude=True)
class CrossProviderComplianceViewSet(BaseRLSViewSet):
    resource_name = False
    filter_backends = []
    pagination_class = None

    def get_queryset(self):
        providers = Provider.objects.filter(tenant_id=self.request.tenant_id)
        role = self.user_role
        if not role.unlimited_visibility:
            providers = providers.filter(id__in=get_providers(role).values("id"))
        return providers

    # ------------------------------------------------------------- helpers
    def _kind(self) -> str:
        return (
            compliance_pdf.CROSS_ACCOUNT
            if self.action.startswith("cross_account")
            else compliance_pdf.CROSS_PROVIDER
        )

    def _scope(self, request):
        """(compliance_id, provider_type, providers, scan_ids) from the filters."""
        params = request.query_params
        compliance_id = params.get("filter[compliance_id]")
        if not compliance_id:
            raise ValidationError(
                {"compliance_id": ["filter[compliance_id] is required."]}
            )
        csv = lambda key: [v for v in params.get(key, "").split(",") if v]  # noqa: E731
        providers = self.get_queryset()
        if types := csv("filter[provider_type__in]"):
            providers = providers.filter(provider__in=types)
        if ids := csv("filter[provider_id__in]"):
            providers = providers.filter(id__in=ids)
        if groups := csv("filter[provider_groups__in]"):
            providers = providers.filter(
                id__in=ProviderGroupMembership.objects.filter(
                    provider_group_id__in=groups
                ).values("provider_id")
            )
        provider_type = None
        if self._kind() == compliance_pdf.CROSS_ACCOUNT:
            provider_type = params.get("filter[provider_type]")
            if not provider_type:
                raise ValidationError(
                    {"provider_type": ["filter[provider_type] is required."]}
                )
        return compliance_id, provider_type, providers, csv("filter[scan__in]")

    def _report_params(self, request) -> dict:
        compliance_id, provider_type, providers, scan_ids = self._scope(request)
        return {
            "compliance_id": compliance_id,
            "provider_type": provider_type,
            "provider_ids": sorted(
                str(pid) for pid in providers.values_list("id", flat=True)
            ),
            "scan_ids": sorted(scan_ids),
        }

    # ------------------------------------------------------------ overviews
    def cross_account(self, request):
        return self.overview(request)

    def overview(self, request):
        compliance_id, provider_type, providers, scan_ids = self._scope(request)
        if self._kind() == compliance_pdf.CROSS_ACCOUNT:
            payload = cross_provider.cross_account(
                str(request.tenant_id),
                compliance_id,
                provider_type,
                providers,
                scan_ids,
            )
            if payload is None:
                raise NotFound("This provider type has no such framework.")
            return Response(
                {
                    "data": {
                        "type": "cross-account-compliance-overviews",
                        "id": f"{compliance_id}:{provider_type}",
                        "attributes": payload,
                    }
                }
            )
        payload = cross_provider.overview(
            str(request.tenant_id), compliance_id, providers, scan_ids
        )
        if payload is None:
            raise NotFound("No provider of this tenant supports this framework.")
        return Response(
            {
                "data": {
                    "type": "cross-provider-compliance-overviews",
                    "id": compliance_id,
                    "attributes": payload,
                }
            }
        )

    # ------------------------------------------------------------------ PDF
    @staticmethod
    def _task_doc(task) -> dict:
        data = dict(TaskSerializer(task).data)
        task_id = str(data.pop("id"))
        return {"data": {"type": "tasks", "id": task_id, "attributes": data}}

    def pdf_generate(self, request):
        from tasks.tasks import generate_aggregated_compliance_pdf_task

        params = self._report_params(request)
        if not params["provider_ids"]:
            raise NotFound("No provider matches these filters.")
        kind = self._kind()
        with transaction.atomic():
            task = generate_aggregated_compliance_pdf_task.delay(
                tenant_id=str(request.tenant_id),
                kind=kind,
                report_name=(request.query_params.get("report_name") or "")[:150],
                key=compliance_pdf.request_key(kind, params),
                **params,
            )
        return Response(
            self._task_doc(Task.objects.get(id=task.id)),
            status=status.HTTP_202_ACCEPTED,
        )

    def _pdf_tasks(self):
        return Task.objects.filter(
            tenant_id=self.request.tenant_id,
            task_runner_task__task_name=compliance_pdf.TASK_NAME,
        ).select_related("task_runner_task")

    def pdf_binary(self, request, task_id):
        task = self._pdf_tasks().filter(id=task_id).first()
        if task is None:
            raise NotFound("Report not found.")
        runner = task.task_runner_task
        if runner.status == "FAILURE":
            raise ValidationError({"report": ["The report could not be generated."]})
        if runner.status != "SUCCESS":
            return Response(self._task_doc(task), status=status.HTTP_202_ACCEPTED)
        result = TaskSerializer(task).data.get("result") or {}
        path = compliance_pdf.output_path(str(request.tenant_id), str(task.id))
        if result.get("kind") != self._kind() or not path.exists():
            raise NotFound("Report not found.")
        return FileResponse(
            open(path, "rb"),
            as_attachment=True,
            filename=result.get("filename") or "compliance-report.pdf",
            content_type="application/pdf",
        )

    def pdf_latest(self, request):
        key = compliance_pdf.request_key(self._kind(), self._report_params(request))
        for task in (
            self._pdf_tasks()
            .filter(task_runner_task__status="SUCCESS")
            .order_by("-task_runner_task__date_done")[:50]
        ):
            result = TaskSerializer(task).data.get("result") or {}
            if (
                result.get("key") == key
                and compliance_pdf.output_path(
                    str(request.tenant_id), str(task.id)
                ).exists()
            ):
                return Response(self._task_doc(task))
        raise NotFound("No report yet.")

    def cross_account_pdf_generate(self, request):
        return self.pdf_generate(request)

    def cross_account_pdf_latest(self, request):
        return self.pdf_latest(request)

    def cross_account_pdf_binary(self, request, task_id):
        return self.pdf_binary(request, task_id)
