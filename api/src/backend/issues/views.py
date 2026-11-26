"""Issues API: `/issues`, `/issues/overview`, `/issues/<id>`, and its triage."""

from api.base_views import BaseRLSViewSet
from api.models import Issue, IssueTriage, IssueTriageNote
from api.rbac.permissions import Permissions, get_providers
from django.db.models import Count, OuterRef, Subquery, Sum
from drf_spectacular.utils import extend_schema
from issues.engine import VERDICT_RANK
from realtime.views import DocumentParser
from rest_framework import status
from rest_framework.exceptions import NotFound, ValidationError
from rest_framework.permissions import SAFE_METHODS
from rest_framework.response import Response
from triage.services import MANUAL_STATUSES, NOTE_MAX_LENGTH

ORDERING = {
    "verdict_rank": "verdict_rank",
    "severity": "severity_rank",
    "findings_count": "findings_count",
    "updated_at": "updated_at",
    "title": "title",
}


def _csv(request, key):
    return [v for v in request.query_params.get(key, "").split(",") if v]


@extend_schema(tags=["Issues"], exclude=True)
class IssueViewSet(BaseRLSViewSet):
    resource_name = False
    parser_classes = [DocumentParser]
    filter_backends = []
    pagination_class = None

    def set_required_permissions(self):
        self.required_permissions = (
            [] if self.request.method in SAFE_METHODS else [Permissions.MANAGE_SCANS]
        )

    def get_queryset(self):
        issues = Issue.objects.filter(tenant_id=self.request.tenant_id)
        role = self.user_role
        if not role.unlimited_visibility:
            issues = issues.filter(provider__in=get_providers(role))
        return issues.select_related("provider").annotate(
            triage_status=Subquery(
                IssueTriage.objects.filter(issue=OuterRef("pk")).values("status")[:1]
            ),
            notes_count=Count("triage_notes", distinct=True),
        )

    def _filtered(self, request):
        issues = self.get_queryset()
        if verdicts := _csv(request, "filter[verdict__in]") or _csv(
            request, "filter[verdict]"
        ):
            issues = issues.filter(verdict__in=verdicts)
        if severities := _csv(request, "filter[severity__in]"):
            issues = issues.filter(severity__in=severities)
        if providers := _csv(request, "filter[provider_id__in]") or _csv(
            request, "filter[provider__in]"
        ):
            issues = issues.filter(provider_id__in=providers)
        if types := _csv(request, "filter[provider_type__in]"):
            issues = issues.filter(provider__provider__in=types)
        if statuses := _csv(request, "filter[triage_status__in]"):
            open_wanted = "open" in statuses
            query = issues.filter(triage_status__in=statuses)
            issues = (
                query | issues.filter(triage_status__isnull=True)
                if open_wanted
                else query
            )
        if search := request.query_params.get("filter[search]"):
            issues = issues.filter(title__icontains=search)
        return issues

    def _resource(self, issue: Issue, detail=False) -> dict:
        attributes = {
            "pattern": issue.pattern,
            "cloud": issue.provider.provider,
            "account": issue.provider.alias or issue.provider.uid,
            "title": issue.title,
            "verdict": issue.verdict,
            "severity": issue.severity,
            "outcome": issue.outcome,
            "attacker_start": issue.attacker_start,
            "legs": issue.legs,
            "fix": issue.fix,
            "findings_count": issue.findings_count,
            "triage_status": getattr(issue, "triage_status", None) or "open",
            "notes_count": getattr(issue, "notes_count", 0),
            "inserted_at": issue.inserted_at,
            "updated_at": issue.updated_at,
        }
        if detail:
            attributes["finding_uids"] = issue.finding_uids
            attributes["resource_uids"] = issue.resource_uids
        return {
            "type": "issues",
            "id": str(issue.id),
            "attributes": attributes,
            "relationships": {
                "provider": {
                    "data": {"type": "providers", "id": str(issue.provider_id)}
                },
                "scan": {
                    "data": {"type": "scans", "id": str(issue.scan_id)}
                    if issue.scan_id
                    else None
                },
            },
        }

    def _issue(self, pk) -> Issue:
        issue = self.get_queryset().filter(id=pk).first()
        if issue is None:
            raise NotFound("Issue not found.")
        return issue

    def list_issues(self, request):
        issues = self._filtered(request)
        sort = request.query_params.get("sort", "")
        key = ORDERING.get(sort.lstrip("-"))
        if key:
            order = [f"-{key}" if sort.startswith("-") else key, "-severity_rank"]
        else:
            order = ["-verdict_rank", "-severity_rank", "-findings_count"]
        try:
            number = max(int(request.query_params.get("page[number]", 1)), 1)
            size = min(max(int(request.query_params.get("page[size]", 10)), 1), 100)
        except ValueError as error:
            raise ValidationError({"page": ["Page values must be numbers."]}) from error
        count = issues.count()
        rows = issues.order_by(*order)[(number - 1) * size : number * size]
        return Response(
            {
                "data": [self._resource(issue) for issue in rows],
                "meta": {
                    "pagination": {
                        "page": number,
                        "pages": max((count + size - 1) // size, 1),
                        "count": count,
                    }
                },
            }
        )

    def overview(self, request):
        issues = self._filtered(request)
        by_verdict = dict(
            issues.values_list("verdict").annotate(total=Count("id")).order_by()
        )
        findings = issues.aggregate(total=Sum("findings_count"))["total"] or 0
        not_exploitable = (
            issues.filter(verdict="not_exploitable").aggregate(
                total=Sum("findings_count")
            )["total"]
            or 0
        )
        attributes = {verdict: by_verdict.get(verdict, 0) for verdict in VERDICT_RANK}
        attributes.update(
            issues=sum(by_verdict.values()),
            findings=findings,
            actionable=by_verdict.get("exploitable", 0) + by_verdict.get("likely", 0),
            not_exploitable_findings=not_exploitable,
        )
        return Response(
            {
                "data": {
                    "type": "issues-overview",
                    "id": "overview",
                    "attributes": attributes,
                }
            }
        )

    def retrieve_issue(self, request, pk):
        return Response({"data": self._resource(self._issue(pk), detail=True)})

    def update_triage(self, request, pk):
        issue = self._issue(pk)
        attributes = request.data.get("attributes") or {}
        new_status = attributes.get("status")
        if new_status not in MANUAL_STATUSES:
            raise ValidationError(
                {"status": [f"Use one of {sorted(MANUAL_STATUSES)}."]}
            )
        note = (attributes.get("note") or "").strip()
        if len(note) > NOTE_MAX_LENGTH:
            raise ValidationError(
                {"note": [f"A note cannot exceed {NOTE_MAX_LENGTH} characters."]}
            )
        IssueTriage.objects.update_or_create(
            tenant_id=request.tenant_id,
            issue=issue,
            defaults={"status": new_status, "updated_by": request.user},
        )
        if note:
            IssueTriageNote.objects.create(
                tenant_id=request.tenant_id,
                issue=issue,
                body=note,
                created_by=request.user,
            )
        return Response({"data": self._resource(self._issue(pk), detail=True)})

    def notes(self, request, pk):
        issue = self._issue(pk)
        if request.method == "POST":
            body = ((request.data.get("attributes") or {}).get("body") or "").strip()
            if not body or len(body) > NOTE_MAX_LENGTH:
                raise ValidationError(
                    {"body": [f"Write a note of 1 to {NOTE_MAX_LENGTH} characters."]}
                )
            note = IssueTriageNote.objects.create(
                tenant_id=request.tenant_id,
                issue=issue,
                body=body,
                created_by=request.user,
            )
            return Response({"data": self._note(note)}, status=status.HTTP_201_CREATED)

        notes = list(
            IssueTriageNote.objects.filter(issue=issue)
            .select_related("created_by")
            .order_by("-id")
        )
        document = {"data": [self._note(note) for note in notes]}
        if "created_by" in request.query_params.get("include", ""):
            authors = {
                note.created_by_id: note.created_by for note in notes if note.created_by
            }
            document["included"] = [
                {
                    "type": "users",
                    "id": str(user.id),
                    "attributes": {"name": user.name, "email": user.email},
                }
                for user in authors.values()
            ]
        return Response(document)

    def _note(self, note: IssueTriageNote) -> dict:
        return {
            "type": "issue-triage-notes",
            "id": str(note.id),
            "attributes": {"body": note.body, "inserted_at": note.inserted_at},
            "relationships": {
                "created_by": {
                    "data": {"type": "users", "id": str(note.created_by_id)}
                    if note.created_by_id
                    else None
                }
            },
        }
