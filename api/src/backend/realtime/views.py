"""Prowler Realtime API (`/api/v1/realtime/...`).

Responses are built as JSON:API documents by hand: most are computed views,
not model rows. `resource_name = False` makes the JSON:API renderer pass them
through while still formatting errors as JSON:API.
"""

import json
from uuid import UUID

from api.base_views import BaseRLSViewSet
from api.compliance import get_compliance_frameworks
from api.models import (
    Provider,
    RealtimeAction,
    RealtimeCredential,
    RealtimeDetection,
    RealtimeEvent,
    RealtimeFeed,
    RealtimePolicy,
)
from api.rbac.permissions import Permissions, get_providers
from django.db import transaction
from drf_spectacular.utils import extend_schema
from realtime import demo, engine, insights, remediations
from rest_framework import status
from rest_framework.exceptions import (
    APIException,
    NotFound,
    ParseError,
    ValidationError,
)
from rest_framework.parsers import BaseParser
from rest_framework.permissions import SAFE_METHODS
from rest_framework.response import Response

MAX_EVENTS = 500


class RevertRefused(APIException):
    """409: the UI explains it as "AWS did not accept the change"."""

    status_code = status.HTTP_409_CONFLICT
    default_code = "revert_refused"


POLICY_FIELDS = (
    "enabled",
    "mode",
    "dry_run",
    "min_severity",
    "deny_checks",
    "allow_regions",
    "scope_tags",
    "iac_repo",
    "iac_path",
    "open_pr",
    "use_lighthouse",
    "frameworks",
    "cost_anomaly_enabled",
    "cost_anomaly_min_ratio",
    "cost_anomaly_min_delta",
    "notifications",
)
SEVERITIES = ("low", "medium", "high", "critical")


class DocumentParser(BaseParser):
    media_type = "application/vnd.api+json"

    def parse(self, stream, media_type=None, parser_context=None):
        try:
            document = json.loads(stream.read() or b"{}")
        except ValueError as error:
            raise ParseError("Malformed JSON.") from error
        data = document.get("data") if isinstance(document, dict) else None
        if not isinstance(data, dict) or not isinstance(
            data.get("attributes", {}), dict
        ):
            raise ParseError("Send a JSON:API document with `data.attributes`.")
        return data


def resource(
    type_: str, id_, attributes: dict, provider_id=None, detection_id=None
) -> dict:
    relationships = {}
    if provider_id:
        relationships["provider"] = {
            "data": {"type": "providers", "id": str(provider_id)}
        }
    if detection_id:
        relationships["detection"] = {
            "data": {"type": "realtime-detections", "id": str(detection_id)}
        }
    item = {"type": type_, "id": str(id_), "attributes": attributes}
    if relationships:
        item["relationships"] = relationships
    return item


def policy_doc(p: RealtimePolicy) -> dict:
    return resource(
        "realtime-policies",
        p.id,
        {f: getattr(p, f) for f in POLICY_FIELDS},
        p.provider_id,
    )


def feed_doc(f: RealtimeFeed) -> dict:
    return resource(
        "realtime-feeds",
        f.id,
        {
            "queue_url": f.queue_url,
            "region": f.region,
            "status": f.status,
            "last_polled_at": f.last_polled_at,
            "last_event_at": f.last_event_at,
            "last_error": f.last_error,
        },
        f.provider_id,
    )


def credential_doc(c: RealtimeCredential) -> dict:
    return resource(
        "realtime-credentials",
        c.id,
        {
            "role_arn": c.role_arn,
            "has_github_token": bool(c.secrets_decoded.get("github_token")),
        },
        c.provider_id,
    )


def event_doc(e: RealtimeEvent) -> dict:
    detection = getattr(e, "detection", None)
    return resource(
        "realtime-events",
        e.id,
        {
            "event_time": e.event_time,
            "region": e.region,
            "event_source": e.event_source,
            "event_name": e.event_name,
            "user_type": e.user_type,
            "user_arn": e.user_arn,
            "source_ip": e.source_ip,
            "error_code": e.error_code,
            "read_only": e.read_only,
            "provider_id": str(e.provider_id),
            "detection_status": detection.status if detection else None,
            "rule_id": detection.rule_id if detection else None,
        },
    )


def detection_doc(d: RealtimeDetection) -> dict:
    return resource(
        "realtime-detections",
        d.id,
        {
            "event_id": str(d.event_id),
            "event_time": d.event.event_time,
            "region": d.event.region,
            "rule_id": d.rule_id,
            "title": d.title,
            "severity": d.severity,
            "actor": d.actor,
            "resource": d.resource,
            "check_ids": d.check_ids,
            "requirements": d.requirements,
            "status": d.status,
            "note": d.note,
            "verified_at": d.verified_at,
        },
        d.provider_id,
    )


def action_doc(a: RealtimeAction) -> dict:
    return resource(
        "realtime-actions",
        a.id,
        {
            "kind": a.kind,
            "status": a.status,
            "check_id": a.check_id,
            "resource_uid": a.resource_uid,
            "region": a.region,
            "severity": a.severity,
            "summary": a.summary,
            "pr_url": a.pr_url,
            "branch": a.branch,
            "revertible": a.revertible,
            "inserted_at": a.inserted_at,
        },
        a.provider_id,
        a.detection_id,
    )


def _page(request, queryset, to_doc):
    try:
        number = max(int(request.query_params.get("page[number]", 1)), 1)
        size = min(max(int(request.query_params.get("page[size]", 25)), 1), 100)
    except ValueError as error:
        raise ValidationError({"page": ["Page values must be numbers."]}) from error
    count = queryset.count()
    pages = max((count + size - 1) // size, 1)
    rows = queryset[(number - 1) * size : number * size]
    return Response(
        {
            "data": [to_doc(row) for row in rows],
            "meta": {"pagination": {"page": number, "pages": pages, "count": count}},
        }
    )


def _csv(request, key) -> list[str]:
    return [v for v in request.query_params.get(key, "").split(",") if v]


@extend_schema(exclude=True)
class RealtimeViewSet(BaseRLSViewSet):
    resource_name = False
    parser_classes = [DocumentParser]
    filter_backends = []
    pagination_class = None

    def set_required_permissions(self):
        self.required_permissions = (
            [] if self.request.method in SAFE_METHODS else [Permissions.MANAGE_SCANS]
        )

    def get_queryset(self):
        return RealtimePolicy.objects.filter(tenant_id=self.request.tenant_id)

    # ---------------------------------------------------------------- helpers
    def _providers(self):
        role = self.user_role
        providers = Provider.objects.filter(
            tenant_id=self.request.tenant_id, provider=Provider.ProviderChoices.AWS
        )
        return (
            providers
            if role.unlimited_visibility
            else providers.filter(id__in=get_providers(role).values("id"))
        )

    def _provider(self, provider_id) -> Provider:
        try:
            UUID(str(provider_id))
        except ValueError:
            raise ValidationError(
                {"provider": ["Select an AWS provider first."]}
            ) from None
        provider = self._providers().filter(id=provider_id).first()
        if provider is None:
            raise NotFound("AWS provider not found.")
        return provider

    def _query_provider(self):
        return self._provider(
            self.request.query_params.get("filter[provider]")
            or self.request.query_params.get("provider")
        )

    def _body_provider(self):
        relationships = self.request.data.get("relationships") or {}
        data = (relationships.get("provider") or {}).get("data") or {}
        return self._provider(data.get("id"))

    def _attributes(self) -> dict:
        return self.request.data.get("attributes") or {}

    def _scoped(self, model, pk):
        row = model.objects.filter(
            tenant_id=self.request.tenant_id, provider__in=self._providers(), id=pk
        ).first()
        if row is None:
            raise NotFound()
        return row

    # --------------------------------------------------------------- policies
    def _clean_policy(self, attributes: dict, partial: bool) -> dict:
        unknown = set(attributes) - set(POLICY_FIELDS)
        if unknown:
            raise ValidationError(
                {"attributes": [f"Unknown fields: {sorted(unknown)}."]}
            )
        cleaned = {}
        for field, value in attributes.items():
            if field == "mode" and value not in RealtimePolicy.ModeChoices.values:
                raise ValidationError({"mode": ["Unknown mode."]})
            if field == "min_severity" and value not in SEVERITIES:
                raise ValidationError({"min_severity": ["Unknown severity."]})
            if field in ("deny_checks", "allow_regions", "frameworks") and not (
                isinstance(value, list) and all(isinstance(v, str) and v for v in value)
            ):
                raise ValidationError({field: ["Send a list of names."]})
            if field == "scope_tags" and not isinstance(value, dict):
                raise ValidationError({"scope_tags": ["Send key/value tags."]})
            if field == "cost_anomaly_min_ratio" and not 1.1 <= float(value) <= 20:
                raise ValidationError({field: ["Must be between 1.1 and 20."]})
            if field == "cost_anomaly_min_delta" and not 0 <= float(value) <= 100000:
                raise ValidationError(
                    {field: ["Must be between 0 and 100000 dollars."]}
                )
            cleaned[field] = value
        return cleaned

    def list_policies(self, request):
        provider = self._query_provider()
        rows = RealtimePolicy.objects.filter(provider=provider)
        return Response({"data": [policy_doc(p) for p in rows]})

    def create_policy(self, request):
        provider = self._body_provider()
        if RealtimePolicy.objects.filter(provider=provider).exists():
            raise ValidationError({"provider": ["This provider already has a policy."]})
        policy = RealtimePolicy.objects.create(
            tenant_id=request.tenant_id,
            provider=provider,
            **self._clean_policy(self._attributes(), partial=False),
        )
        return Response({"data": policy_doc(policy)}, status=status.HTTP_201_CREATED)

    def update_policy(self, request, pk):
        policy = self._scoped(RealtimePolicy, pk)
        for field, value in self._clean_policy(
            self._attributes(), partial=True
        ).items():
            setattr(policy, field, value)
        policy.save()
        return Response({"data": policy_doc(policy)})

    # ------------------------------------------------------------- frameworks
    def list_frameworks(self, request):
        rows = []
        for framework_id in sorted(
            get_compliance_frameworks(Provider.ProviderChoices.AWS)
        ):
            name, _, version = framework_id.removesuffix("_aws").rpartition("_")
            rows.append(
                resource(
                    "realtime-frameworks",
                    framework_id,
                    {
                        "name": (name or framework_id).replace("_", " ").upper(),
                        "version": version,
                    },
                )
            )
        return Response({"data": rows})

    # ------------------------------------------------------------------ feeds
    def _clean_feed(self, attributes):
        queue_url = (attributes.get("queue_url") or "").strip()
        region = (attributes.get("region") or "us-east-1").strip()
        if queue_url and not queue_url.startswith("https://sqs."):
            raise ValidationError(
                {"queue_url": ["Use the queue URL the stack outputs."]}
            )
        return {"queue_url": queue_url, "region": region}

    def list_feeds(self, request):
        provider = self._query_provider()
        return Response(
            {
                "data": [
                    feed_doc(f) for f in RealtimeFeed.objects.filter(provider=provider)
                ]
            }
        )

    def create_feed(self, request):
        provider = self._body_provider()
        feed, _ = RealtimeFeed.objects.update_or_create(
            tenant_id=request.tenant_id,
            provider=provider,
            defaults=self._clean_feed(self._attributes()),
        )
        return Response({"data": feed_doc(feed)}, status=status.HTTP_201_CREATED)

    def update_feed(self, request, pk):
        feed = self._scoped(RealtimeFeed, pk)
        for field, value in self._clean_feed(self._attributes()).items():
            setattr(feed, field, value)
        feed.save()
        return Response({"data": feed_doc(feed)})

    def poll_feed(self, request, pk):
        from tasks.tasks import realtime_poll_feed_task

        feed = self._scoped(RealtimeFeed, pk)
        tenant_id = str(request.tenant_id)
        transaction.on_commit(
            lambda: realtime_poll_feed_task.apply_async(
                kwargs={"tenant_id": tenant_id, "feed_id": str(feed.id)}
            )
        )
        return Response({"data": feed_doc(feed)}, status=status.HTTP_202_ACCEPTED)

    # ----------------------------------------------------------------- events
    def list_events(self, request):
        provider = self._query_provider()
        try:
            limit = min(max(int(request.query_params.get("limit", 100)), 1), MAX_EVENTS)
        except ValueError:
            limit = 100
        events = RealtimeEvent.objects.filter(provider=provider).select_related(
            "detection"
        )
        if request.query_params.get("writes_only") == "true":
            events = events.filter(read_only=False)
        return Response(
            {"data": [event_doc(e) for e in events.order_by("-event_time")[:limit]]}
        )

    # ------------------------------------------------- detections and actions
    def list_detections(self, request):
        provider = self._query_provider()
        rows = RealtimeDetection.objects.filter(provider=provider).select_related(
            "event"
        )
        if statuses := _csv(request, "filter[status__in]"):
            rows = rows.filter(status__in=statuses)
        if severities := _csv(request, "filter[severity__in]"):
            rows = rows.filter(severity__in=severities)
        if rule_id := request.query_params.get("filter[rule_id]"):
            rows = rows.filter(rule_id=rule_id)
        return _page(request, rows.order_by("-event__event_time"), detection_doc)

    def retrieve_detection(self, request, pk):
        return Response({"data": detection_doc(self._scoped(RealtimeDetection, pk))})

    def list_actions(self, request):
        provider = self._query_provider()
        rows = RealtimeAction.objects.filter(provider=provider)
        if statuses := _csv(request, "filter[status__in]"):
            rows = rows.filter(status__in=statuses)
        if kinds := _csv(request, "filter[kind__in]"):
            rows = rows.filter(kind__in=kinds)
        return _page(request, rows.order_by("-inserted_at"), action_doc)

    def retrieve_action(self, request, pk):
        return Response({"data": action_doc(self._scoped(RealtimeAction, pk))})

    def revert_action(self, request, pk):
        action = self._scoped(RealtimeAction, pk)
        try:
            engine.revert_action(action)
        except remediations.RemediationError as error:
            raise RevertRefused(str(error)) from error
        return Response({"data": action_doc(action)})

    # ------------------------------------------------------------ credentials
    def list_credentials(self, request):
        provider = self._query_provider()
        rows = RealtimeCredential.objects.filter(provider=provider)
        return Response({"data": [credential_doc(c) for c in rows]})

    def create_credential(self, request):
        provider = self._body_provider()
        attributes = self._attributes()
        role_arn = (attributes.get("role_arn") or "").strip()
        if role_arn and not role_arn.startswith("arn:aws"):
            raise ValidationError(
                {"role_arn": ["Paste the RoleArn the stack outputs."]}
            )
        external_id = attributes.get("external_id") or ""
        if role_arn and len(external_id) < 8:
            raise ValidationError({"external_id": ["Use at least 8 characters."]})
        credential, _ = RealtimeCredential.objects.get_or_create(
            tenant_id=request.tenant_id, provider=provider
        )
        secrets = credential.secrets_decoded
        if role_arn:
            credential.role_arn = role_arn
            secrets["external_id"] = external_id
        if attributes.get("github_token"):
            secrets["github_token"] = attributes["github_token"]
        credential.secrets_decoded = secrets
        credential.save()
        return Response(
            {"data": credential_doc(credential)}, status=status.HTTP_201_CREATED
        )

    def delete_credential(self, request, pk):
        self._scoped(RealtimeCredential, pk).delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

    # --------------------------------------------------------------- insights
    def insight(self, request, kind):
        provider = self._query_provider()
        if kind == "setup":
            payload = insights.setup_view(provider)
        elif kind == "anomaly":
            payload = insights.anomaly_view(
                provider,
                request.query_params.get("service", ""),
                request.query_params.get("region", ""),
            )
        elif kind in insights.VIEWS:
            payload = insights.VIEWS[kind](provider)
        else:
            raise NotFound("Unknown view.")
        return Response(
            {
                "data": resource(
                    "realtime-insights", kind, {"kind": kind, "payload": payload}
                )
            }
        )

    def notification_targets(self, request):
        from api.models import AlertRecipient

        recipients = AlertRecipient.objects.filter(
            tenant_id=request.tenant_id
        ).order_by("email")
        return Response(
            {
                "data": resource(
                    "realtime-notification-targets",
                    "targets",
                    {
                        "slack": [],
                        "email": [
                            {"id": str(r.id), "email": r.email, "status": r.status}
                            for r in recipients
                        ],
                    },
                )
            }
        )

    def list_remediations(self, request):
        provider_id = request.query_params.get("provider")
        policy = None
        if provider_id:
            policy = RealtimePolicy.objects.filter(
                provider=self._provider(provider_id)
            ).first()
        denied = set(policy.deny_checks) if policy else set()
        rows = []
        for item in remediations.CATALOG.values():
            active = [c for c in item.checks if c not in denied]
            rows.append(
                resource(
                    "realtime-remediations",
                    item.id,
                    {
                        "title": item.title,
                        "effect": item.effect,
                        "checks": list(item.checks),
                        "active_checks": active,
                        "iam_actions": list(item.iam_actions),
                        "revertible": item.revertible,
                        "undo": item.undo,
                        "in_enforced_scope": bool(
                            policy
                            and policy.enabled
                            and active
                            and policy.mode == RealtimePolicy.ModeChoices.AUTO
                        ),
                    },
                )
            )
        return Response({"data": rows})

    def demo(self, request, kind):
        payload = demo.payload(kind)
        if payload is None:
            raise NotFound("Unknown view.")
        return Response(
            {
                "data": resource(
                    "realtime-demo", kind, {"kind": kind, "payload": payload}
                )
            }
        )
