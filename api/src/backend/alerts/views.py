from alerts import dsl, services
from alerts.filters import AlertRecipientFilter, AlertRuleFilter
from alerts.serializers import (
    AlertRecipientSerializer,
    AlertRulePreviewSerializer,
    AlertRuleSeedSerializer,
    AlertRuleSerializer,
    AlertRuleUpdateSerializer,
    AlertRuleWriteSerializer,
)
from api.base_views import BaseRLSViewSet
from api.db_router import MainRouter
from api.db_utils import rls_transaction
from api.models import AlertRecipient, AlertRule
from api.rbac.permissions import Permissions, get_providers
from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import AllowAny
from rest_framework.renderers import JSONRenderer
from rest_framework.response import Response
from rest_framework.views import APIView

SEEDED_RULE_NAME = "Findings filter alert"


@extend_schema_view(
    list=extend_schema(tags=["Alerts"], summary="List alert rules"),
    retrieve=extend_schema(tags=["Alerts"], summary="Retrieve an alert rule"),
    create=extend_schema(
        tags=["Alerts"],
        summary="Create an alert rule",
        request=AlertRuleWriteSerializer,
        responses={201: AlertRuleSerializer},
    ),
    partial_update=extend_schema(
        tags=["Alerts"],
        summary="Update an alert rule",
        request=AlertRuleUpdateSerializer,
        responses={200: AlertRuleSerializer},
    ),
    destroy=extend_schema(tags=["Alerts"], summary="Delete an alert rule"),
    seed=extend_schema(
        tags=["Alerts"],
        summary="Build an alert condition from Findings filters",
        description="Translates Findings list filters into an alert condition. "
        "Nothing is stored.",
    ),
    preview=extend_schema(
        tags=["Alerts"],
        summary="Preview an alert condition",
        description="Evaluates a condition over the latest scan of each provider "
        "without sending notifications.",
    ),
)
class AlertRuleViewSet(BaseRLSViewSet):
    queryset = AlertRule.objects.all()
    serializer_class = AlertRuleSerializer
    filterset_class = AlertRuleFilter
    http_method_names = ["get", "post", "patch", "delete"]
    search_fields = ["name", "description"]
    ordering = ["-inserted_at"]
    ordering_fields = ["name", "enabled", "trigger", "inserted_at", "updated_at"]
    # Alerts send finding data to destinations outside Prowler.
    required_permissions = [Permissions.MANAGE_INTEGRATIONS]

    def get_queryset(self):
        return (
            AlertRule.objects.filter(tenant_id=self.request.tenant_id)
            .select_related("created_by")
            .prefetch_related("recipients")
        )

    def get_serializer_class(self):
        if self.action == "create":
            return AlertRuleWriteSerializer
        if self.action == "partial_update":
            return AlertRuleUpdateSerializer
        if self.action == "seed":
            return AlertRuleSeedSerializer
        if self.action == "preview":
            return AlertRulePreviewSerializer
        return super().get_serializer_class()

    def _read_response(self, rule, response_status):
        rule = self.get_queryset().get(id=rule.id)
        serializer = AlertRuleSerializer(rule, context=self.get_serializer_context())
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

    @action(detail=False, methods=["post"], url_name="seed")
    def seed(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            condition = dsl.condition_from_filter_bag(
                serializer.validated_data["filter_bag"]
            )
        except dsl.ConditionError as error:
            raise ValidationError({"filter_bag": [str(error)]}) from error

        seeded = {
            "name": SEEDED_RULE_NAME,
            "description": "",
            "trigger": AlertRule.TriggerChoices.AFTER_SCAN,
            "condition": condition,
            "schema_version": dsl.SCHEMA_VERSION,
        }
        return Response(data=self.get_serializer(instance=seeded).data)

    @action(detail=False, methods=["post"], url_name="preview")
    def preview(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        role = self.user_role
        providers = None if role.unlimited_visibility else get_providers(role)
        result = services.preview_condition(
            str(request.tenant_id),
            serializer.validated_data["condition"],
            providers=providers,
        )
        return Response(data=self.get_serializer(instance=result).data)


@extend_schema_view(
    list=extend_schema(tags=["Alerts"], summary="List alert recipients"),
    retrieve=extend_schema(tags=["Alerts"], summary="Retrieve an alert recipient"),
)
class AlertRecipientViewSet(BaseRLSViewSet):
    queryset = AlertRecipient.objects.all()
    serializer_class = AlertRecipientSerializer
    filterset_class = AlertRecipientFilter
    http_method_names = ["get"]
    search_fields = ["email"]
    ordering = ["email"]
    ordering_fields = ["email", "status", "inserted_at", "updated_at"]
    required_permissions = [Permissions.MANAGE_INTEGRATIONS]

    def get_queryset(self):
        return AlertRecipient.objects.filter(tenant_id=self.request.tenant_id)


@extend_schema_view(
    list=extend_schema(
        tags=["Alerts"],
        summary="List Slack channels eligible as alert destinations",
        description="Always empty: Slack delivery needs the Slack integration, "
        "which self-hosted deployments do not include.",
    ),
)
class AlertSlackChannelViewSet(BaseRLSViewSet):
    resource_name = "alert-slack-channels"
    http_method_names = ["get"]
    filter_backends = []
    pagination_class = None
    required_permissions = [Permissions.MANAGE_INTEGRATIONS]

    def get_queryset(self):
        return AlertRecipient.objects.none()

    def list(self, request, *args, **kwargs):
        return Response(data=[])


class _RecipientLinkView(APIView):
    """Public endpoint behind a link emailed to a recipient.

    The token is the only credential, so the row is found with the admin
    connection and then changed inside its own tenant's RLS transaction.
    """

    authentication_classes = []
    permission_classes = [AllowAny]
    renderer_classes = [JSONRenderer]

    def apply(self, recipient):
        raise NotImplementedError

    def get(self, request):
        token = request.query_params.get("token", "")
        found = (
            AlertRecipient.objects.using(MainRouter.admin_db)
            .filter(token=token)
            .values("id", "tenant_id")
            .first()
            if token
            else None
        )
        if found is None:
            return Response(
                {"state": "invalid", "message": "This link is not valid."},
                status=status.HTTP_404_NOT_FOUND,
            )

        with rls_transaction(str(found["tenant_id"])):
            recipient = AlertRecipient.objects.get(id=found["id"])
            state, message = self.apply(recipient)

        failed = state in {"expired", "unsubscribed"} and isinstance(
            self, AlertRecipientConfirmView
        )
        return Response(
            {"state": state, "message": message},
            status=status.HTTP_409_CONFLICT if failed else status.HTTP_200_OK,
        )


@extend_schema(exclude=True)
class AlertRecipientConfirmView(_RecipientLinkView):
    def apply(self, recipient):
        return services.confirm_recipient(recipient)


@extend_schema(exclude=True)
class AlertRecipientUnsubscribeView(_RecipientLinkView):
    def apply(self, recipient):
        return services.unsubscribe_recipient(recipient)
