from api.base_views import BaseRLSViewSet
from api.models import (
    LighthouseAIConfiguration,
    LighthouseMessage,
    LighthouseSession,
    Task,
)
from api.rbac.permissions import Permissions
from api.sse import BaseSSEViewSet
from api.v1.serializers import TaskSerializer
from django.db import transaction
from django.urls import reverse
from django_filters.rest_framework import BooleanFilter, FilterSet
from drf_spectacular.utils import extend_schema, extend_schema_view
from lighthouse import agent, llm, services
from lighthouse.serializers import (
    LighthouseAIConfigurationSerializer,
    LighthouseAIConfigurationUpdateSerializer,
    LighthouseAIConfigurationWriteSerializer,
    LighthouseMessageCreateSerializer,
    LighthouseMessageSerializer,
    LighthouseSessionSerializer,
    LighthouseSupportedModelSerializer,
    LighthouseSupportedProviderSerializer,
)
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.exceptions import NotFound
from rest_framework.permissions import SAFE_METHODS
from rest_framework.response import Response
from tasks.tasks import check_lighthouse_ai_connection_task, lighthouse_chat_task

TAG = "Lighthouse AI"


def _task_response(task_id):
    prowler_task = Task.objects.get(id=task_id)
    return Response(
        data=TaskSerializer(prowler_task).data,
        status=status.HTTP_202_ACCEPTED,
        headers={
            "Content-Location": reverse("task-detail", kwargs={"pk": prowler_task.id})
        },
    )


class _TaskResponseMixin:
    """Lets an action answer with a `tasks` resource instead of its own type."""

    def get_serializer_class(self):
        if hasattr(self, "response_serializer_class"):
            return self.response_serializer_class
        return super().get_serializer_class()


@extend_schema_view(
    list=extend_schema(tags=[TAG], summary="List LLM provider configurations"),
    retrieve=extend_schema(tags=[TAG], summary="Retrieve an LLM configuration"),
    create=extend_schema(tags=[TAG], summary="Connect an LLM provider"),
    partial_update=extend_schema(tags=[TAG], summary="Update an LLM configuration"),
    destroy=extend_schema(tags=[TAG], summary="Remove an LLM configuration"),
    connection=extend_schema(
        tags=[TAG], summary="Check the LLM provider connection", request=None
    ),
)
class LighthouseAIConfigurationViewSet(_TaskResponseMixin, BaseRLSViewSet):
    queryset = LighthouseAIConfiguration.objects.all()
    serializer_class = LighthouseAIConfigurationSerializer
    filterset_fields = {"provider_type": ["exact"]}
    http_method_names = ["get", "post", "patch", "delete"]
    ordering = ["provider_type"]
    ordering_fields = ["provider_type", "inserted_at", "updated_at"]

    def set_required_permissions(self):
        # Anyone in the tenant can see which providers exist (the chat needs
        # it); only account managers handle the credentials.
        self.required_permissions = (
            [] if self.request.method in SAFE_METHODS else [Permissions.MANAGE_ACCOUNT]
        )

    def get_queryset(self):
        return LighthouseAIConfiguration.objects.filter(
            tenant_id=self.request.tenant_id
        )

    def get_serializer_class(self):
        if self.action == "create":
            return LighthouseAIConfigurationWriteSerializer
        if self.action == "partial_update":
            return LighthouseAIConfigurationUpdateSerializer
        return super().get_serializer_class()

    def list(self, request, *args, **kwargs):
        services.ensure_env_configuration(str(request.tenant_id))
        return super().list(request, *args, **kwargs)

    def _read_response(self, configuration, response_status):
        serializer = LighthouseAIConfigurationSerializer(
            configuration, context=self.get_serializer_context()
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

    @action(detail=True, methods=["post"], url_name="connection")
    def connection(self, request, pk=None):
        configuration = self.get_object()
        with transaction.atomic():
            task = check_lighthouse_ai_connection_task.delay(
                configuration_id=str(configuration.id),
                tenant_id=str(request.tenant_id),
            )
        self.response_serializer_class = TaskSerializer
        return _task_response(task.id)


@extend_schema_view(
    list=extend_schema(tags=[TAG], summary="List supported LLM providers"),
    models=extend_schema(
        tags=[TAG], summary="List the models of a connected LLM provider"
    ),
)
class LighthouseSupportedProviderViewSet(BaseRLSViewSet):
    serializer_class = LighthouseSupportedProviderSerializer
    http_method_names = ["get"]
    filter_backends = []
    pagination_class = None
    lookup_value_regex = "[a-z_]+"

    def get_queryset(self):
        return LighthouseAIConfiguration.objects.none()

    def get_serializer_class(self):
        if self.action == "models":
            return LighthouseSupportedModelSerializer
        return super().get_serializer_class()

    def list(self, request, *args, **kwargs):
        serializer = self.get_serializer(llm.SUPPORTED_PROVIDERS, many=True)
        return Response(data=serializer.data)

    @action(detail=True, methods=["get"], url_name="models")
    def models(self, request, pk=None):
        if pk not in LighthouseAIConfiguration.ProviderChoices.values:
            raise NotFound("Unknown provider.")
        configuration = LighthouseAIConfiguration.objects.filter(
            tenant_id=request.tenant_id, provider_type=pk
        ).first()
        # Models are listed with the tenant's own key; until one is connected
        # there is nothing to ask the provider with.
        rows = llm.list_models(configuration) if configuration else []
        return Response(data=self.get_serializer(rows, many=True).data)


class LighthouseSessionFilter(FilterSet):
    is_archived = BooleanFilter()

    class Meta:
        model = LighthouseSession
        fields = {"id": ["exact", "in"]}


@extend_schema_view(
    list=extend_schema(tags=[TAG], summary="List the user's chat sessions"),
    retrieve=extend_schema(tags=[TAG], summary="Retrieve a chat session"),
    create=extend_schema(tags=[TAG], summary="Start a chat session"),
    partial_update=extend_schema(tags=[TAG], summary="Rename or archive a session"),
    destroy=extend_schema(tags=[TAG], summary="Delete a chat session"),
    messages=extend_schema(
        tags=[TAG],
        summary="List a session's messages, or send one",
        description="POST stores the user's message and starts the answer in the "
        "background; follow it on the session's event stream.",
    ),
)
class LighthouseSessionViewSet(_TaskResponseMixin, BaseRLSViewSet):
    queryset = LighthouseSession.objects.all()
    serializer_class = LighthouseSessionSerializer
    filterset_class = LighthouseSessionFilter
    http_method_names = ["get", "post", "patch", "delete"]
    search_fields = ["title"]
    ordering = ["-updated_at"]
    ordering_fields = ["inserted_at", "updated_at", "title"]

    def get_queryset(self):
        # Conversations are private to the user who started them.
        return LighthouseSession.objects.filter(
            tenant_id=self.request.tenant_id, user=self.request.user
        )

    def get_serializer_class(self):
        if self.action == "messages":
            if hasattr(self, "response_serializer_class"):
                return self.response_serializer_class
            if self.request.method == "POST":
                return LighthouseMessageCreateSerializer
            return LighthouseMessageSerializer
        return super().get_serializer_class()

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

    @action(
        detail=True,
        methods=["get", "post"],
        url_name="messages",
        filter_backends=[],
        pagination_class=None,
    )
    def messages(self, request, pk=None):
        session = self.get_object()
        if request.method == "GET":
            messages = LighthouseMessage.objects.filter(
                tenant_id=request.tenant_id, session=session
            ).order_by("id")
            return Response(data=self.get_serializer(messages, many=True).data)

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        tenant_id = str(request.tenant_id)
        with transaction.atomic():
            LighthouseMessage.objects.create(
                tenant_id=tenant_id,
                session=session,
                role=LighthouseMessage.RoleChoices.USER,
                parts=[
                    agent.new_part("text", part["content"])
                    for part in serializer.validated_data["parts"]
                ],
            )
            if not session.title:
                session.title = agent.session_title(
                    serializer.validated_data["parts"][0]["content"]
                )
            session.save(update_fields=["title", "updated_at"])
        # Queued after the commit above so the worker can read the message.
        task = lighthouse_chat_task.delay(
            tenant_id=tenant_id,
            session_id=str(session.id),
            user_id=str(request.user.id),
            provider=serializer.validated_data["provider"],
            model=serializer.validated_data.get("model") or None,
        )
        self.response_serializer_class = TaskSerializer
        return _task_response(task.id)


@extend_schema(exclude=True)
class LighthouseSessionEventStreamView(BaseSSEViewSet):
    """Live events of a chat run: text deltas, tool calls, end and errors."""

    def get_channels(self) -> set[str]:
        session = LighthouseSession.objects.filter(
            tenant_id=self.request.tenant_id,
            user=self.request.user,
            id=self.kwargs["session_id"],
        ).first()
        if session is None:
            raise NotFound("Session not found.")
        return {agent.channel_name(str(self.request.tenant_id), str(session.id))}
