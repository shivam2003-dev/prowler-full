import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from api.models import (
    LighthouseAIConfiguration,
    LighthouseMessage,
    LighthouseSession,
    StateChoices,
)
from django.urls import reverse
from lighthouse import agent, services
from lighthouse.tools import ToolContext, run_tool
from rest_framework import status

CONTENT_TYPE = "application/vnd.api+json"
SECRET = "sk-test-never-returned"


def _config_payload(config_id=None, **attributes):
    data = {"type": "lighthouse-ai-configurations", "attributes": attributes}
    if config_id:
        data["id"] = config_id
    return {"data": data}


def _create_config(client, **attributes):
    attributes = {
        "provider_type": "openai_compatible",
        "credentials": {"api_key": SECRET},
        "base_url": "https://openrouter.ai/api/v1",
        **attributes,
    }
    return client.post(
        reverse("lighthouse-ai-configuration-list"),
        data=_config_payload(**attributes),
        content_type=CONTENT_TYPE,
    )


def _make_config(tenant, **fields):
    configuration = LighthouseAIConfiguration(
        tenant_id=tenant.id,
        provider_type="openai_compatible",
        base_url="https://openrouter.ai/api/v1",
        default_model="test/model",
        **fields,
    )
    configuration.credentials_decoded = {"api_key": SECRET}
    configuration.save()
    return configuration


@pytest.mark.django_db
class TestLighthouseAIConfiguration:
    def test_create_encrypts_and_never_returns_credentials(self, authenticated_client):
        response = _create_config(authenticated_client)

        assert response.status_code == status.HTTP_201_CREATED, response.json()
        assert SECRET not in response.content.decode()
        attributes = response.json()["data"]["attributes"]
        assert attributes["provider_type"] == "openai_compatible"
        assert attributes["connected"] is None
        stored = LighthouseAIConfiguration.objects.get()
        assert SECRET.encode() not in bytes(stored.credentials)
        assert stored.credentials_decoded == {"api_key": SECRET}

        listed = authenticated_client.get(reverse("lighthouse-ai-configuration-list"))
        assert SECRET not in listed.content.decode()

    def test_create_validates_credentials_base_url_and_duplicates(
        self, authenticated_client
    ):
        no_key = _create_config(authenticated_client, credentials={})
        no_url = _create_config(authenticated_client, base_url=None)
        _create_config(authenticated_client)
        duplicate = _create_config(authenticated_client)

        assert no_key.status_code == status.HTTP_400_BAD_REQUEST
        assert no_url.status_code == status.HTTP_400_BAD_REQUEST
        assert duplicate.status_code == status.HTTP_400_BAD_REQUEST
        assert LighthouseAIConfiguration.objects.count() == 1

    def test_patch_model_keeps_credentials_and_connection_state(
        self, authenticated_client, tenants_fixture
    ):
        configuration = _make_config(tenants_fixture[0], connected=True)

        response = authenticated_client.patch(
            reverse(
                "lighthouse-ai-configuration-detail", kwargs={"pk": configuration.id}
            ),
            data=_config_payload(
                str(configuration.id),
                default_model="other/model",
                business_context="Fintech, PCI scope.",
            ),
            content_type=CONTENT_TYPE,
        )

        assert response.status_code == status.HTTP_200_OK, response.json()
        configuration.refresh_from_db()
        assert configuration.default_model == "other/model"
        assert configuration.business_context == "Fintech, PCI scope."
        assert configuration.connected is True
        assert configuration.credentials_decoded == {"api_key": SECRET}

    def test_new_credentials_reset_connection_state(
        self, authenticated_client, tenants_fixture
    ):
        configuration = _make_config(tenants_fixture[0], connected=True)

        authenticated_client.patch(
            reverse(
                "lighthouse-ai-configuration-detail", kwargs={"pk": configuration.id}
            ),
            data=_config_payload(
                str(configuration.id), credentials={"api_key": "sk-new"}
            ),
            content_type=CONTENT_TYPE,
        )

        configuration.refresh_from_db()
        assert configuration.connected is None
        assert configuration.credentials_decoded == {"api_key": "sk-new"}

    def test_env_key_bootstraps_one_configuration(self, authenticated_client, settings):
        settings.LIGHTHOUSE_OPENROUTER_API_KEY = SECRET
        settings.LIGHTHOUSE_DEFAULT_MODEL = "env/model"
        url = reverse("lighthouse-ai-configuration-list")

        first = authenticated_client.get(url)
        second = authenticated_client.get(url)

        assert len(first.json()["data"]) == len(second.json()["data"]) == 1
        attributes = first.json()["data"][0]["attributes"]
        assert attributes["provider_type"] == "openai_compatible"
        assert attributes["default_model"] == "env/model"
        assert SECRET not in first.content.decode()

    def test_env_key_does_not_override_an_existing_configuration(
        self, tenants_fixture, settings
    ):
        settings.LIGHTHOUSE_OPENROUTER_API_KEY = "sk-env"
        configuration = _make_config(tenants_fixture[0])

        services.ensure_env_configuration(str(tenants_fixture[0].id))

        assert LighthouseAIConfiguration.objects.get() == configuration
        assert configuration.credentials_decoded == {"api_key": SECRET}

    def test_supported_providers_and_models(
        self, authenticated_client, tenants_fixture
    ):
        providers = authenticated_client.get(
            reverse("lighthouse-supported-provider-list")
        )
        models_url = reverse(
            "lighthouse-supported-provider-models", kwargs={"pk": "openai_compatible"}
        )
        without_config = authenticated_client.get(models_url)
        _make_config(tenants_fixture[0])
        row = {
            "id": "test/model",
            "model_name": "Test Model",
            "max_input_tokens": 1000,
            "max_output_tokens": None,
            "supports_function_calling": True,
            "supports_vision": None,
            "supports_reasoning": False,
        }
        with patch("lighthouse.views.llm.list_models", return_value=[row]):
            with_config = authenticated_client.get(models_url)

        assert [p["id"] for p in providers.json()["data"]] == [
            "openai",
            "openai_compatible",
        ]
        assert without_config.json()["data"] == []
        model = with_config.json()["data"][0]
        assert model["id"] == "test/model"
        assert model["attributes"]["model_name"] == "Test Model"
        assert model["attributes"]["supports_function_calling"] is True


def _send(client, session_id, text="How many critical findings?"):
    return client.post(
        reverse("lighthouse-session-messages", kwargs={"pk": session_id}),
        data={
            "data": {
                "type": "lighthouse-messages",
                "attributes": {
                    "parts": [
                        {
                            "part_type": "text",
                            "content": {"text": f"<ctx>{text}", "display_text": text},
                        }
                    ],
                    "provider": "openai_compatible",
                    "model": "test/model",
                },
            }
        },
        content_type=CONTENT_TYPE,
    )


@pytest.mark.django_db
class TestLighthouseSessions:
    def _create(self, client, title=None):
        return client.post(
            reverse("lighthouse-session-list"),
            data={
                "data": {"type": "lighthouse-sessions", "attributes": {"title": title}}
            },
            content_type=CONTENT_TYPE,
        )

    def test_create_list_rename_and_archive(self, authenticated_client):
        created = self._create(authenticated_client)
        session_id = created.json()["data"]["id"]

        patched = authenticated_client.patch(
            reverse("lighthouse-session-detail", kwargs={"pk": session_id}),
            data={
                "data": {
                    "type": "lighthouse-sessions",
                    "id": session_id,
                    "attributes": {"title": "Renamed", "is_archived": True},
                }
            },
            content_type=CONTENT_TYPE,
        )
        active = authenticated_client.get(
            reverse("lighthouse-session-list"), {"filter[is_archived]": "false"}
        )

        assert created.status_code == status.HTTP_201_CREATED, created.json()
        assert created.json()["data"]["attributes"]["title"] is None
        assert patched.json()["data"]["attributes"]["title"] == "Renamed"
        assert patched.json()["data"]["attributes"]["is_archived"] is True
        assert active.json()["data"] == []

    def test_sessions_are_private_to_their_user(
        self, authenticated_client, tenants_fixture, users_fixture
    ):
        other = LighthouseSession.objects.create(
            tenant_id=tenants_fixture[0].id, user=users_fixture[0], title="Not mine"
        )

        listed = authenticated_client.get(reverse("lighthouse-session-list"))
        detail = authenticated_client.get(
            reverse("lighthouse-session-detail", kwargs={"pk": other.id})
        )
        stream = authenticated_client.get(
            reverse("lighthouse-session-event-stream", kwargs={"session_id": other.id}),
            HTTP_ACCEPT="text/event-stream",
        )

        assert listed.json()["data"] == []
        assert detail.status_code == status.HTTP_404_NOT_FOUND
        assert stream.status_code == status.HTTP_404_NOT_FOUND

    def test_send_stores_the_message_titles_the_session_and_queues_a_run(
        self, authenticated_client, tasks_fixture
    ):
        session_id = self._create(authenticated_client).json()["data"]["id"]
        with (
            patch("lighthouse.views.lighthouse_chat_task.delay") as delay,
            patch("lighthouse.views.Task.objects.get", return_value=tasks_fixture[0]),
        ):
            delay.return_value = SimpleNamespace(id=tasks_fixture[0].id)
            response = _send(authenticated_client, session_id)

        assert response.status_code == status.HTTP_202_ACCEPTED, response.json()
        assert response.json()["data"]["type"] == "tasks"
        kwargs = delay.call_args.kwargs
        assert kwargs["session_id"] == session_id
        assert kwargs["provider"] == "openai_compatible"
        assert kwargs["model"] == "test/model"
        message = LighthouseMessage.objects.get()
        assert message.role == "user"
        assert message.parts[0]["content"]["display_text"].startswith("How many")
        session = LighthouseSession.objects.get(id=session_id)
        # The title shows what the user typed, not the context-wrapped agent text.
        assert session.title == "How many critical findings?"

        listed = authenticated_client.get(
            reverse("lighthouse-session-messages", kwargs={"pk": session_id})
        )
        assert len(listed.json()["data"]) == 1
        assert listed.json()["data"][0]["attributes"]["parts"][0]["part_type"] == "text"

    def test_send_rejects_empty_and_non_text_parts(self, authenticated_client):
        session_id = self._create(authenticated_client).json()["data"]["id"]
        url = reverse("lighthouse-session-messages", kwargs={"pk": session_id})

        def post(parts):
            return authenticated_client.post(
                url,
                data={
                    "data": {
                        "type": "lighthouse-messages",
                        "attributes": {"parts": parts, "provider": "openai"},
                    }
                },
                content_type=CONTENT_TYPE,
            )

        assert post([]).status_code == status.HTTP_400_BAD_REQUEST
        assert (
            post([{"part_type": "text", "content": "  "}]).status_code
            == status.HTTP_400_BAD_REQUEST
        )
        assert (
            post([{"part_type": "tool_call", "content": {}}]).status_code
            == status.HTTP_400_BAD_REQUEST
        )
        assert not LighthouseMessage.objects.exists()


def _chunk(content=None, tool_calls=None, usage=None):
    choices = (
        []
        if usage is not None
        else [
            SimpleNamespace(
                delta=SimpleNamespace(content=content, tool_calls=tool_calls)
            )
        ]
    )
    return SimpleNamespace(choices=choices, usage=usage)


def _tool_delta(index, call_id=None, name=None, arguments=None):
    return SimpleNamespace(
        index=index,
        id=call_id,
        function=SimpleNamespace(name=name, arguments=arguments),
    )


@pytest.mark.django_db
@pytest.mark.usefixtures("set_user_admin_roles_fixture")
class TestRunChat:
    def _session(self, tenant, user, text="How many critical findings?"):
        session = LighthouseSession.objects.create(tenant_id=tenant.id, user=user)
        LighthouseMessage.objects.create(
            tenant_id=tenant.id,
            session=session,
            role="user",
            parts=[agent.new_part("text", {"text": text})],
        )
        return session

    def _run(self, tenant, user, session, rounds):
        client = MagicMock()
        client.chat.completions.create.side_effect = [iter(r) for r in rounds]
        events = []
        with (
            patch("lighthouse.agent.llm.build_client", return_value=client),
            patch(
                "lighthouse.agent.send_event",
                side_effect=lambda channel, event, data: events.append((event, data)),
            ),
        ):
            result = agent.run_chat(
                str(tenant.id), str(session.id), str(user.id), "openai_compatible", None
            )
        return result, events, client

    def test_tool_round_then_answer_is_streamed_and_persisted(
        self, tenants_fixture, create_test_user, findings_fixture
    ):
        tenant = tenants_fixture[0]
        scan = findings_fixture[0].scan
        scan.state = StateChoices.COMPLETED
        scan.save()
        _make_config(tenant)
        session = self._session(tenant, create_test_user)
        usage = SimpleNamespace(prompt_tokens=10, completion_tokens=5, total_tokens=15)
        rounds = [
            [
                _chunk(
                    tool_calls=[
                        _tool_delta(0, "call_1", "prowler_get_findings_overview", "")
                    ]
                ),
                _chunk(tool_calls=[_tool_delta(0, arguments="{}")]),
                _chunk(usage=usage),
            ],
            [
                _chunk(content="You have "),
                _chunk(content="1 critical."),
                _chunk(usage=usage),
            ],
        ]

        result, events, client = self._run(tenant, create_test_user, session, rounds)

        assert [event for event, _ in events] == [
            "tool_call.start",
            "tool_call.end",
            "message.delta",
            "message.delta",
            "message.end",
        ]
        assert events[0][1] == {
            "tool_call_id": "call_1",
            "tool_name": "prowler_get_findings_overview",
        }
        assert events[1][1] == {"tool_call_id": "call_1", "outcome": "success"}
        message = LighthouseMessage.objects.get(session=session, role="assistant")
        assert events[-1][1] == {"message_id": str(message.id)}
        assert result["message_id"] == str(message.id)
        assert message.model == "test/model"
        assert message.token_usage["total_tokens"] == 30
        tool_part, text_part = message.parts
        assert tool_part["part_type"] == "tool_call"
        assert tool_part["tool_call_outcome"] == "success"
        assert tool_part["content"]["tool_name"] == "prowler_get_findings_overview"
        assert "failing_by_severity" in tool_part["content"]["result"]
        assert text_part["content"] == {"text": "You have 1 critical."}
        # The second model call carries the tool result back.
        second_call_messages = client.chat.completions.create.call_args_list[1].kwargs[
            "messages"
        ]
        assert second_call_messages[-1]["role"] == "tool"
        assert second_call_messages[0]["role"] == "system"

    def test_missing_configuration_is_reported_as_an_error_event(
        self, tenants_fixture, create_test_user
    ):
        session = self._session(tenants_fixture[0], create_test_user)

        result, events, _ = self._run(tenants_fixture[0], create_test_user, session, [])

        assert result == {"error": "not_configured"}
        assert [event for event, _ in events] == ["error"]
        assert events[0][1]["code"] == "not_configured"
        assert LighthouseMessage.objects.filter(role="assistant").count() == 0

    def test_provider_failure_publishes_error_without_leaking_the_key(
        self, tenants_fixture, create_test_user
    ):
        tenant = tenants_fixture[0]
        _make_config(tenant)
        session = self._session(tenant, create_test_user)
        client = MagicMock()
        client.chat.completions.create.side_effect = RuntimeError("401 invalid key")
        events = []
        with (
            patch("lighthouse.agent.llm.build_client", return_value=client),
            patch(
                "lighthouse.agent.send_event",
                side_effect=lambda channel, event, data: events.append((event, data)),
            ),
            pytest.raises(RuntimeError),
        ):
            agent.run_chat(
                str(tenant.id),
                str(session.id),
                str(create_test_user.id),
                "openai_compatible",
                None,
            )

        assert events == [("error", {"code": "llm_error", "detail": "401 invalid key"})]
        assert SECRET not in json.dumps(events)


@pytest.mark.django_db
class TestTools:
    def test_overview_and_search_read_latest_scan_findings(
        self, tenants_fixture, findings_fixture
    ):
        scan = findings_fixture[0].scan
        scan.state = StateChoices.COMPLETED
        scan.save()
        context = ToolContext(str(tenants_fixture[0].id))

        overview, outcome = run_tool(context, "prowler_get_findings_overview", "{}")
        search, _ = run_tool(
            context,
            "prowler_search_security_findings",
            json.dumps({"severity": ["CRITICAL"], "status": ["fail"], "limit": 5}),
        )

        assert outcome == "success"
        assert json.loads(overview)["failing_by_severity"]["critical"] >= 1
        found = json.loads(search)
        assert found["total_matching"] >= 1
        assert {row["severity"] for row in found["findings"]} == {"critical"}

    def test_unknown_tool_and_bad_arguments_are_errors_not_exceptions(
        self, tenants_fixture
    ):
        context = ToolContext(str(tenants_fixture[0].id))

        assert run_tool(context, "drop_database", "{}")[1] == "error"
        assert run_tool(context, "prowler_list_scans", "not json")[1] == "error"
        assert (
            run_tool(context, "prowler_get_finding_details", '{"finding_id": "x"}')[1]
            == "error"
        )
