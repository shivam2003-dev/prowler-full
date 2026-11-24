"""Lighthouse AI chat run: stream an answer, calling tools as the model asks."""

import json
from datetime import UTC, datetime
from uuid import uuid4

from api.db_utils import rls_transaction
from api.models import (
    LighthouseAIConfiguration,
    LighthouseMessage,
    LighthouseSession,
    User,
)
from api.rbac.permissions import get_providers, get_role
from api.sse import make_channel_name
from celery.utils.log import get_task_logger
from django_eventstream import send_event
from lighthouse import llm
from lighthouse.tools import TOOL_SPECS, ToolContext, run_tool

logger = get_task_logger(__name__)

CHANNEL_PREFIX = "lighthouse-session"
MAX_TOOL_ROUNDS = 8
MAX_HISTORY_MESSAGES = 30
TITLE_LENGTH = 60

EVENT_DELTA = "message.delta"
EVENT_TOOL_START = "tool_call.start"
EVENT_TOOL_END = "tool_call.end"
EVENT_END = "message.end"
EVENT_ERROR = "error"

SYSTEM_PROMPT = """You are Lighthouse AI, the security analyst built into Prowler.
You help the user understand and act on the cloud security posture Prowler found.

Rules:
- Answer from Prowler data. Call the tools to get it; never invent findings,
  counts, resources or account ids. If the tools return nothing, say so.
- Tool data covers the latest completed scan of each connected provider.
- Be concise and concrete. Use Markdown; use tables for lists of findings.
- When you recommend a fix, say what to change and why it lowers risk.
- You cannot change anything in the user's cloud accounts or in Prowler.
Today is {today}."""


class ChatError(Exception):
    """A failure to report to the user as-is."""

    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code
        self.detail = detail


def channel_name(tenant_id: str, session_id: str) -> str:
    return make_channel_name(CHANNEL_PREFIX, tenant_id, session_id)


def text_of(content) -> str:
    """Text the model should read from a stored part's content."""
    if isinstance(content, str):
        return content
    if isinstance(content, dict) and isinstance(content.get("text"), str):
        return content["text"]
    return ""


def display_text_of(content) -> str:
    if isinstance(content, dict) and isinstance(content.get("display_text"), str):
        return content["display_text"]
    return text_of(content)


def new_part(part_type: str, content, outcome: str | None = None) -> dict:
    now = datetime.now(tz=UTC).isoformat()
    return {
        "id": str(uuid4()),
        "part_type": part_type,
        "content": content,
        "tool_call_outcome": outcome,
        "inserted_at": now,
        "updated_at": now,
    }


def _history(session: LighthouseSession) -> list[dict]:
    """Earlier turns as plain text. Old tool traffic is dropped on purpose:
    the answer it produced is already in the assistant's text."""
    stored = list(session.messages.order_by("-id")[:MAX_HISTORY_MESSAGES])
    messages = []
    for message in reversed(stored):
        text = "\n".join(
            text_of(part.get("content"))
            for part in message.parts
            if part.get("part_type") == "text"
        ).strip()
        if text:
            messages.append({"role": message.role, "content": text})
    return messages


def _system_prompt(configuration: LighthouseAIConfiguration) -> str:
    prompt = SYSTEM_PROMPT.format(today=datetime.now(tz=UTC).date().isoformat())
    if configuration.business_context.strip():
        prompt += (
            "\n\nContext the user gave about their organization:\n"
            + configuration.business_context.strip()
        )
    return prompt


def _stream_round(
    client, model: str, messages: list, publish
) -> tuple[str, list, dict]:
    """One model call. Streams text deltas; returns (text, tool_calls, usage)."""
    stream = client.chat.completions.create(
        model=model,
        messages=messages,
        tools=TOOL_SPECS,
        stream=True,
        stream_options={"include_usage": True},
    )
    text = ""
    calls: dict[int, dict] = {}
    usage: dict = {}
    for chunk in stream:
        if chunk.usage is not None:
            usage = {
                "prompt_tokens": chunk.usage.prompt_tokens,
                "completion_tokens": chunk.usage.completion_tokens,
                "total_tokens": chunk.usage.total_tokens,
            }
        if not chunk.choices:
            continue
        delta = chunk.choices[0].delta
        if delta.content:
            text += delta.content
            publish(EVENT_DELTA, {"content": delta.content})
        for call in delta.tool_calls or []:
            entry = calls.setdefault(
                call.index, {"id": "", "name": "", "arguments": ""}
            )
            if call.id:
                entry["id"] = call.id
            if call.function and call.function.name:
                entry["name"] += call.function.name
            if call.function and call.function.arguments:
                entry["arguments"] += call.function.arguments
    return text, [calls[index] for index in sorted(calls)], usage


def run_chat(
    tenant_id: str, session_id: str, user_id: str, provider: str, model: str | None
) -> dict:
    """Answer the session's last user message and stream it over SSE."""
    channel = channel_name(tenant_id, session_id)

    def publish(event: str, data: dict) -> None:
        send_event(channel, event, data)

    try:
        with rls_transaction(tenant_id):
            session = LighthouseSession.objects.get(id=session_id)
            configuration = LighthouseAIConfiguration.objects.filter(
                tenant_id=tenant_id, provider_type=provider
            ).first()
            if configuration is None:
                raise ChatError(
                    "not_configured",
                    "This LLM provider is not connected. Connect it in Lighthouse "
                    "AI settings.",
                )
            chosen_model = model or configuration.default_model
            if not chosen_model:
                raise ChatError(
                    "model_required", "Select a model for this provider first."
                )
            client = llm.build_client(configuration)
            messages = [
                {"role": "system", "content": _system_prompt(configuration)},
                *_history(session),
            ]
            role = get_role(User.objects.get(id=user_id), tenant_id)
            providers = None if role.unlimited_visibility else get_providers(role)

        parts: list[dict] = []
        usage_total: dict = {}
        for _ in range(MAX_TOOL_ROUNDS):
            text, tool_calls, usage = _stream_round(
                client, chosen_model, messages, publish
            )
            for key, value in usage.items():
                usage_total[key] = usage_total.get(key, 0) + (value or 0)
            if text:
                parts.append(new_part("text", {"text": text}))
            if not tool_calls:
                break

            messages.append(
                {
                    "role": "assistant",
                    "content": text or None,
                    "tool_calls": [
                        {
                            "id": call["id"],
                            "type": "function",
                            "function": {
                                "name": call["name"],
                                "arguments": call["arguments"] or "{}",
                            },
                        }
                        for call in tool_calls
                    ],
                }
            )
            for call in tool_calls:
                publish(
                    EVENT_TOOL_START,
                    {"tool_call_id": call["id"], "tool_name": call["name"]},
                )
                with rls_transaction(tenant_id):
                    result, outcome = run_tool(
                        ToolContext(tenant_id, providers),
                        call["name"],
                        call["arguments"],
                    )
                publish(
                    EVENT_TOOL_END, {"tool_call_id": call["id"], "outcome": outcome}
                )
                messages.append(
                    {"role": "tool", "tool_call_id": call["id"], "content": result}
                )
                try:
                    arguments = json.loads(call["arguments"] or "{}")
                except ValueError:
                    arguments = call["arguments"]
                parts.append(
                    new_part(
                        "tool_call",
                        {
                            "tool_call_id": call["id"],
                            "tool_name": call["name"],
                            "arguments": arguments,
                            "result": json.loads(result),
                            "outcome": outcome,
                        },
                        outcome,
                    )
                )
        else:
            note = "I stopped here: this question needed more tool calls than I allow in one answer."
            publish(EVENT_DELTA, {"content": note})
            parts.append(new_part("text", {"text": note}))

        if not parts:
            raise ChatError("empty_response", "The model returned an empty answer.")

        with rls_transaction(tenant_id):
            message = LighthouseMessage.objects.create(
                tenant_id=tenant_id,
                session=session,
                role=LighthouseMessage.RoleChoices.ASSISTANT,
                model=chosen_model,
                token_usage=usage_total or None,
                parts=parts,
            )
            session.save(update_fields=["updated_at"])
        publish(EVENT_END, {"message_id": str(message.id)})
        return {"message_id": str(message.id), "token_usage": usage_total}
    except ChatError as error:
        publish(EVENT_ERROR, {"code": error.code, "detail": error.detail})
        return {"error": error.code}
    except Exception as error:
        logger.exception("Lighthouse chat run failed for session %s", session_id)
        # Provider errors (bad key, unknown model, quota) are the user's to fix,
        # so their message is passed on. Nothing here carries the API key.
        publish(
            EVENT_ERROR,
            {"code": "llm_error", "detail": str(error) or error.__class__.__name__},
        )
        raise


def session_title(content) -> str:
    title = " ".join(display_text_of(content).split())
    return title[:TITLE_LENGTH] or "New chat"
