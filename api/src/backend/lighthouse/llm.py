"""LLM access for Lighthouse AI: OpenAI and any OpenAI-compatible endpoint."""

from datetime import UTC, datetime

from api.models import LighthouseAIConfiguration
from django.core.cache import cache
from openai import OpenAI

OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
MODELS_CACHE_SECONDS = 600
REQUEST_TIMEOUT_SECONDS = 120

SUPPORTED_PROVIDERS = [
    {
        "id": LighthouseAIConfiguration.ProviderChoices.OPENAI.value,
        "name": "OpenAI",
        "credentials_optional": False,
    },
    {
        "id": LighthouseAIConfiguration.ProviderChoices.OPENAI_COMPATIBLE.value,
        "name": "OpenAI Compatible",
        "credentials_optional": False,
    },
]


def build_client(configuration: LighthouseAIConfiguration) -> OpenAI:
    is_compatible = (
        configuration.provider_type
        == LighthouseAIConfiguration.ProviderChoices.OPENAI_COMPATIBLE
    )
    return OpenAI(
        api_key=configuration.credentials_decoded.get("api_key", ""),
        base_url=configuration.base_url if is_compatible else None,
        timeout=REQUEST_TIMEOUT_SECONDS,
        max_retries=1,
    )


def _model_row(model) -> dict:
    """Normalize a /models entry. Capability fields exist on OpenRouter only."""
    extra = getattr(model, "model_extra", None) or {}
    supported = extra.get("supported_parameters")
    modalities = (extra.get("architecture") or {}).get("input_modalities")
    top_provider = extra.get("top_provider") or {}
    return {
        "id": model.id,
        "model_name": extra.get("name") or model.id,
        "max_input_tokens": extra.get("context_length"),
        "max_output_tokens": top_provider.get("max_completion_tokens"),
        "supports_function_calling": (
            "tools" in supported if isinstance(supported, list) else None
        ),
        "supports_vision": (
            "image" in modalities if isinstance(modalities, list) else None
        ),
        "supports_reasoning": (
            "reasoning" in supported if isinstance(supported, list) else None
        ),
    }


def list_models(configuration: LighthouseAIConfiguration) -> list[dict]:
    """Models the configured key can use, cached to keep page loads off the API."""
    cache_key = f"lighthouse-ai-models:{configuration.id}:{configuration.updated_at.timestamp()}"
    cached = cache.get(cache_key)
    if cached is not None:
        return cached

    rows = [_model_row(model) for model in build_client(configuration).models.list()]
    # A provider that reports capabilities lists hundreds of models; the chat
    # agent needs tool calling, so the ones that cannot do it are left out.
    if any(row["supports_function_calling"] for row in rows):
        rows = [row for row in rows if row["supports_function_calling"]]
    rows.sort(key=lambda row: row["id"])
    cache.set(cache_key, rows, MODELS_CACHE_SECONDS)
    return rows


def check_connection(configuration: LighthouseAIConfiguration) -> dict:
    """Verify the credentials by listing models, and record the result."""
    error = None
    try:
        build_client(configuration).models.list()
        connected = True
    except Exception as exc:  # noqa: BLE001 - any failure means "not connected"
        connected = False
        error = str(exc) or exc.__class__.__name__

    configuration.connected = connected
    configuration.connection_last_checked_at = datetime.now(tz=UTC)
    configuration.save(
        update_fields=["connected", "connection_last_checked_at", "updated_at"]
    )
    return {"connected": connected, "error": error}
