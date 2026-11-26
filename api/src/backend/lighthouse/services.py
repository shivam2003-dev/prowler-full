from api.db_router import MainRouter
from api.db_utils import rls_transaction
from api.models import LighthouseAIConfiguration
from django.conf import settings
from lighthouse import llm


def ensure_env_configuration(tenant_id: str) -> None:
    """Create an OpenRouter configuration from the server's environment.

    Lets a self-hosted deployment enable chat by setting OPENROUTER_API_KEY,
    without pasting the key into the UI. Runs only while the tenant has no
    configuration, so a configuration the user deletes or edits later is not
    silently recreated on top of theirs.
    """
    api_key = settings.LIGHTHOUSE_OPENROUTER_API_KEY
    if not api_key:
        return
    # Called from GET requests, which may run on the read replica; the write
    # goes to the primary inside its own tenant-scoped transaction.
    with rls_transaction(tenant_id, using=MainRouter.default_db):
        configurations = LighthouseAIConfiguration.objects.using(
            MainRouter.default_db
        ).filter(tenant_id=tenant_id)
        if configurations.exists():
            return
        configuration = LighthouseAIConfiguration(
            tenant_id=tenant_id,
            provider_type=LighthouseAIConfiguration.ProviderChoices.OPENAI_COMPATIBLE,
            base_url=llm.OPENROUTER_BASE_URL,
            default_model=settings.LIGHTHOUSE_DEFAULT_MODEL,
        )
        configuration.credentials_decoded = {"api_key": api_key}
        configuration.save(using=MainRouter.default_db)
