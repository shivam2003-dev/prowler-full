from api.models import Provider, ScanConfiguration, ScanConfigurationProvider

MAX_CONFIGURATION_BYTES = 256 * 1024


class ConfigurationError(ValueError):
    """The configuration is not a mapping of provider sections."""


def validate_configuration(configuration) -> dict:
    """Check the shape Prowler's config loader expects: `{provider_type: {...}}`."""
    if not isinstance(configuration, dict) or not configuration:
        raise ConfigurationError(
            "Configuration must be a mapping with provider sections."
        )
    known = set(Provider.ProviderChoices.values)
    unknown = sorted(str(key) for key in configuration if key not in known)
    if unknown:
        raise ConfigurationError(
            f"Unknown provider sections: {', '.join(unknown)}. "
            f"Valid sections: {', '.join(sorted(known))}."
        )
    not_mappings = sorted(
        key for key, section in configuration.items() if not isinstance(section, dict)
    )
    if not_mappings:
        raise ConfigurationError(
            f"These sections must be mappings: {', '.join(not_mappings)}."
        )
    return configuration


def set_providers(scan_configuration: ScanConfiguration, providers) -> None:
    """Attach exactly `providers`, moving each off any other configuration."""
    tenant_id = scan_configuration.tenant_id
    provider_ids = [provider.id for provider in providers]

    links = ScanConfigurationProvider.objects.filter(tenant_id=tenant_id)
    links.filter(scan_configuration=scan_configuration).exclude(
        provider_id__in=provider_ids
    ).delete()
    links.filter(provider_id__in=provider_ids).exclude(
        scan_configuration=scan_configuration
    ).delete()

    attached = set(
        links.filter(scan_configuration=scan_configuration).values_list(
            "provider_id", flat=True
        )
    )
    ScanConfigurationProvider.objects.bulk_create(
        ScanConfigurationProvider(
            tenant_id=tenant_id,
            scan_configuration=scan_configuration,
            provider_id=provider_id,
        )
        for provider_id in dict.fromkeys(provider_ids)
        if provider_id not in attached
    )
