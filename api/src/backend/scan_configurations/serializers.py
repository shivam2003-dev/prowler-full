import json

from api.models import ScanConfiguration
from api.v1.serializer_utils.base import YamlOrJsonField
from api.v1.serializers import BaseWriteSerializer, RLSSerializer
from rest_framework_json_api import serializers
from rest_framework_json_api.serializers import ValidationError
from scan_configurations import services


class ScanConfigurationSerializer(RLSSerializer):
    providers = serializers.SerializerMethodField()

    class Meta:
        model = ScanConfiguration
        fields = [
            "id",
            "inserted_at",
            "updated_at",
            "name",
            "configuration",
            "providers",
        ]

    def get_providers(self, scan_configuration) -> list[str]:
        # Prefetched by the viewset.
        return sorted(
            str(provider.id) for provider in scan_configuration.providers.all()
        )


class ScanConfigurationWriteSerializer(RLSSerializer, BaseWriteSerializer):
    configuration = YamlOrJsonField()
    provider_ids = serializers.ListField(
        child=serializers.UUIDField(),
        required=False,
        help_text="Providers that follow this configuration. Replaces the current "
        "list; a provider attached elsewhere is moved here.",
    )

    class Meta:
        model = ScanConfiguration
        fields = ["id", "name", "configuration", "provider_ids"]
        extra_kwargs = {"id": {"read_only": True}}

    def validate_name(self, value):
        value = value.strip()
        duplicates = ScanConfiguration.objects.filter(
            tenant_id=self.context.get("tenant_id"), name=value
        )
        if self.instance is not None:
            duplicates = duplicates.exclude(id=self.instance.id)
        if duplicates.exists():
            raise ValidationError("A scan configuration with this name already exists.")
        return value

    def validate_configuration(self, value):
        try:
            services.validate_configuration(value)
        except services.ConfigurationError as error:
            raise ValidationError(str(error)) from error
        if len(json.dumps(value)) > services.MAX_CONFIGURATION_BYTES:
            raise ValidationError("Configuration is too large.")
        return value

    def validate_provider_ids(self, value):
        provider_ids = list(dict.fromkeys(value))
        providers = self.context["provider_queryset"].filter(id__in=provider_ids)
        found = {provider.id: provider for provider in providers}
        missing = [str(pid) for pid in provider_ids if pid not in found]
        if missing:
            raise ValidationError(f"Providers not found: {', '.join(missing)}.")
        return [found[provider_id] for provider_id in provider_ids]

    def create(self, validated_data):
        providers = validated_data.pop("provider_ids", [])
        scan_configuration = super().create(validated_data)
        services.set_providers(scan_configuration, providers)
        return scan_configuration

    def update(self, instance, validated_data):
        providers = validated_data.pop("provider_ids", None)
        scan_configuration = super().update(instance, validated_data)
        if providers is not None:
            services.set_providers(scan_configuration, providers)
        return scan_configuration


class ScanConfigurationUpdateSerializer(ScanConfigurationWriteSerializer):
    class Meta(ScanConfigurationWriteSerializer.Meta):
        extra_kwargs = {
            **ScanConfigurationWriteSerializer.Meta.extra_kwargs,
            "name": {"required": False},
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["configuration"].required = False
