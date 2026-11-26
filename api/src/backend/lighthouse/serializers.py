from api.models import LighthouseAIConfiguration, LighthouseMessage, LighthouseSession
from api.v1.serializers import BaseSerializerV1, BaseWriteSerializer, RLSSerializer
from rest_framework_json_api import serializers
from rest_framework_json_api.serializers import ValidationError

MAX_MESSAGE_CHARS = 100_000


class LighthouseAIConfigurationSerializer(RLSSerializer):
    class Meta:
        model = LighthouseAIConfiguration
        fields = [
            "id",
            "inserted_at",
            "updated_at",
            "provider_type",
            "base_url",
            "default_model",
            "business_context",
            "connected",
            "connection_last_checked_at",
        ]


class LighthouseAIConfigurationWriteSerializer(RLSSerializer, BaseWriteSerializer):
    credentials = serializers.DictField(write_only=True, required=True)

    class Meta:
        model = LighthouseAIConfiguration
        fields = [
            "id",
            "provider_type",
            "credentials",
            "base_url",
            "default_model",
            "business_context",
        ]
        extra_kwargs = {"id": {"read_only": True}}

    def validate_credentials(self, value):
        api_key = value.get("api_key")
        if not isinstance(api_key, str) or not api_key.strip():
            raise ValidationError("`api_key` is required.")
        if set(value) - {"api_key"}:
            raise ValidationError("Only `api_key` is accepted.")
        return {"api_key": api_key.strip()}

    def validate(self, attrs):
        attrs = super().validate(attrs)
        provider_type = attrs.get(
            "provider_type", getattr(self.instance, "provider_type", None)
        )
        base_url = attrs.get("base_url", getattr(self.instance, "base_url", None))
        compatible = LighthouseAIConfiguration.ProviderChoices.OPENAI_COMPATIBLE
        if provider_type == compatible and not base_url:
            raise ValidationError(
                {"base_url": "A base URL is required for OpenAI-compatible providers."}
            )
        if (
            self.instance is None
            and LighthouseAIConfiguration.objects.filter(
                tenant_id=self.context.get("tenant_id"), provider_type=provider_type
            ).exists()
        ):
            raise ValidationError(
                {"provider_type": "This provider is already configured."}
            )
        return attrs

    def _apply(self, instance, validated_data):
        credentials = validated_data.pop("credentials", None)
        for field, value in validated_data.items():
            setattr(instance, field, value)
        if credentials is not None:
            instance.credentials_decoded = credentials
            # New credentials have not been verified yet.
            instance.connected = None
            instance.connection_last_checked_at = None
        instance.save()
        return instance

    def create(self, validated_data):
        instance = LighthouseAIConfiguration(tenant_id=self.context.get("tenant_id"))
        return self._apply(instance, validated_data)

    def update(self, instance, validated_data):
        return self._apply(instance, validated_data)


class LighthouseAIConfigurationUpdateSerializer(
    LighthouseAIConfigurationWriteSerializer
):
    credentials = serializers.DictField(write_only=True, required=False)

    class Meta(LighthouseAIConfigurationWriteSerializer.Meta):
        fields = ["id", "credentials", "base_url", "default_model", "business_context"]


class LighthouseSupportedProviderSerializer(BaseSerializerV1):
    id = serializers.CharField()
    name = serializers.CharField()
    credentials_optional = serializers.BooleanField()

    class Meta:
        resource_name = "lighthouse-supported-providers"


class LighthouseSupportedModelSerializer(BaseSerializerV1):
    id = serializers.CharField()
    model_name = serializers.CharField()
    max_input_tokens = serializers.IntegerField(allow_null=True)
    max_output_tokens = serializers.IntegerField(allow_null=True)
    supports_function_calling = serializers.BooleanField(allow_null=True)
    supports_vision = serializers.BooleanField(allow_null=True)
    supports_reasoning = serializers.BooleanField(allow_null=True)

    class Meta:
        resource_name = "lighthouse-supported-models"


class LighthouseSessionSerializer(RLSSerializer):
    class Meta:
        model = LighthouseSession
        fields = ["id", "inserted_at", "updated_at", "title", "is_archived"]
        extra_kwargs = {
            "title": {"required": False, "allow_null": True},
            "is_archived": {"required": False},
        }


class LighthouseMessageSerializer(RLSSerializer):
    class Meta:
        model = LighthouseMessage
        fields = ["id", "inserted_at", "role", "model", "token_usage", "parts"]


class LighthouseMessageCreateSerializer(BaseSerializerV1):
    parts = serializers.ListField(child=serializers.DictField(), min_length=1)
    provider = serializers.ChoiceField(
        choices=LighthouseAIConfiguration.ProviderChoices.choices
    )
    model = serializers.CharField(required=False, allow_null=True, max_length=200)

    class Meta:
        resource_name = "lighthouse-messages"

    def validate_parts(self, value):
        cleaned = []
        for part in value:
            if part.get("part_type") != "text":
                raise ValidationError("Only `text` parts can be sent.")
            content = part.get("content")
            text = content.get("text") if isinstance(content, dict) else content
            if not isinstance(text, str) or not text.strip():
                raise ValidationError("A text part needs non-empty content.")
            if len(text) > MAX_MESSAGE_CHARS:
                raise ValidationError("The message is too long.")
            cleaned.append({"part_type": "text", "content": content})
        return cleaned
