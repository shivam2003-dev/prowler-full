from alerts import dsl, services
from api.models import AlertRecipient, AlertRule
from api.v1.serializers import (
    BaseSerializerV1,
    BaseWriteSerializer,
    RLSSerializer,
)
from rest_framework_json_api import serializers
from rest_framework_json_api.serializers import ValidationError

MAX_RECIPIENTS_PER_RULE = 50


class AlertRecipientSerializer(RLSSerializer):
    class Meta:
        model = AlertRecipient
        fields = [
            "id",
            "inserted_at",
            "updated_at",
            "email",
            "status",
            "confirmation_sent_at",
            "confirmation_expires_at",
            "confirmed_at",
            "unsubscribed_at",
            "last_bounce_at",
        ]


class AlertRuleSerializer(RLSSerializer):
    recipient_emails = serializers.SerializerMethodField()

    class Meta:
        model = AlertRule
        fields = [
            "id",
            "inserted_at",
            "updated_at",
            "name",
            "description",
            "enabled",
            "trigger",
            "condition",
            "schema_version",
            "recipient_emails",
            "slack_channels",
            "last_evaluated_at",
            "last_triggered_at",
            "created_by",
        ]

    included_serializers = {
        "created_by": "api.v1.serializers.UserIncludeSerializer",
    }

    def get_recipient_emails(self, rule) -> list[str]:
        # `recipients` is prefetched by the viewset; sort in Python to reuse it.
        return sorted(recipient.email for recipient in rule.recipients.all())


class AlertRuleWriteSerializer(RLSSerializer, BaseWriteSerializer):
    """Shared by create and update; update makes every field optional."""

    recipient_emails = serializers.ListField(
        child=serializers.EmailField(max_length=254),
        required=False,
        max_length=MAX_RECIPIENTS_PER_RULE,
        help_text="Replaces the rule's recipients. Omit to leave them unchanged.",
    )
    slack_channels = serializers.ListField(
        child=serializers.DictField(), required=False
    )

    class Meta:
        model = AlertRule
        fields = [
            "id",
            "name",
            "description",
            "enabled",
            "trigger",
            "condition",
            "schema_version",
            "recipient_emails",
            "slack_channels",
        ]
        extra_kwargs = {
            "id": {"read_only": True},
            "description": {"required": False},
            "enabled": {"required": False},
            "schema_version": {"required": False},
        }

    def validate_name(self, value):
        value = value.strip()
        if not value:
            raise ValidationError("Name is required.")
        duplicates = AlertRule.objects.filter(
            tenant_id=self.context.get("tenant_id"), name=value
        )
        if self.instance is not None:
            duplicates = duplicates.exclude(id=self.instance.id)
        if duplicates.exists():
            raise ValidationError("An alert with this name already exists.")
        return value

    def validate_condition(self, value):
        try:
            return dsl.validate_condition(value)
        except dsl.ConditionError as error:
            raise ValidationError(str(error)) from error

    def validate_schema_version(self, value):
        if value != dsl.SCHEMA_VERSION:
            raise ValidationError(
                f"Unsupported schema version. Expected {dsl.SCHEMA_VERSION}."
            )
        return value

    def validate_slack_channels(self, value):
        if value:
            raise ValidationError(
                "Slack delivery is not available in this deployment. "
                "Use email recipients."
            )
        return value

    def create(self, validated_data):
        recipient_emails = validated_data.pop("recipient_emails", [])
        request = self.context.get("request")
        validated_data["created_by"] = getattr(request, "user", None)
        rule = super().create(validated_data)
        services.set_rule_recipients(rule, recipient_emails)
        return rule

    def update(self, instance, validated_data):
        recipient_emails = validated_data.pop("recipient_emails", None)
        rule = super().update(instance, validated_data)
        if recipient_emails is not None:
            services.set_rule_recipients(rule, recipient_emails)
        return rule


class AlertRuleUpdateSerializer(AlertRuleWriteSerializer):
    class Meta(AlertRuleWriteSerializer.Meta):
        extra_kwargs = {
            **AlertRuleWriteSerializer.Meta.extra_kwargs,
            "name": {"required": False},
            "trigger": {"required": False},
            "condition": {"required": False},
        }


class AlertRuleSeedSerializer(BaseSerializerV1):
    filter_bag = serializers.JSONField(write_only=True)
    name = serializers.CharField(read_only=True)
    description = serializers.CharField(read_only=True)
    trigger = serializers.CharField(read_only=True)
    condition = serializers.JSONField(read_only=True)
    schema_version = serializers.IntegerField(read_only=True)

    class Meta:
        resource_name = "alert-rule-seedings"


class AlertRulePreviewSerializer(BaseSerializerV1):
    condition = serializers.JSONField(write_only=True)
    summary = serializers.JSONField(read_only=True)
    sample_finding_ids = serializers.ListField(
        child=serializers.CharField(), read_only=True
    )
    evaluation_failed = serializers.BooleanField(read_only=True)
    last_error = serializers.CharField(read_only=True, allow_null=True)
    summary_fallback = serializers.BooleanField(read_only=True)
    duration_ms = serializers.IntegerField(read_only=True)

    class Meta:
        resource_name = "alert-rule-previews"

    def validate_condition(self, value):
        try:
            return dsl.validate_condition(value)
        except dsl.ConditionError as error:
            raise ValidationError(str(error)) from error
