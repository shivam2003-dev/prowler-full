from api.models import AlertRecipient, AlertRule
from django_filters.rest_framework import ChoiceFilter, FilterSet


class AlertRuleFilter(FilterSet):
    trigger = ChoiceFilter(choices=AlertRule.TriggerChoices.choices)

    class Meta:
        model = AlertRule
        fields = {
            "id": ["exact", "in"],
            "name": ["exact", "icontains"],
            "enabled": ["exact"],
            "inserted_at": ["gte", "lte"],
            "updated_at": ["gte", "lte"],
        }


class AlertRecipientFilter(FilterSet):
    status = ChoiceFilter(choices=AlertRecipient.StatusChoices.choices)

    class Meta:
        model = AlertRecipient
        fields = {
            "id": ["exact", "in"],
            "email": ["exact", "icontains"],
        }
