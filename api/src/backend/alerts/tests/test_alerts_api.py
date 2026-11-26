from uuid import uuid4

import pytest
from alerts import services
from api.models import (
    AlertEvent,
    AlertRecipient,
    AlertRule,
    Finding,
    StateChoices,
)
from django.core import mail
from django.urls import reverse
from rest_framework import status

CONTENT_TYPE = "application/vnd.api+json"
CRITICAL = {"op": "count_gte", "filter": {"severity": ["critical"]}, "value": 1}


def _rule_payload(**attributes):
    base = {
        "name": "Critical findings",
        "description": "Any critical finding",
        "trigger": "after_scan",
        "condition": CRITICAL,
        "schema_version": 1,
        "recipient_emails": ["Sec@Example.com"],
        "slack_channels": [],
    }
    return {"data": {"type": "alert-rules", "attributes": {**base, **attributes}}}


def _create_rule(client, **attributes):
    return client.post(
        reverse("alert-rule-list"),
        data=_rule_payload(**attributes),
        content_type=CONTENT_TYPE,
    )


def _make_rule(tenant, emails=("sec@example.com",), **fields):
    defaults = {
        "name": f"rule-{uuid4().hex[:8]}",
        "trigger": AlertRule.TriggerChoices.AFTER_SCAN,
        "condition": CRITICAL,
    }
    rule = AlertRule.objects.create(tenant_id=tenant.id, **{**defaults, **fields})
    services.set_rule_recipients(rule, list(emails))
    return rule


@pytest.mark.django_db
class TestAlertRuleViewSet:
    def test_list_is_empty_without_rules(self, authenticated_client):
        response = authenticated_client.get(reverse("alert-rule-list"))

        assert response.status_code == status.HTTP_200_OK
        assert response.json()["data"] == []

    def test_create_stores_rule_and_confirmed_recipient(self, authenticated_client):
        response = _create_rule(authenticated_client)

        assert response.status_code == status.HTTP_201_CREATED, response.json()
        data = response.json()["data"]
        assert data["type"] == "alert-rules"
        attributes = data["attributes"]
        assert attributes["name"] == "Critical findings"
        assert attributes["enabled"] is True
        assert attributes["condition"] == CRITICAL
        # Emails are normalized and, self-hosted, trusted without a double opt-in.
        assert attributes["recipient_emails"] == ["sec@example.com"]
        recipient = AlertRecipient.objects.get(email="sec@example.com")
        assert recipient.status == AlertRecipient.StatusChoices.CONFIRMED
        assert "token" not in attributes

    def test_create_rejects_invalid_condition(self, authenticated_client):
        response = _create_rule(
            authenticated_client,
            condition={"op": "any", "filter": {"severity": ["catastrophic"]}},
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.json()["errors"][0]["source"]["pointer"] == (
            "/data/attributes/condition"
        )
        assert not AlertRule.objects.exists()

    def test_create_rejects_duplicate_name(self, authenticated_client):
        _create_rule(authenticated_client)

        response = _create_rule(authenticated_client)

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert AlertRule.objects.count() == 1

    def test_create_rejects_slack_channels(self, authenticated_client):
        response = _create_rule(authenticated_client, slack_channels=[{"id": "C1"}])

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_patch_enabled_keeps_recipients(self, authenticated_client):
        rule_id = _create_rule(authenticated_client).json()["data"]["id"]

        response = authenticated_client.patch(
            reverse("alert-rule-detail", kwargs={"pk": rule_id}),
            data={
                "data": {
                    "type": "alert-rules",
                    "id": rule_id,
                    "attributes": {"enabled": False},
                }
            },
            content_type=CONTENT_TYPE,
        )

        assert response.status_code == status.HTTP_200_OK, response.json()
        attributes = response.json()["data"]["attributes"]
        assert attributes["enabled"] is False
        assert attributes["recipient_emails"] == ["sec@example.com"]

    def test_patch_replaces_recipients(self, authenticated_client):
        rule_id = _create_rule(authenticated_client).json()["data"]["id"]
        payload = _rule_payload(recipient_emails=["new@example.com"])
        payload["data"]["id"] = rule_id

        response = authenticated_client.patch(
            reverse("alert-rule-detail", kwargs={"pk": rule_id}),
            data=payload,
            content_type=CONTENT_TYPE,
        )

        assert response.status_code == status.HTTP_200_OK, response.json()
        assert response.json()["data"]["attributes"]["recipient_emails"] == [
            "new@example.com"
        ]

    def test_delete_removes_rule(self, authenticated_client):
        rule_id = _create_rule(authenticated_client).json()["data"]["id"]

        response = authenticated_client.delete(
            reverse("alert-rule-detail", kwargs={"pk": rule_id})
        )

        assert response.status_code == status.HTTP_204_NO_CONTENT
        assert not AlertRule.objects.exists()

    def test_filters_and_search(self, authenticated_client):
        _create_rule(authenticated_client, name="Alpha", trigger="daily")
        _create_rule(authenticated_client, name="Beta", enabled=False)

        by_trigger = authenticated_client.get(
            reverse("alert-rule-list"), {"filter[trigger]": "daily"}
        )
        by_enabled = authenticated_client.get(
            reverse("alert-rule-list"), {"filter[enabled]": "false"}
        )
        by_search = authenticated_client.get(
            reverse("alert-rule-list"), {"filter[search]": "alph"}
        )

        assert [r["attributes"]["name"] for r in by_trigger.json()["data"]] == ["Alpha"]
        assert [r["attributes"]["name"] for r in by_enabled.json()["data"]] == ["Beta"]
        assert [r["attributes"]["name"] for r in by_search.json()["data"]] == ["Alpha"]

    def test_requires_manage_integrations(
        self, authenticated_client_no_permissions_rbac
    ):
        response = authenticated_client_no_permissions_rbac.get(
            reverse("alert-rule-list")
        )

        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_seed_builds_condition_from_findings_filters(self, authenticated_client):
        response = authenticated_client.post(
            reverse("alert-rule-seed"),
            data={
                "data": {
                    "type": "alert-rule-seedings",
                    "attributes": {
                        "filter_bag": {
                            "filter[severity__in]": ["critical", "high"],
                            "filter[status__in]": "FAIL",
                        }
                    },
                }
            },
            content_type=CONTENT_TYPE,
        )

        assert response.status_code == status.HTTP_200_OK, response.json()
        assert response.json()["data"]["attributes"]["condition"] == {
            "op": "count_gte",
            "filter": {"severity": ["critical", "high"]},
            "value": 1,
        }
        assert not AlertRule.objects.exists()

    def test_seed_rejects_bag_without_usable_filters(self, authenticated_client):
        response = authenticated_client.post(
            reverse("alert-rule-seed"),
            data={
                "data": {
                    "type": "alert-rule-seedings",
                    "attributes": {"filter_bag": {"filter[status__in]": "FAIL"}},
                }
            },
            content_type=CONTENT_TYPE,
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_preview_counts_failing_findings_of_latest_scans(
        self, authenticated_client, findings_fixture
    ):
        scan = findings_fixture[0].scan
        scan.state = StateChoices.COMPLETED
        scan.save()
        expected = Finding.all_objects.filter(
            scan=scan, status="FAIL", muted=False, severity="critical"
        ).count()
        assert expected > 0

        response = authenticated_client.post(
            reverse("alert-rule-preview"),
            data={
                "data": {
                    "type": "alert-rule-previews",
                    "attributes": {"condition": CRITICAL},
                }
            },
            content_type=CONTENT_TYPE,
        )

        assert response.status_code == status.HTTP_200_OK, response.json()
        attributes = response.json()["data"]["attributes"]
        assert attributes["evaluation_failed"] is False
        assert attributes["summary"]["finding_count_total"] == expected
        assert attributes["summary"]["counts_by_severity"] == {"critical": expected}
        assert attributes["summary"]["top_severity"] == "critical"
        assert len(attributes["sample_finding_ids"]) == expected


@pytest.mark.django_db
class TestAlertRecipients:
    def test_list_returns_recipients_sorted_by_email(
        self, authenticated_client, tenants_fixture
    ):
        _make_rule(tenants_fixture[0], emails=("zed@example.com", "amy@example.com"))

        response = authenticated_client.get(
            reverse("alert-recipient-list"), {"page[size]": "100", "sort": "email"}
        )

        assert response.status_code == status.HTTP_200_OK
        assert [r["attributes"]["email"] for r in response.json()["data"]] == [
            "amy@example.com",
            "zed@example.com",
        ]

    def test_slack_channels_is_empty(self, authenticated_client):
        response = authenticated_client.get(reverse("alert-slack-channel-list"))

        assert response.status_code == status.HTTP_200_OK
        assert response.json()["data"] == []

    def test_unsubscribe_link_needs_no_auth_and_stops_delivery(
        self, client, tenants_fixture
    ):
        rule = _make_rule(tenants_fixture[0])
        recipient = rule.recipients.get()

        response = client.get(
            reverse("alert-recipient-unsubscribe"), {"token": recipient.token}
        )

        assert response.status_code == status.HTTP_200_OK
        assert response.json()["state"] == "unsubscribed"
        recipient.refresh_from_db()
        assert recipient.status == AlertRecipient.StatusChoices.UNSUBSCRIBED

    def test_unknown_token_is_rejected(self, client, tenants_fixture):
        response = client.get(reverse("alert-recipient-confirm"), {"token": "nope"})

        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert response.json()["state"] == "invalid"

    def test_confirmation_required_keeps_recipient_pending_until_confirmed(
        self, client, tenants_fixture, settings
    ):
        settings.ALERTS_RECIPIENT_CONFIRMATION_REQUIRED = True
        rule = _make_rule(tenants_fixture[0])
        recipient = rule.recipients.get()
        assert recipient.status == AlertRecipient.StatusChoices.PENDING
        assert recipient.token in mail.outbox[0].body

        response = client.get(
            reverse("alert-recipient-confirm"), {"token": recipient.token}
        )

        assert response.json()["state"] == "confirmed"
        recipient.refresh_from_db()
        assert recipient.status == AlertRecipient.StatusChoices.CONFIRMED


@pytest.mark.django_db
class TestEvaluateRules:
    def test_matching_rule_sends_email_and_records_event(
        self, tenants_fixture, findings_fixture
    ):
        tenant = tenants_fixture[0]
        scan = findings_fixture[0].scan
        rule = _make_rule(tenant)

        result = services.evaluate_rules(
            str(tenant.id), "after_scan", scan_ids=[scan.id], scan_id=scan.id
        )

        assert result == {"evaluated": 1, "fired": 1, "failed": 0}
        assert len(mail.outbox) == 1
        message = mail.outbox[0]
        assert message.to == ["sec@example.com"]
        assert rule.name in message.subject
        assert "/alerts/unsubscribe?token=" in message.body
        event = AlertEvent.objects.get(rule=rule)
        assert event.status == AlertEvent.StatusChoices.SENT
        assert event.scan_id == scan.id
        assert event.summary["finding_count_total"] >= 1

    def test_rule_that_does_not_hold_is_silent(self, tenants_fixture, findings_fixture):
        tenant = tenants_fixture[0]
        scan = findings_fixture[0].scan
        _make_rule(
            tenant,
            condition={"op": "none", "filter": {"severity": ["critical"]}},
        )

        result = services.evaluate_rules(
            str(tenant.id), "after_scan", scan_ids=[scan.id], scan_id=scan.id
        )

        assert result == {"evaluated": 1, "fired": 0, "failed": 0}
        assert mail.outbox == []
        assert not AlertEvent.objects.exists()

    def test_disabled_daily_and_unsubscribed_are_skipped(
        self, tenants_fixture, findings_fixture
    ):
        tenant = tenants_fixture[0]
        scan = findings_fixture[0].scan
        _make_rule(tenant, enabled=False)
        _make_rule(tenant, trigger=AlertRule.TriggerChoices.DAILY)
        unsubscribed = _make_rule(tenant, emails=("gone@example.com",))
        services.unsubscribe_recipient(unsubscribed.recipients.get())

        result = services.evaluate_rules(
            str(tenant.id), "after_scan", scan_ids=[scan.id], scan_id=scan.id
        )

        # Only the unsubscribed rule is evaluated; it fires but has nobody to mail.
        assert result == {"evaluated": 1, "fired": 1, "failed": 0}
        assert mail.outbox == []
        event = AlertEvent.objects.get()
        assert event.status == AlertEvent.StatusChoices.NO_RECIPIENTS

    def test_muted_findings_do_not_trigger(self, tenants_fixture, findings_fixture):
        tenant = tenants_fixture[0]
        scan = findings_fixture[0].scan
        Finding.all_objects.filter(scan=scan).update(muted=True)
        _make_rule(tenant)

        result = services.evaluate_rules(
            str(tenant.id), "after_scan", scan_ids=[scan.id], scan_id=scan.id
        )

        assert result["fired"] == 0
