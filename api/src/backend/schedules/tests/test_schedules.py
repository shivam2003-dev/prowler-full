import json

import pytest
from api.models import ProviderScanSchedule
from django_celery_beat.models import PeriodicTask
from schedules import services

CONTENT_TYPE = "application/vnd.api+json"


def _patch(client, provider_id, **attributes):
    return client.patch(
        f"/api/v1/schedules/{provider_id}",
        data={
            "data": {
                "type": "schedules",
                "id": str(provider_id),
                "attributes": attributes,
            }
        },
        content_type=CONTENT_TYPE,
    )


WEEKLY = {
    "scan_enabled": True,
    "scan_frequency": "WEEKLY",
    "scan_hour": 6,
    "scan_timezone": "Asia/Kolkata",
    "scan_interval_hours": None,
    "scan_day_of_week": 1,
    "scan_day_of_month": None,
}


@pytest.mark.django_db
class TestScheduleApi:
    def test_unconfigured_provider_reads_as_off(
        self, authenticated_client, aws_provider
    ):
        response = authenticated_client.get(
            f"/api/v1/schedules/{aws_provider.id}?include=provider"
        )

        assert response.status_code == 200, response.json()
        attributes = response.json()["data"]["attributes"]
        assert attributes["scan_enabled"] is False
        assert attributes["next_scan_at"] is None
        assert response.json()["included"][0]["id"] == str(aws_provider.id)

    def test_weekly_schedule_creates_a_timezone_aware_cron_task(
        self, authenticated_client, aws_provider
    ):
        response = _patch(authenticated_client, aws_provider.id, **WEEKLY)

        assert response.status_code == 200, response.json()
        attributes = response.json()["data"]["attributes"]
        assert attributes["scan_frequency"] == "WEEKLY"
        assert attributes["next_scan_at"]
        task = PeriodicTask.objects.get(
            name=f"scan-perform-scheduled-{aws_provider.id}"
        )
        assert task.task == "scan-perform-scheduled"
        assert json.loads(task.kwargs)["provider_id"] == str(aws_provider.id)
        assert (task.crontab.hour, task.crontab.day_of_week) == ("6", "1")
        assert str(task.crontab.timezone) == "Asia/Kolkata"

    def test_switching_to_interval_replaces_the_cron(
        self, authenticated_client, aws_provider
    ):
        _patch(authenticated_client, aws_provider.id, **WEEKLY)

        response = _patch(
            authenticated_client,
            aws_provider.id,
            **{
                **WEEKLY,
                "scan_frequency": "INTERVAL",
                "scan_interval_hours": 6,
                "scan_hour": None,
            },
        )

        assert response.status_code == 200, response.json()
        task = PeriodicTask.objects.get(
            name=f"scan-perform-scheduled-{aws_provider.id}"
        )
        assert task.crontab is None
        assert (task.interval.every, task.interval.period) == (6, "hours")

    @pytest.mark.parametrize(
        "change, message",
        [
            ({"scan_frequency": "YEARLY"}, "Use one of"),
            ({"scan_timezone": "Mars/Base"}, "Unknown time zone"),
            ({"scan_hour": 24}, "from 0 to 23"),
            ({"scan_day_of_week": None}, "required"),
            (
                {"scan_frequency": "MONTHLY", "scan_day_of_month": 31},
                "from 1 to 28",
            ),
            (
                {"scan_frequency": "INTERVAL", "scan_interval_hours": 5},
                "Use one of (1, 2",
            ),
        ],
    )
    def test_invalid_schedules_are_rejected(
        self, authenticated_client, aws_provider, change, message
    ):
        response = _patch(authenticated_client, aws_provider.id, **{**WEEKLY, **change})

        assert response.status_code == 400
        assert message in response.json()["errors"][0]["detail"]
        assert not ProviderScanSchedule.objects.exists()

    def test_pause_keeps_the_schedule_and_disables_the_task(
        self, authenticated_client, aws_provider
    ):
        _patch(authenticated_client, aws_provider.id, **WEEKLY)

        _patch(
            authenticated_client, aws_provider.id, **{**WEEKLY, "scan_enabled": False}
        )

        task = PeriodicTask.objects.get(
            name=f"scan-perform-scheduled-{aws_provider.id}"
        )
        assert task.enabled is False
        assert services.describe(aws_provider)["next_scan_at"] is None

    def test_delete_removes_schedule_and_task(self, authenticated_client, aws_provider):
        _patch(authenticated_client, aws_provider.id, **WEEKLY)

        response = authenticated_client.delete(f"/api/v1/schedules/{aws_provider.id}")

        assert response.status_code == 204
        assert not PeriodicTask.objects.filter(
            name__endswith=str(aws_provider.id)
        ).exists()

    def test_list_filters_configured_and_paginates(
        self, authenticated_client, aws_provider, gcp_provider
    ):
        _patch(authenticated_client, aws_provider.id, **WEEKLY)

        configured = authenticated_client.get(
            "/api/v1/schedules", {"filter[configured]": "true", "include": "provider"}
        )
        everything = authenticated_client.get("/api/v1/schedules", {"page[size]": "1"})

        assert [row["id"] for row in configured.json()["data"]] == [
            str(aws_provider.id)
        ]
        assert configured.json()["included"][0]["type"] == "providers"
        assert everything.json()["meta"]["pagination"]["pages"] >= 2

    def test_bulk_reports_updated_and_failed(self, authenticated_client, aws_provider):
        missing = "00000000-0000-4000-8000-000000000000"

        response = authenticated_client.post(
            "/api/v1/schedules/bulk",
            data={
                "data": {
                    "type": "schedules-bulk",
                    "attributes": {
                        "schedule": WEEKLY,
                        "provider_ids": [str(aws_provider.id), missing],
                    },
                }
            },
            content_type=CONTENT_TYPE,
        )

        assert response.status_code == 200, response.json()
        assert response.json()["data"] == {
            "updated": [str(aws_provider.id)],
            "failed": [{"id": missing, "error": "Provider not found."}],
        }

    def test_legacy_daily_schedule_is_reported(self, aws_provider, tenants_fixture):
        from django_celery_beat.models import IntervalSchedule

        PeriodicTask.objects.create(
            name=f"scan-perform-scheduled-{aws_provider.id}",
            task="scan-perform-scheduled",
            interval=IntervalSchedule.objects.get_or_create(every=24, period="hours")[
                0
            ],
            kwargs="{}",
        )

        described = services.describe(aws_provider)

        assert described["_configured"] is True
        assert described["scan_frequency"] == "DAILY"
        assert described["next_scan_at"] is not None

    def test_writes_need_manage_scans(
        self, authenticated_client_no_permissions_rbac, aws_provider
    ):
        response = _patch(
            authenticated_client_no_permissions_rbac, aws_provider.id, **WEEKLY
        )

        assert response.status_code == 403
