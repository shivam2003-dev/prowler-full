"""Scan schedules: validate, store, and mirror into Celery beat."""

import json
from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from api.models import Provider, ProviderScanSchedule, Scan, StateChoices
from celery.schedules import crontab
from django_celery_beat.models import CrontabSchedule, IntervalSchedule, PeriodicTask

Frequency = ProviderScanSchedule.FrequencyChoices
TASK = "scan-perform-scheduled"
INTERVAL_CHOICES = (1, 2, 3, 4, 6, 8, 12)


class ScheduleError(ValueError):
    def __init__(self, field: str, detail: str):
        super().__init__(detail)
        self.field = field
        self.detail = detail


def task_name(provider_id) -> str:
    # The name the scheduled scan task looks itself up by.
    return f"{TASK}-{provider_id}"


def validate(attributes: dict) -> dict:
    frequency = attributes.get("scan_frequency")
    if frequency not in Frequency.values:
        raise ScheduleError("scan_frequency", f"Use one of {Frequency.values}.")
    tz = attributes.get("scan_timezone") or "UTC"
    try:
        ZoneInfo(tz)
    except (ZoneInfoNotFoundError, ValueError):
        raise ScheduleError("scan_timezone", f"Unknown time zone {tz!r}.") from None

    def number(field, low, high, required):
        value = attributes.get(field)
        if value is None:
            if required:
                raise ScheduleError(field, "This field is required.")
            return None
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not low <= value <= high
        ):
            raise ScheduleError(field, f"Must be a whole number from {low} to {high}.")
        return value

    cleaned = {
        "scan_enabled": bool(attributes.get("scan_enabled", True)),
        "scan_frequency": frequency,
        "scan_timezone": tz,
        "scan_hour": number("scan_hour", 0, 23, frequency != Frequency.INTERVAL),
        "scan_interval_hours": None,
        "scan_day_of_week": None,
        "scan_day_of_month": None,
    }
    if frequency == Frequency.INTERVAL:
        hours = number("scan_interval_hours", 1, 24, True)
        if hours not in INTERVAL_CHOICES:
            raise ScheduleError(
                "scan_interval_hours", f"Use one of {INTERVAL_CHOICES}."
            )
        cleaned["scan_interval_hours"] = hours
    elif frequency == Frequency.WEEKLY:
        cleaned["scan_day_of_week"] = number("scan_day_of_week", 0, 6, True)
    elif frequency == Frequency.MONTHLY:
        # 1-28 so every month has the day.
        cleaned["scan_day_of_month"] = number("scan_day_of_month", 1, 28, True)
    return cleaned


def _crontab(schedule: ProviderScanSchedule) -> CrontabSchedule:
    fields = {
        "minute": "0",
        "hour": str(schedule.scan_hour),
        "day_of_week": "*",
        "day_of_month": "*",
        "month_of_year": "*",
        "timezone": schedule.scan_timezone,
    }
    if schedule.scan_frequency == Frequency.WEEKLY:
        fields["day_of_week"] = str(schedule.scan_day_of_week)
    if schedule.scan_frequency == Frequency.MONTHLY:
        fields["day_of_month"] = str(schedule.scan_day_of_month)
    crontab_schedule, _ = CrontabSchedule.objects.get_or_create(**fields)
    return crontab_schedule


def sync_periodic_task(schedule: ProviderScanSchedule) -> PeriodicTask:
    """Create or update the beat task that runs the provider's scheduled scans."""
    defaults = {
        "task": TASK,
        "kwargs": json.dumps(
            {
                "tenant_id": str(schedule.tenant_id),
                "provider_id": str(schedule.provider_id),
            }
        ),
        "enabled": schedule.scan_enabled,
        "one_off": False,
    }
    if schedule.scan_frequency == Frequency.INTERVAL:
        interval, _ = IntervalSchedule.objects.get_or_create(
            every=schedule.scan_interval_hours, period=IntervalSchedule.HOURS
        )
        defaults.update(
            interval=interval,
            crontab=None,
            start_time=datetime.now(tz=UTC)
            + timedelta(hours=schedule.scan_interval_hours),
        )
    else:
        defaults.update(interval=None, crontab=_crontab(schedule), start_time=None)
    task, _ = PeriodicTask.objects.update_or_create(
        name=task_name(schedule.provider_id), defaults=defaults
    )
    return task


def save(tenant_id: str, provider: Provider, attributes: dict) -> ProviderScanSchedule:
    cleaned = validate(attributes)
    schedule, _ = ProviderScanSchedule.objects.update_or_create(
        tenant_id=tenant_id, provider=provider, defaults=cleaned
    )
    sync_periodic_task(schedule)
    return schedule


def remove(provider: Provider) -> None:
    ProviderScanSchedule.objects.filter(provider=provider).delete()
    PeriodicTask.objects.filter(name=task_name(provider.id)).delete()


def _legacy(provider: Provider) -> dict | None:
    """A daily schedule made by POST /schedules/daily, which has no stored row."""
    task = PeriodicTask.objects.filter(
        name=task_name(provider.id), interval__isnull=False
    ).first()
    if task is None:
        return None
    started = task.start_time or task.date_changed
    return {
        "scan_enabled": task.enabled,
        "scan_frequency": Frequency.DAILY,
        "scan_hour": started.astimezone(UTC).hour if started else 0,
        "scan_timezone": "UTC",
        "scan_interval_hours": None,
        "scan_day_of_week": None,
        "scan_day_of_month": None,
        "_task": task,
    }


def next_run(attributes: dict, task: PeriodicTask | None) -> datetime | None:
    if not attributes.get("scan_enabled") or task is None:
        return None
    now = datetime.now(tz=UTC)
    if task.interval_id:
        last = task.last_run_at or task.start_time or now
        step = timedelta(**{task.interval.period: task.interval.every})
        candidate = last + step
        while candidate < now:
            candidate += step
        return candidate
    if task.crontab_id:
        cron = task.crontab
        schedule = crontab(
            minute=cron.minute,
            hour=cron.hour,
            day_of_week=cron.day_of_week,
            day_of_month=cron.day_of_month,
            month_of_year=cron.month_of_year,
            nowfun=lambda: datetime.now(tz=ZoneInfo(str(cron.timezone))),
        )
        local_now = datetime.now(tz=ZoneInfo(str(cron.timezone)))
        return (local_now + schedule.remaining_estimate(local_now)).astimezone(UTC)
    return None


def describe(provider: Provider) -> dict:
    """Schedule attributes of a provider, configured or not."""
    stored = ProviderScanSchedule.objects.filter(provider=provider).first()
    if stored is not None:
        attributes = {
            field: getattr(stored, field)
            for field in (
                "scan_enabled",
                "scan_frequency",
                "scan_hour",
                "scan_timezone",
                "scan_interval_hours",
                "scan_day_of_week",
                "scan_day_of_month",
            )
        }
        task = PeriodicTask.objects.filter(name=task_name(provider.id)).first()
        configured = True
    elif (legacy := _legacy(provider)) is not None:
        task = legacy.pop("_task")
        attributes = legacy
        configured = True
    else:
        task = None
        configured = False
        attributes = {
            "scan_enabled": False,
            "scan_frequency": Frequency.DAILY,
            "scan_hour": None,
            "scan_timezone": "UTC",
            "scan_interval_hours": None,
            "scan_day_of_week": None,
            "scan_day_of_month": None,
        }
    last_scan = (
        Scan.objects.filter(provider=provider, state=StateChoices.COMPLETED)
        .order_by("-completed_at")
        .values_list("completed_at", flat=True)
        .first()
    )
    return {
        **attributes,
        "next_scan_at": next_run(attributes, task),
        "last_scan_at": last_scan,
        "_configured": configured,
    }
