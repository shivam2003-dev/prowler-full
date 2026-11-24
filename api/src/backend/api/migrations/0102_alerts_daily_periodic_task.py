from django.db import migrations

TASK_NAME = "alerts-evaluate-daily"
# 08:00 UTC, once a day.
CRONTAB = {
    "minute": "0",
    "hour": "8",
    "day_of_week": "*",
    "day_of_month": "*",
    "month_of_year": "*",
}


def create_periodic_task(apps, schema_editor):
    CrontabSchedule = apps.get_model("django_celery_beat", "CrontabSchedule")
    PeriodicTask = apps.get_model("django_celery_beat", "PeriodicTask")

    schedule, _ = CrontabSchedule.objects.get_or_create(**CRONTAB)
    PeriodicTask.objects.update_or_create(
        name=TASK_NAME,
        defaults={"task": TASK_NAME, "crontab": schedule, "enabled": True},
    )


def delete_periodic_task(apps, schema_editor):
    CrontabSchedule = apps.get_model("django_celery_beat", "CrontabSchedule")
    PeriodicTask = apps.get_model("django_celery_beat", "PeriodicTask")

    PeriodicTask.objects.filter(name=TASK_NAME).delete()
    # Clean up the schedule if no other task references it
    CrontabSchedule.objects.filter(**CRONTAB, periodictask__isnull=True).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0101_alerts"),
        ("django_celery_beat", "0019_alter_periodictasks_options"),
    ]

    operations = [
        migrations.RunPython(create_periodic_task, delete_periodic_task),
    ]
