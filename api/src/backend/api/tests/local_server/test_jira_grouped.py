from unittest.mock import MagicMock, patch

import pytest
from tasks.jobs.integrations import send_findings_to_jira


@pytest.mark.django_db
def test_grouped_dispatch_sends_one_issue_per_check(tenants_fixture, findings_fixture):
    tenant_id = str(tenants_fixture[0].id)
    first, second = findings_fixture[0], findings_fixture[1]
    type(second).all_objects.filter(id=second.id).update(check_id=first.check_id)
    jira = MagicMock()
    jira.send_finding.return_value = {"key": "SEC-1"}
    integration = MagicMock()

    with (
        patch(
            "tasks.jobs.integrations.Integration.objects.get", return_value=integration
        ),
        patch(
            "tasks.jobs.integrations.initialize_prowler_integration", return_value=jira
        ),
        patch("tasks.jobs.integrations.get_tenant_name", return_value="tenant"),
    ):
        result = send_findings_to_jira(
            tenant_id,
            "integration-1",
            "SEC",
            "Task",
            [str(first.id), str(second.id)],
            "grouped",
        )

    assert result == {"created_count": 1, "failed_count": 0}
    kwargs = jira.send_finding.call_args.kwargs
    assert len(kwargs["grouped_resources"]) == 2
    assert kwargs["affected_failing_resources"] == 2
    assert kwargs["check_id"] == first.check_id
