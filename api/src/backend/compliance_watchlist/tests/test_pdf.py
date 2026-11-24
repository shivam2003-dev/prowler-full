import json
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

import pytest
from api.models import ComplianceRequirementOverview, Scan, Task
from compliance_watchlist import pdf as compliance_pdf
from django_celery_results.models import TaskResult
from tasks.tasks import generate_aggregated_compliance_pdf_task

FRAMEWORK = "dora_2022_2554"
BASE = "/api/v1/cross-provider-compliance-overviews"


@pytest.fixture
def scanned(aws_provider, settings, tmp_path):
    scan = Scan.objects.create(
        tenant_id=aws_provider.tenant_id,
        provider=aws_provider,
        trigger="manual",
        state="completed",
    )
    ComplianceRequirementOverview.objects.create(
        tenant_id=scan.tenant_id,
        scan=scan,
        compliance_id=FRAMEWORK,
        framework="DORA",
        version="2022/2554",
        region="us-east-1",
        requirement_id="DORA-Art5",
        requirement_status="FAIL",
    )
    with patch.object(compliance_pdf, "DJANGO_TMP_OUTPUT_DIRECTORY", str(tmp_path)):
        yield aws_provider


def _run_task(
    tenant_id, provider, kind=compliance_pdf.CROSS_PROVIDER, provider_type=None
):
    params = {
        "compliance_id": FRAMEWORK
        if kind == compliance_pdf.CROSS_PROVIDER
        else "cis_2.0_aws",
        "provider_type": provider_type,
        "provider_ids": [str(provider.id)],
        "scan_ids": [],
    }
    task_id = str(uuid4())
    result = generate_aggregated_compliance_pdf_task.apply(
        kwargs={
            "tenant_id": tenant_id,
            "kind": kind,
            "report_name": "",
            "key": compliance_pdf.request_key(kind, params),
            **params,
        },
        task_id=task_id,
    ).get()
    runner = TaskResult.objects.create(
        task_id=task_id,
        task_name=compliance_pdf.TASK_NAME,
        status="SUCCESS",
        result=json.dumps(result),
    )
    Task.objects.create(id=task_id, task_runner_task=runner, tenant_id=tenant_id)
    return task_id, result


@pytest.mark.django_db
class TestCompliancePdf:
    def test_task_renders_a_pdf(self, tenants_fixture, scanned):
        tenant_id = str(tenants_fixture[0].id)

        task_id, result = _run_task(tenant_id, scanned)

        path = compliance_pdf.output_path(tenant_id, task_id)
        assert path.read_bytes().startswith(b"%PDF")
        assert result["kind"] == "cross_provider"
        assert result["filename"].endswith(".pdf")

    def test_download_and_latest(self, authenticated_client, tenants_fixture, scanned):
        tenant_id = str(tenants_fixture[0].id)
        task_id, result = _run_task(tenant_id, scanned)

        download = authenticated_client.get(f"{BASE}/pdf/{task_id}")
        latest = authenticated_client.get(
            f"{BASE}/pdf/latest", {"filter[compliance_id]": FRAMEWORK}
        )
        other = authenticated_client.get(
            f"{BASE}/pdf/latest", {"filter[compliance_id]": "cis_controls_8.1"}
        )
        wrong_kind = authenticated_client.get(
            f"/api/v1/cross-account-compliance-overviews/pdf/{task_id}"
        )

        assert download.status_code == 200
        assert download["Content-Type"] == "application/pdf"
        assert result["filename"] in download["Content-Disposition"]
        assert b"".join(download.streaming_content).startswith(b"%PDF")
        assert latest.status_code == 200, latest.json()
        assert latest.json()["data"]["id"] == task_id
        assert (
            latest.json()["data"]["attributes"]["result"]["filename"]
            == result["filename"]
        )
        assert other.status_code == 404
        assert wrong_kind.status_code == 404

    def test_pending_task_answers_202(
        self, authenticated_client, tenants_fixture, scanned
    ):
        runner = TaskResult.objects.create(
            task_id=str(uuid4()), task_name=compliance_pdf.TASK_NAME, status="STARTED"
        )
        Task.objects.create(
            id=runner.task_id, task_runner_task=runner, tenant_id=tenants_fixture[0].id
        )

        response = authenticated_client.get(f"{BASE}/pdf/{runner.task_id}")

        assert response.status_code == 202
        assert response.json()["data"]["id"] == runner.task_id

    def test_generate_queues_a_task(self, authenticated_client, tasks_fixture, scanned):
        with patch(
            "tasks.tasks.generate_aggregated_compliance_pdf_task.delay",
            return_value=SimpleNamespace(id=tasks_fixture[0].id),
        ) as delay:
            response = authenticated_client.post(
                f"{BASE}/pdf?filter%5Bcompliance_id%5D={FRAMEWORK}&report_name=Board+report"
            )

        assert response.status_code == 202, response.json()
        assert response.json()["data"]["id"] == str(tasks_fixture[0].id)
        kwargs = delay.call_args.kwargs
        assert kwargs["kind"] == "cross_provider"
        assert kwargs["report_name"] == "Board report"
        assert kwargs["provider_ids"] == [str(scanned.id)]

    def test_cross_account_pdf(self, tenants_fixture, scanned):
        tenant_id = str(tenants_fixture[0].id)

        task_id, result = _run_task(
            tenant_id, scanned, kind=compliance_pdf.CROSS_ACCOUNT, provider_type="aws"
        )

        assert (
            compliance_pdf.output_path(tenant_id, task_id)
            .read_bytes()
            .startswith(b"%PDF")
        )
        assert result["kind"] == "cross_account"
