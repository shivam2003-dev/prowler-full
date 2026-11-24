import json
from unittest.mock import patch

import pytest
from api.models import Finding, Ingestion, Provider, Resource, Scan, StateChoices
from django.core.files.uploadedfile import SimpleUploadedFile
from django.urls import reverse
from ingestions import services
from ingestions.ocsf import InvalidRecord, OcsfFinding, parse_records
from rest_framework import status

ACCOUNT = "123456789012"


def ocsf_record(**overrides):
    record = {
        "message": "IAM Access Analyzer is not enabled.",
        "metadata": {"event_code": "accessanalyzer_enabled"},
        "severity": "Low",
        "status": "New",
        "status_code": "FAIL",
        "status_detail": "IAM Access Analyzer in account is not enabled.",
        "status_id": 1,
        "risk_details": "Unused access is not detected.",
        "remediation": {"desc": "Enable it.", "references": ["https://example.com"]},
        "finding_info": {
            "uid": "prowler-aws-accessanalyzer_enabled-123456789012-eu-west-1-analyzer",
            "title": "Check if IAM Access Analyzer is enabled",
            "desc": "Check if IAM Access Analyzer is enabled",
            "types": ["Software and Configuration Checks"],
        },
        "resources": [
            {
                "uid": f"arn:aws:accessanalyzer:eu-west-1:{ACCOUNT}:analyzer/unknown",
                "name": "analyzer/unknown",
                "type": "Other",
                "region": "eu-west-1",
                "cloud_partition": "aws",
                "group": {"name": "accessanalyzer"},
                "labels": ["env:dev", "team:sec"],
                "data": {"details": "", "metadata": {"arn": "x"}},
            }
        ],
        "cloud": {
            "provider": "aws",
            "region": "eu-west-1",
            "account": {"uid": ACCOUNT, "name": "imported-account"},
        },
        "unmapped": {
            "provider": "aws",
            "provider_uid": ACCOUNT,
            "categories": ["identity-access"],
            "compliance": {"CIS-1.4": ["1.20"]},
        },
    }
    for key, value in overrides.items():
        record[key] = value
    return record


def second_record():
    record = ocsf_record(status_code="PASS", severity="High")
    record["finding_info"] = {**record["finding_info"], "uid": "finding-two"}
    record["metadata"] = {"event_code": "a_check_this_server_does_not_know"}
    record["resources"] = [
        {**record["resources"][0], "uid": "arn:aws:s3:::bucket", "name": "bucket"}
    ]
    return record


class TestOcsfFinding:
    def test_maps_the_fields_the_scan_job_reads(self):
        finding = OcsfFinding(ocsf_record())

        assert finding.provider == "aws"
        assert finding.account_uid == ACCOUNT
        assert finding.check_id == "accessanalyzer_enabled"
        assert finding.status == "FAIL"
        assert finding.severity == "low"
        assert finding.muted is False
        assert finding.region == "eu-west-1"
        assert finding.service_name == "accessanalyzer"
        assert finding.resource_tags == {"env": "dev", "team": "sec"}
        assert finding.resource_metadata == {"arn": "x"}
        assert finding.compliance == {"CIS-1.4": ["1.20"]}

    def test_metadata_comes_from_the_sdk_when_it_knows_the_check(self):
        metadata = OcsfFinding(ocsf_record()).get_metadata()

        assert metadata["checkid"] == "accessanalyzer_enabled"
        # Only the SDK copy has remediation code; the report does not carry it.
        assert "code" in metadata["remediation"]
        assert metadata["severity"] == "low"

    def test_metadata_falls_back_to_the_report_for_unknown_checks(self):
        metadata = OcsfFinding(second_record()).get_metadata()

        assert metadata["checkid"] == "a_check_this_server_does_not_know"
        assert metadata["categories"] == ["identity-access"]
        assert metadata["remediation"]["recommendation"]["url"] == "https://example.com"

    def test_suppressed_status_is_muted(self):
        assert OcsfFinding(ocsf_record(status_id=3, status="Suppressed")).muted is True

    @pytest.mark.parametrize(
        "overrides",
        [
            {"metadata": {}},
            {"finding_info": {}},
            {"resources": []},
            {"status_code": "UNKNOWN"},
            {"severity": "Fatal"},
            {"unmapped": {}, "cloud": {}},
        ],
    )
    def test_incomplete_record_is_invalid(self, overrides):
        with pytest.raises(InvalidRecord):
            OcsfFinding(ocsf_record(**overrides))

    def test_parse_records_groups_by_account_and_counts_invalid(self):
        groups, invalid = parse_records([ocsf_record(), second_record(), "junk", {}])

        assert invalid == 2
        assert [len(findings) for findings in groups.values()] == [2]
        assert list(groups) == [("aws", ACCOUNT)]


def _upload(client, content: bytes, name="report.ocsf.json"):
    return client.post(
        reverse("ingestion-list"),
        data={"file": SimpleUploadedFile(name, content, "application/json")},
        format="multipart",
    )


@pytest.mark.django_db
class TestIngestionViewSet:
    def test_upload_is_accepted_and_queued(
        self,
        authenticated_client,
        tenants_fixture,
        tmp_path,
        django_capture_on_commit_callbacks,
    ):
        with (
            patch("ingestions.views.process_ingestion_task.apply_async") as queued,
            patch("ingestions.services.DJANGO_TMP_OUTPUT_DIRECTORY", str(tmp_path)),
            django_capture_on_commit_callbacks(execute=True),
        ):
            response = _upload(
                authenticated_client, json.dumps([ocsf_record()]).encode()
            )

        assert response.status_code == status.HTTP_202_ACCEPTED, response.json()
        data = response.json()["data"]
        assert data["type"] == "ingestions"
        assert data["attributes"]["status"] == "pending"
        assert data["attributes"]["summary"] == {
            "total": 0,
            "processed": 0,
            "invalid": 0,
        }
        tenant_id = str(tenants_fixture[0].id)
        assert (
            tmp_path / tenant_id / "ingestions" / f"{data['id']}.ocsf.json"
        ).exists()
        queued.assert_called_once()

        detail = authenticated_client.get(
            reverse("ingestion-detail", kwargs={"pk": data["id"]})
        )
        assert detail.status_code == status.HTTP_200_OK

    def test_rejects_missing_non_report_and_oversized_files(
        self, authenticated_client, settings
    ):
        missing = authenticated_client.post(
            reverse("ingestion-list"), data={}, format="multipart"
        )
        not_a_report = _upload(authenticated_client, b'{"not": "an array"}')
        settings.INGESTION_MAX_UPLOAD_BYTES = 10
        too_large = _upload(authenticated_client, b"[" + b" " * 50 + b"]")

        assert missing.status_code == status.HTTP_400_BAD_REQUEST
        assert not_a_report.status_code == status.HTTP_400_BAD_REQUEST
        assert too_large.status_code == status.HTTP_413_REQUEST_ENTITY_TOO_LARGE
        assert not Ingestion.objects.exists()

    def test_requires_manage_scans(self, authenticated_client_no_permissions_rbac):
        response = authenticated_client_no_permissions_rbac.get(
            reverse("ingestion-list")
        )

        assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.django_db
class TestProcessIngestion:
    def _run(self, tenant, records, tmp_path):
        ingestion = Ingestion.objects.create(
            tenant_id=tenant.id, file_name="r.ocsf.json"
        )
        with patch("ingestions.services.DJANGO_TMP_OUTPUT_DIRECTORY", str(tmp_path)):
            path = services.report_path(str(tenant.id), str(ingestion.id))
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                records if isinstance(records, str) else json.dumps(records)
            )
            result = services.process_ingestion(str(tenant.id), str(ingestion.id))
            assert not path.exists()
        ingestion.refresh_from_db()
        return ingestion, result

    def test_report_becomes_provider_scan_resources_and_findings(
        self, tenants_fixture, tmp_path
    ):
        tenant = tenants_fixture[0]

        ingestion, result = self._run(
            tenant, [ocsf_record(), second_record(), {"junk": True}], tmp_path
        )

        assert ingestion.status == Ingestion.StatusChoices.COMPLETED, ingestion.error
        assert (
            ingestion.total_records,
            ingestion.processed_records,
            ingestion.invalid_records,
        ) == (3, 2, 1)
        provider = Provider.objects.get(tenant_id=tenant.id, uid=ACCOUNT)
        assert provider.provider == "aws"
        assert provider.alias == "imported-account"
        scan = Scan.objects.get(provider=provider)
        assert [str(scan.id)] == [item["scan_id"] for item in result["scans"]]
        assert scan.trigger == Scan.TriggerChoices.IMPORTED
        assert scan.state == StateChoices.COMPLETED
        assert scan.progress == 100
        assert scan.unique_resource_count == 2
        assert scan.is_full_scope() is False
        findings = Finding.all_objects.filter(scan=scan).order_by("check_id")
        assert [(f.check_id, f.status, f.severity) for f in findings] == [
            ("a_check_this_server_does_not_know", "PASS", "high"),
            ("accessanalyzer_enabled", "FAIL", "low"),
        ]
        assert Resource.objects.filter(provider=provider).count() == 2
        failing = Resource.objects.get(provider=provider, name="analyzer/unknown")
        assert failing.failed_findings_count == 1
        assert failing.region == "eu-west-1"

    def test_second_import_reuses_the_provider(self, tenants_fixture, tmp_path):
        tenant = tenants_fixture[0]

        self._run(tenant, [ocsf_record()], tmp_path)
        self._run(tenant, [ocsf_record()], tmp_path)

        assert Provider.objects.filter(tenant_id=tenant.id, uid=ACCOUNT).count() == 1
        assert Scan.objects.filter(provider__uid=ACCOUNT).count() == 2

    @pytest.mark.parametrize(
        "records", ["not json", {"an": "object"}, [], [{"junk": True}]]
    )
    def test_unusable_report_fails_without_creating_scans(
        self, tenants_fixture, tmp_path, records
    ):
        ingestion, result = self._run(tenants_fixture[0], records, tmp_path)

        assert ingestion.status == Ingestion.StatusChoices.FAILED
        assert ingestion.error
        assert result == {"scans": []}
        assert not Scan.objects.exists()

    def test_account_with_malformed_id_is_counted_invalid(
        self, tenants_fixture, tmp_path
    ):
        bad = ocsf_record()
        bad["unmapped"] = {**bad["unmapped"], "provider_uid": "not-an-aws-account"}

        ingestion, _ = self._run(tenants_fixture[0], [bad, ocsf_record()], tmp_path)

        assert ingestion.status == Ingestion.StatusChoices.COMPLETED
        assert (ingestion.processed_records, ingestion.invalid_records) == (1, 1)
        assert Provider.objects.filter(uid="not-an-aws-account").count() == 0
