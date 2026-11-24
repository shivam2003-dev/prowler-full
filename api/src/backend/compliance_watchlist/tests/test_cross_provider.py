import pytest
from api.models import ComplianceRequirementOverview, Scan

FRAMEWORK = "dora_2022_2554"


def _row(scan, requirement_id, status, region="us-east-1"):
    return ComplianceRequirementOverview.objects.create(
        tenant_id=scan.tenant_id,
        scan=scan,
        compliance_id=FRAMEWORK,
        framework="DORA",
        version="2022/2554",
        region=region,
        requirement_id=requirement_id,
        requirement_status=status,
    )


@pytest.mark.django_db
class TestCrossProviderCompliance:
    def test_requirements_merge_fail_dominant_across_providers(
        self, authenticated_client, aws_provider, azure_provider
    ):
        aws_scan = Scan.objects.create(
            tenant_id=aws_provider.tenant_id,
            provider=aws_provider,
            trigger="manual",
            state="completed",
        )
        azure_scan = Scan.objects.create(
            tenant_id=azure_provider.tenant_id,
            provider=azure_provider,
            trigger="manual",
            state="completed",
        )
        _row(aws_scan, "DORA-Art5", "PASS")
        _row(aws_scan, "DORA-Art5", "FAIL", region="eu-west-1")
        _row(azure_scan, "DORA-Art5", "PASS")

        response = authenticated_client.get(
            "/api/v1/cross-provider-compliance-overviews",
            {"filter[compliance_id]": FRAMEWORK},
        )

        assert response.status_code == 200, response.json()
        attributes = response.json()["data"]["attributes"]
        assert set(attributes["providers"]) == {"aws", "azure"}
        art5 = next(r for r in attributes["requirements"] if r["id"] == "DORA-Art5")
        assert art5["providers"] == {"aws": "FAIL", "azure": "PASS"}
        assert art5["status"] == "FAIL"
        assert art5["check_ids_by_provider"]["aws"]
        assert attributes["total_requirements"] == len(attributes["requirements"])
        assert attributes["requirements_failed"] >= 1

        only_azure = authenticated_client.get(
            "/api/v1/cross-provider-compliance-overviews",
            {"filter[compliance_id]": FRAMEWORK, "filter[provider_type__in]": "azure"},
        ).json()["data"]["attributes"]
        assert only_azure["providers"] == ["azure"]

    def test_unknown_framework_and_missing_id(self, authenticated_client, aws_provider):
        unknown = authenticated_client.get(
            "/api/v1/cross-provider-compliance-overviews",
            {"filter[compliance_id]": "nope"},
        )
        missing = authenticated_client.get(
            "/api/v1/cross-provider-compliance-overviews"
        )

        assert unknown.status_code == 404
        assert missing.status_code == 400


@pytest.mark.django_db
def test_cross_account_merges_accounts_of_one_type(
    authenticated_client, aws_provider_pair
):
    first, second = aws_provider_pair
    framework = "cis_2.0_aws"
    for provider, status in ((first, "FAIL"), (second, "PASS")):
        scan = Scan.objects.create(
            tenant_id=provider.tenant_id,
            provider=provider,
            trigger="manual",
            state="completed",
        )
        ComplianceRequirementOverview.objects.create(
            tenant_id=scan.tenant_id,
            scan=scan,
            compliance_id=framework,
            framework="CIS",
            version="2.0",
            region="us-east-1",
            requirement_id="1.1",
            requirement_status=status,
        )

    response = authenticated_client.get(
        "/api/v1/cross-account-compliance-overviews",
        {"filter[compliance_id]": framework, "filter[provider_type]": "aws"},
    )

    assert response.status_code == 200, response.json()
    attributes = response.json()["data"]["attributes"]
    assert len(attributes["accounts"]) == 2
    requirement = next(r for r in attributes["requirements"] if r["id"] == "1.1")
    assert requirement["accounts"] == {str(first.id): "FAIL", str(second.id): "PASS"}
    assert requirement["status"] == "FAIL"
    assert isinstance(requirement["attributes"], list)
