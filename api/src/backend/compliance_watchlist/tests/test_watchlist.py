import pytest
from api.models import ComplianceWatchlistEntry, TenantComplianceSummary
from compliance_watchlist import services

CONTENT_TYPE = "application/vnd.api+json"


def _body(type_, attributes):
    return {"data": {"type": type_, "attributes": attributes}}


@pytest.fixture
def aws_framework():
    framework_id = next(
        cid
        for cid, f in services._frameworks("aws").items()
        if f["provider_type"] == "aws"
    )
    return framework_id


@pytest.mark.django_db
class TestComplianceWatchlist:
    def test_catalog_lists_frameworks_for_the_tenants_provider_types(
        self, authenticated_client, aws_provider, tenants_fixture, aws_framework
    ):
        TenantComplianceSummary.objects.create(
            tenant_id=tenants_fixture[0].id,
            compliance_id=aws_framework,
            requirements_passed=3,
            requirements_failed=1,
            requirements_manual=0,
            total_requirements=4,
        )

        response = authenticated_client.get(
            "/api/v1/compliance-catalog", {"page[size]": "500"}
        )

        assert response.status_code == 200, response.json()
        meta = response.json()["meta"]
        assert "aws" in meta["eligible_provider_types"]
        rows = {
            r["attributes"]["compliance_id"]: r["attributes"]
            for r in response.json()["data"]
        }
        assert rows[aws_framework]["score"] == 75.0
        assert rows[aws_framework]["has_data"] is True
        assert rows[aws_framework]["in_watchlist"] is False
        assert any(r["provider_type"] == "*" for r in rows.values()), (
            "universal frameworks once"
        )

    def test_add_remove_and_bulk(
        self, authenticated_client, aws_provider, aws_framework
    ):
        added = authenticated_client.post(
            "/api/v1/compliance-watchlist-entries",
            data=_body(
                "compliance-watchlist-entries",
                {"compliance_id": aws_framework, "provider_type": "aws"},
            ),
            content_type=CONTENT_TYPE,
        )
        again = authenticated_client.post(
            "/api/v1/compliance-watchlist-entries",
            data=_body(
                "compliance-watchlist-entries",
                {"compliance_id": aws_framework, "provider_type": "aws"},
            ),
            content_type=CONTENT_TYPE,
        )
        bulk = authenticated_client.post(
            "/api/v1/compliance-watchlist-entries/bulk",
            data=_body(
                "compliance-watchlist-bulk",
                {
                    "add": [{"compliance_id": aws_framework, "provider_type": "aws"}],
                    "remove": [
                        {"compliance_id": aws_framework, "provider_type": "aws"}
                    ],
                },
            ),
            content_type=CONTENT_TYPE,
        )
        unknown = authenticated_client.post(
            "/api/v1/compliance-watchlist-entries",
            data=_body(
                "compliance-watchlist-entries",
                {"compliance_id": "nope", "provider_type": "aws"},
            ),
            content_type=CONTENT_TYPE,
        )

        assert added.status_code == 201, added.json()
        assert again.status_code == 200
        assert bulk.json()["meta"] == {
            "added": 0,
            "already_present": 1,
            "removed": 1,
            "not_present": 0,
            "watchlist_count": 0,
        }
        assert unknown.status_code == 400
        assert not ComplianceWatchlistEntry.objects.exists()

    def test_overview_watchlist_filter(
        self, authenticated_client, tenants_fixture, aws_framework
    ):
        for cid in (aws_framework, "other_framework_aws"):
            TenantComplianceSummary.objects.create(
                tenant_id=tenants_fixture[0].id,
                compliance_id=cid,
                requirements_passed=1,
                requirements_failed=0,
                requirements_manual=0,
                total_requirements=1,
            )
        ComplianceWatchlistEntry.objects.create(
            tenant_id=tenants_fixture[0].id,
            compliance_id=aws_framework,
            provider_type="aws",
        )

        everything = authenticated_client.get("/api/v1/overviews/compliance-watchlist")
        watched = authenticated_client.get(
            "/api/v1/overviews/compliance-watchlist", {"filter[in_watchlist]": "true"}
        )

        assert everything.status_code == 200, everything.json()
        assert len(everything.json()["data"]) == 2
        assert watched.status_code == 200, watched.json()
        assert [r["attributes"]["compliance_id"] for r in watched.json()["data"]] == [
            aws_framework
        ]

    def test_finding_frameworks(
        self, authenticated_client, findings_fixture, tenants_fixture
    ):
        finding = findings_fixture[0]
        real_check = next(
            iter(
                next(f for f in services._frameworks("aws").values() if f["checks"])[
                    "checks"
                ]
            )
        )
        type(finding).all_objects.filter(id=finding.id).update(check_id=real_check)

        response = authenticated_client.get(
            f"/api/v1/findings/{finding.id}/compliance-frameworks"
        )
        watched = authenticated_client.get(
            f"/api/v1/findings/{finding.id}/compliance-frameworks",
            {"filter[in_watchlist]": "true"},
        )

        assert response.status_code == 200, response.json()
        assert response.json()["data"]
        assert all(
            r["attributes"]["in_watchlist"] is False for r in response.json()["data"]
        )
        assert watched.json()["data"] == []
