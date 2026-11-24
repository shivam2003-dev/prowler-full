import pytest
from api.models import Finding, Issue, IssueTriage, IssueTriageNote, Resource, Scan
from issues import engine

CONTENT_TYPE = "application/vnd.api+json"


def _finding(scan, check_id, status="FAIL", severity="high", resource=None, uid=None):
    finding = Finding.objects.create(
        tenant_id=scan.tenant_id,
        uid=uid or f"{check_id}-{status}-{resource.uid if resource else 'none'}",
        scan=scan,
        status=status,
        severity=severity,
        impact=severity,
        check_id=check_id,
        check_metadata={"checkid": check_id},
    )
    if resource:
        finding.add_resources([resource])
    return finding


@pytest.fixture
def scan_with_paths(tenants_fixture, aws_provider):
    tenant = tenants_fixture[0]
    scan = Scan.objects.create(
        tenant_id=tenant.id, provider=aws_provider, trigger="manual", state="completed"
    )
    bucket = Resource.objects.create(
        tenant_id=tenant.id,
        provider=aws_provider,
        uid="arn:aws:s3:::open-bucket",
        name="open-bucket",
        region="us-east-1",
        service="s3",
        type="AwsS3Bucket",
    )
    _finding(scan, "s3_bucket_public_access", severity="critical", resource=bucket)
    _finding(scan, "s3_bucket_policy_public_write_access", resource=bucket)
    _finding(scan, "rds_instance_no_public_access", status="PASS", uid="rds-pass")
    _finding(scan, "rds_snapshots_public_access", status="PASS", uid="snap-pass")
    _finding(scan, "cloudtrail_multi_region_enabled", severity="medium", uid="trail")
    _finding(scan, "some_unmodelled_check", severity="low", uid="other")
    _finding(
        scan, "s3_bucket_public_access", severity="critical", uid="muted-one"
    ).__class__.objects.filter(uid="muted-one").update(muted=True)
    return scan


@pytest.mark.django_db
class TestIssueEngine:
    def test_findings_fold_into_patterns_with_verdicts(
        self, tenants_fixture, scan_with_paths
    ):
        issues = {
            i.pattern: i
            for i in engine.rebuild(str(tenants_fixture[0].id), scan_with_paths)
        }

        assert set(issues) == {
            "public_storage_data_exposure",
            "detection_gaps",
            "unmodelled",
        }
        storage = issues["public_storage_data_exposure"]
        assert storage.verdict == "exploitable"
        assert storage.severity == "critical"
        assert storage.legs["reachability"]["state"] == "yes"
        assert "arn:aws:s3:::open-bucket" in storage.legs["reachability"]["evidence"]
        assert storage.findings_count == 2, "muted findings are left out"
        assert storage.resource_uids == ["arn:aws:s3:::open-bucket"]
        assert issues["detection_gaps"].verdict == "unknown"
        assert issues["unmodelled"].finding_uids == ["other"]

    def test_ids_are_stable_and_closed_paths_disappear(
        self, tenants_fixture, scan_with_paths, aws_provider
    ):
        tenant_id = str(tenants_fixture[0].id)
        first = {i.pattern: i.id for i in engine.rebuild(tenant_id, scan_with_paths)}
        clean_scan = Scan.objects.create(
            tenant_id=tenant_id,
            provider=aws_provider,
            trigger="manual",
            state="completed",
        )
        _finding(
            clean_scan,
            "cloudtrail_multi_region_enabled",
            severity="medium",
            uid="trail",
        )

        second = {i.pattern: i.id for i in engine.rebuild(tenant_id, clean_scan)}

        assert second == {"detection_gaps": first["detection_gaps"]}
        assert Issue.objects.count() == 1

    def test_reachable_but_passing_access_is_not_exploitable(
        self, tenants_fixture, aws_provider
    ):
        scan = Scan.objects.create(
            tenant_id=tenants_fixture[0].id,
            provider=aws_provider,
            trigger="manual",
            state="completed",
        )
        _finding(scan, "rds_snapshots_public_access", status="PASS", uid="s")
        _finding(scan, "rds_instance_no_public_access", status="PASS", uid="r")
        _finding(scan, "rds_instance_storage_encrypted", uid="e")

        [issue] = engine.rebuild(str(tenants_fixture[0].id), scan)

        assert issue.pattern == "public_database"
        assert issue.verdict == "not_exploitable"


@pytest.mark.django_db
class TestIssuesApi:
    def test_list_overview_and_detail(
        self, authenticated_client, tenants_fixture, scan_with_paths
    ):
        engine.rebuild(str(tenants_fixture[0].id), scan_with_paths)

        listed = authenticated_client.get("/api/v1/issues", {"page[size]": "10"})
        overview = authenticated_client.get("/api/v1/issues/overview")
        filtered = authenticated_client.get(
            "/api/v1/issues", {"filter[verdict__in]": "exploitable"}
        )

        rows = listed.json()["data"]
        assert listed.status_code == 200, listed.json()
        assert rows[0]["attributes"]["verdict"] == "exploitable", "worst verdict first"
        assert rows[0]["attributes"]["triage_status"] == "open"
        assert "finding_uids" not in rows[0]["attributes"]
        assert overview.json()["data"]["attributes"]["issues"] == 3
        assert overview.json()["data"]["attributes"]["actionable"] == 1
        assert len(filtered.json()["data"]) == 1
        detail = authenticated_client.get(f"/api/v1/issues/{rows[0]['id']}")
        assert detail.json()["data"]["attributes"]["finding_uids"]
        assert detail.json()["data"]["relationships"]["scan"]["data"]["id"] == str(
            scan_with_paths.id
        )

    def test_triage_and_notes(
        self, authenticated_client, tenants_fixture, scan_with_paths
    ):
        issue = engine.rebuild(str(tenants_fixture[0].id), scan_with_paths)[0]
        url = f"/api/v1/issues/{issue.id}/triage"

        updated = authenticated_client.patch(
            url,
            data={
                "data": {
                    "type": "issue-triages",
                    "attributes": {
                        "status": "remediating",
                        "note": "Owner: platform team",
                    },
                }
            },
            content_type=CONTENT_TYPE,
        )
        added = authenticated_client.post(
            f"{url}/notes",
            data={
                "data": {
                    "type": "issue-triage-notes",
                    "attributes": {"body": "Fix scheduled"},
                }
            },
            content_type=CONTENT_TYPE,
        )
        notes = authenticated_client.get(f"{url}/notes", {"include": "created_by"})
        bad = authenticated_client.patch(
            url,
            data={
                "data": {"type": "issue-triages", "attributes": {"status": "resolved"}}
            },
            content_type=CONTENT_TYPE,
        )

        assert updated.status_code == 200, updated.json()
        assert updated.json()["data"]["attributes"]["triage_status"] == "remediating"
        assert added.status_code == 201
        assert [n["attributes"]["body"] for n in notes.json()["data"]] == [
            "Fix scheduled",
            "Owner: platform team",
        ]
        assert notes.json()["included"][0]["type"] == "users"
        assert bad.status_code == 400
        assert IssueTriage.objects.get().status == "remediating"
        assert IssueTriageNote.objects.count() == 2
        filtered = authenticated_client.get(
            "/api/v1/issues", {"filter[triage_status__in]": "remediating"}
        )
        assert [r["id"] for r in filtered.json()["data"]] == [str(issue.id)]

    def test_writes_need_manage_scans(
        self, authenticated_client_no_permissions_rbac, tenants_fixture, scan_with_paths
    ):
        issue = engine.rebuild(str(tenants_fixture[0].id), scan_with_paths)[0]

        response = authenticated_client_no_permissions_rbac.patch(
            f"/api/v1/issues/{issue.id}/triage",
            data={
                "data": {
                    "type": "issue-triages",
                    "attributes": {"status": "remediating"},
                }
            },
            content_type=CONTENT_TYPE,
        )

        assert response.status_code == 403
