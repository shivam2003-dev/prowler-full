from datetime import UTC, datetime, timedelta
from urllib.parse import quote

import pytest
from api.models import Finding, FindingTriage, FindingTriageNote, Scan, StateChoices
from django.urls import reverse
from rest_framework import status
from triage import services

CONTENT_TYPE = "application/vnd.api+json"
ARN_UID = "prowler-aws-s3_check-123456789012-us-east-1-arn:aws:s3:::bucket/with/slash"


def _body(**attributes):
    # The UI sends no resource id: the triage may not exist yet.
    return {"data": {"type": "finding-triages", "attributes": attributes}}


def _by_uid_url(uid, suffix=""):
    return f"/api/v1/findings/{quote(uid, safe='')}/triage{suffix}"


@pytest.fixture
def failing_finding(findings_fixture):
    finding = findings_fixture[0]
    assert finding.status == "FAIL"
    return finding


@pytest.mark.django_db
class TestFindingTriageApi:
    def test_untriaged_finding_reads_open_without_creating_a_row(
        self, authenticated_client, failing_finding
    ):
        response = authenticated_client.get(_by_uid_url(failing_finding.uid))

        assert response.status_code == status.HTTP_200_OK, response.json()
        data = response.json()["data"]
        assert data["type"] == "finding-triages"
        assert data["id"] is None
        assert data["attributes"]["status"] == "open"
        assert data["attributes"]["finding_id"] == str(failing_finding.id)
        assert data["attributes"]["raw_finding_status"] == "FAIL"
        assert data["attributes"]["triage_notes_count"] == 0
        assert not FindingTriage.objects.exists()

    def test_set_status_with_first_note_then_edit_and_delete_the_note(
        self, authenticated_client, failing_finding
    ):
        created = authenticated_client.patch(
            _by_uid_url(failing_finding.uid),
            data=_body(status="under_review", note="Checking with the app team."),
            content_type=CONTENT_TYPE,
        )
        triage_id = created.json()["data"]["id"]
        note_id = created.json()["data"]["attributes"]["note_id"]

        edited = authenticated_client.patch(
            f"/api/v1/finding-triages/{triage_id}/notes/{note_id}",
            data={
                "data": {
                    "type": "finding-triage-notes",
                    "attributes": {"body": "App team owns it."},
                }
            },
            content_type=CONTENT_TYPE,
        )
        by_id = authenticated_client.get(f"/api/v1/finding-triages/{triage_id}")
        notes = authenticated_client.get(f"/api/v1/finding-triages/{triage_id}/notes")
        deleted = authenticated_client.delete(
            f"/api/v1/finding-triages/{triage_id}/notes/{note_id}"
        )

        assert created.status_code == status.HTTP_200_OK, created.json()
        assert created.json()["data"]["attributes"]["status"] == "under_review"
        assert created.json()["data"]["attributes"]["current_note"] == (
            "Checking with the app team."
        )
        assert edited.status_code == status.HTTP_200_OK, edited.json()
        assert by_id.json()["data"]["attributes"]["current_note"] == "App team owns it."
        assert [n["attributes"]["body"] for n in notes.json()["data"]] == [
            "App team owns it."
        ]
        assert deleted.status_code == status.HTTP_204_NO_CONTENT
        assert not FindingTriageNote.objects.exists()
        assert FindingTriage.objects.get().status == "under_review"

    def test_uid_with_slashes_routes_to_the_triage(
        self, authenticated_client, failing_finding
    ):
        Finding.all_objects.filter(id=failing_finding.id).update(uid=ARN_UID)

        response = authenticated_client.patch(
            _by_uid_url(ARN_UID),
            data=_body(status="remediating"),
            content_type=CONTENT_TYPE,
        )
        notes = authenticated_client.get(_by_uid_url(ARN_UID, "/notes"))

        assert response.status_code == status.HTTP_200_OK, response.json()
        assert FindingTriage.objects.get().finding_uid == ARN_UID
        assert notes.status_code == status.HTTP_200_OK
        assert notes.json()["data"] == []

    @pytest.mark.parametrize(
        "attributes, message",
        [
            ({"status": "reopened"}, "set automatically"),
            ({"status": "bogus"}, "Unknown triage status"),
            ({"status": "resolved", "note": "looks fine"}, "Only a MANUAL finding"),
            ({}, "Send a status, a note, or both"),
            ({"note": "x" * 501}, "cannot exceed 500"),
        ],
    )
    def test_invalid_updates_are_rejected(
        self, authenticated_client, failing_finding, attributes, message
    ):
        response = authenticated_client.patch(
            _by_uid_url(failing_finding.uid),
            data=_body(**attributes),
            content_type=CONTENT_TYPE,
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert message in response.json()["errors"][0]["detail"]
        assert not FindingTriage.objects.exists()

    def test_manual_finding_can_be_resolved_with_evidence(
        self, authenticated_client, failing_finding
    ):
        Finding.all_objects.filter(id=failing_finding.id).update(status="MANUAL")

        no_evidence = authenticated_client.patch(
            _by_uid_url(failing_finding.uid),
            data=_body(status="resolved"),
            content_type=CONTENT_TYPE,
        )
        resolved = authenticated_client.patch(
            _by_uid_url(failing_finding.uid),
            data=_body(status="resolved", note="Verified in the console."),
            content_type=CONTENT_TYPE,
        )

        assert no_evidence.status_code == status.HTTP_400_BAD_REQUEST
        assert resolved.status_code == status.HTTP_200_OK, resolved.json()
        attributes = resolved.json()["data"]["attributes"]
        assert attributes["status"] == "resolved"
        assert attributes["manual_pass_active"] is True
        assert attributes["manual_pass_evidence"] == "Verified in the console."
        assert attributes["manual_pass_expires_at"]

    def test_resolved_status_is_locked_for_people(
        self, authenticated_client, failing_finding, tenants_fixture
    ):
        FindingTriage.objects.create(
            tenant_id=tenants_fixture[0].id,
            finding_uid=failing_finding.uid,
            status="resolved",
        )

        response = authenticated_client.patch(
            _by_uid_url(failing_finding.uid),
            data=_body(status="open"),
            content_type=CONTENT_TYPE,
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_unknown_finding_is_not_found_and_writes_need_manage_scans(
        self, authenticated_client, authenticated_client_no_permissions_rbac
    ):
        missing = authenticated_client.get(_by_uid_url("does-not-exist"))
        forbidden = authenticated_client_no_permissions_rbac.patch(
            _by_uid_url("does-not-exist"),
            data=_body(status="open"),
            content_type=CONTENT_TYPE,
        )

        assert missing.status_code == status.HTTP_404_NOT_FOUND
        assert forbidden.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.django_db
class TestTriageInLists:
    def test_findings_list_carries_triage_fields(
        self, authenticated_client, failing_finding, tenants_fixture
    ):
        triage = FindingTriage.objects.create(
            tenant_id=tenants_fixture[0].id,
            finding_uid=failing_finding.uid,
            status="risk_accepted",
        )
        FindingTriageNote.objects.create(
            tenant_id=tenants_fixture[0].id, triage=triage, body="Accepted."
        )

        response = authenticated_client.get(
            reverse("finding-list"),
            {"filter[inserted_at]": failing_finding.inserted_at.date().isoformat()},
        )

        assert response.status_code == status.HTTP_200_OK, response.json()
        rows = {row["id"]: row["attributes"] for row in response.json()["data"]}
        triaged = rows[str(failing_finding.id)]
        assert triaged["triage_status"] == "risk_accepted"
        assert triaged["triage_id"] == str(triage.id)
        assert triaged["triage_notes_count"] == 1
        assert triaged["triage_has_note"] is True
        assert triaged["finding_uid"] == failing_finding.uid
        others = [row for key, row in rows.items() if key != str(failing_finding.id)]
        assert all(row["triage_id"] is None for row in others)


@pytest.mark.django_db
class TestApplyScanResults:
    def _scan_with(self, finding, status_value):
        scan = Scan.objects.create(
            tenant_id=finding.tenant_id,
            provider=finding.scan.provider,
            trigger="manual",
            state=StateChoices.COMPLETED,
        )
        Finding.objects.create(
            tenant_id=finding.tenant_id,
            uid=finding.uid,
            scan=scan,
            status=status_value,
            severity=finding.severity,
            impact=finding.impact,
            check_id=finding.check_id,
            check_metadata=finding.check_metadata,
        )
        return scan

    def test_failing_again_reopens_and_passing_resolves(
        self, tenants_fixture, findings_fixture
    ):
        tenant_id = str(tenants_fixture[0].id)
        resolved_one, open_one = findings_fixture[0], findings_fixture[1]
        FindingTriage.objects.create(
            tenant_id=tenant_id, finding_uid=resolved_one.uid, status="resolved"
        )
        FindingTriage.objects.create(
            tenant_id=tenant_id, finding_uid=open_one.uid, status="remediating"
        )
        failing_scan = self._scan_with(resolved_one, "FAIL")
        passing_scan = self._scan_with(open_one, "PASS")

        first = services.apply_scan_results(tenant_id, str(failing_scan.id))
        second = services.apply_scan_results(tenant_id, str(passing_scan.id))

        assert first["reopened"] == 1
        assert second["resolved"] == 1
        assert FindingTriage.objects.get(finding_uid=resolved_one.uid).status == (
            "reopened"
        )
        assert FindingTriage.objects.get(finding_uid=open_one.uid).status == "resolved"

    def test_expired_manual_pass_is_withdrawn(self, tenants_fixture, findings_fixture):
        tenant_id = str(tenants_fixture[0].id)
        finding = findings_fixture[0]
        FindingTriage.objects.create(
            tenant_id=tenant_id,
            finding_uid=finding.uid,
            status="resolved",
            manual_pass_active=True,
            manual_pass_expires_at=datetime.now(tz=UTC) - timedelta(days=1),
        )
        scan = self._scan_with(finding, "MANUAL")

        result = services.apply_scan_results(tenant_id, str(scan.id))

        triage = FindingTriage.objects.get()
        assert result["manual_pass_expired"] == 1
        assert triage.status == "reopened"
        assert triage.manual_pass_active is False
        assert triage.manual_pass_deactivated_at is not None
