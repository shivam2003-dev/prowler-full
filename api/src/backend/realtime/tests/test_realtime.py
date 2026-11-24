import hashlib
import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from api.models import (
    RealtimeAction,
    RealtimeCredential,
    RealtimeDetection,
    RealtimeFeed,
    RealtimePolicy,
)
from realtime import demo, engine, insights, remediations, rules

CONTENT_TYPE = "application/vnd.api+json"
API = "/api/v1/realtime"


def ct_record(
    name, params=None, event_id=None, region="eu-west-1", user_type="IAMUser", **extra
):
    return {
        "eventID": event_id
        or hashlib.sha1(
            f"{name}{json.dumps(params, sort_keys=True)}".encode()
        ).hexdigest(),
        "eventTime": (datetime.now(tz=UTC) - timedelta(minutes=5)).isoformat(),
        "awsRegion": region,
        "eventSource": "ec2.amazonaws.com",
        "eventName": name,
        "userIdentity": {
            "type": user_type,
            "arn": "arn:aws:iam::123456789012:user/dev",
        },
        "sourceIPAddress": "198.51.100.7",
        "readOnly": False,
        "requestParameters": params or {},
        **extra,
    }


OPEN_SG = {
    "groupId": "sg-123",
    "ipPermissions": {"items": [{"ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]}}]},
}


def body(type_, attributes, provider_id=None):
    data = {"type": type_, "attributes": attributes}
    if provider_id:
        data["relationships"] = {
            "provider": {"data": {"type": "providers", "id": str(provider_id)}}
        }
    return {"data": data}


class TestRules:
    def _event(self, name, params=None, **kwargs):
        return SimpleNamespace(
            event_name=name,
            request_parameters=params or {},
            additional_data=kwargs.get("additional_data"),
            user_type=kwargs.get("user_type", "IAMUser"),
            region="eu-west-1",
        )

    @pytest.mark.parametrize(
        "name, params, violation, remediation",
        [
            ("AuthorizeSecurityGroupIngress", OPEN_SG, True, "close_open_ports"),
            (
                "AuthorizeSecurityGroupIngress",
                {"groupId": "sg-1", "ipPermissions": {"cidrIp": "10.0.0.0/8"}},
                False,
                "",
            ),
            (
                "PutBucketPublicAccessBlock",
                {
                    "bucketName": "b",
                    "PublicAccessBlockConfiguration": {"BlockPublicAcls": False},
                },
                True,
                "bucket_public_access_block",
            ),
            (
                "PutBucketPublicAccessBlock",
                {
                    "bucketName": "b",
                    "PublicAccessBlockConfiguration": {"BlockPublicAcls": True},
                },
                False,
                "",
            ),
            ("StopLogging", {"name": "trail"}, True, "start_logging"),
            ("DeleteTrail", {"name": "trail"}, True, ""),
            (
                "ModifyDBInstance",
                {"dBInstanceIdentifier": "db", "publiclyAccessible": True},
                True,
                "rds_private",
            ),
            ("CreateVolume", {"encrypted": True}, False, ""),
            (
                "AttachUserPolicy",
                {
                    "userName": "u",
                    "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
                },
                True,
                "",
            ),
            (
                "PutBucketPolicy",
                {
                    "bucketName": "b",
                    "bucketPolicy": {"Statement": [{"Principal": "*"}]},
                },
                True,
                "",
            ),
        ],
    )
    def test_verdicts(self, name, params, violation, remediation):
        verdict = rules.evaluate(self._event(name, params))

        assert verdict.violation is violation
        assert verdict.remediation_id == remediation
        assert verdict.check_ids

    def test_root_login_without_mfa_is_critical(self):
        verdict = rules.evaluate(
            self._event(
                "ConsoleLogin", user_type="Root", additional_data={"MFAUsed": "No"}
            )
        )

        assert verdict.violation and verdict.severity == "critical"
        assert "iam_root_mfa_enabled" in verdict.check_ids

    def test_unwatched_events_have_no_rule(self):
        assert rules.evaluate(self._event("DescribeInstances")) is None

    def test_every_remediation_check_exists_in_a_rule_or_catalog(self):
        assert set(remediations.APPLY) == set(remediations.CATALOG)
        assert set(remediations.REVERT) <= set(remediations.CATALOG)


@pytest.mark.django_db
class TestIngest:
    def test_violation_creates_detection_and_dry_run_fix_in_auto_mode(
        self, tenants_fixture, aws_provider
    ):
        tenant_id = str(tenants_fixture[0].id)
        RealtimePolicy.objects.create(
            tenant_id=tenant_id,
            provider=aws_provider,
            enabled=True,
            mode="auto",
            dry_run=True,
        )
        records = [
            ct_record("AuthorizeSecurityGroupIngress", OPEN_SG),
            ct_record("CreateVolume", {"encrypted": True}),
            ct_record("StopLogging", {"name": "t"}, errorCode="AccessDenied"),
            ct_record("DescribeInstances"),
        ]

        counts = engine.ingest(tenant_id, aws_provider, records)
        again = engine.ingest(tenant_id, aws_provider, records)

        assert counts == {"events": 4, "detections": 3, "violations": 1, "actions": 1}
        assert again["events"] == 0, "events are deduplicated by CloudTrail id"
        statuses = dict(RealtimeDetection.objects.values_list("rule_id", "status"))
        assert statuses == {
            "sg_open_ingress": "violation",
            "ebs_volume_unencrypted": "compliant",
            "cloudtrail_stopped": "out_of_scope",
        }
        action = RealtimeAction.objects.get()
        assert (action.kind, action.status) == ("self_fix", "dry_run")
        assert action.remediation_id == "close_open_ports"
        assert action.summary.startswith("Would apply")

    def test_monitor_mode_records_no_action_and_deny_list_is_respected(
        self, tenants_fixture, aws_provider
    ):
        tenant_id = str(tenants_fixture[0].id)
        RealtimePolicy.objects.create(
            tenant_id=tenant_id, provider=aws_provider, enabled=True, mode="monitor"
        )

        engine.ingest(
            tenant_id, aws_provider, [ct_record("StopLogging", {"name": "t"})]
        )

        assert RealtimeDetection.objects.get().status == "violation"
        assert not RealtimeAction.objects.exists()

    def test_auto_mode_queues_real_fix_only_when_server_allows_writes(
        self, tenants_fixture, aws_provider, settings
    ):
        tenant_id = str(tenants_fixture[0].id)
        RealtimePolicy.objects.create(
            tenant_id=tenant_id,
            provider=aws_provider,
            enabled=True,
            mode="auto",
            dry_run=False,
        )
        RealtimeCredential.objects.create(
            tenant_id=tenant_id, provider=aws_provider, role_arn="arn:aws:iam::1:role/R"
        )

        settings.REALTIME_REMEDIATION_ENABLED = False
        engine.ingest(
            tenant_id,
            aws_provider,
            [ct_record("StopLogging", {"name": "a"}, event_id="1")],
        )
        settings.REALTIME_REMEDIATION_ENABLED = True
        engine.ingest(
            tenant_id,
            aws_provider,
            [ct_record("StopLogging", {"name": "b"}, event_id="2")],
        )

        statuses = list(
            RealtimeAction.objects.order_by("inserted_at").values_list(
                "status", flat=True
            )
        )
        assert statuses == ["dry_run", "queued"]


@pytest.mark.django_db
class TestPollAndFix:
    def test_lookup_poll_reads_write_events_with_provider_session(
        self, tenants_fixture, aws_provider
    ):
        tenant_id = str(tenants_fixture[0].id)
        feed = RealtimeFeed.objects.create(
            tenant_id=tenant_id, provider=aws_provider, region="eu-west-1"
        )
        record = ct_record("StopLogging", {"name": "t"})
        cloudtrail = MagicMock()
        cloudtrail.lookup_events.return_value = {
            "Events": [
                {"EventName": "StopLogging", "CloudTrailEvent": json.dumps(record)},
                {"EventName": "TagResource", "CloudTrailEvent": "{}"},
            ]
        }
        session = MagicMock()
        session.client.return_value = cloudtrail
        sdk_provider = SimpleNamespace(session=SimpleNamespace(current_session=session))

        with patch(
            "realtime.engine.initialize_prowler_provider", return_value=sdk_provider
        ):
            result = engine.poll_feed(tenant_id, feed)

        feed.refresh_from_db()
        assert result["events"] == 1
        assert feed.status == "connected" and feed.last_event_at
        kwargs = cloudtrail.lookup_events.call_args.kwargs
        assert kwargs["LookupAttributes"] == [
            {"AttributeKey": "ReadOnly", "AttributeValue": "false"}
        ]
        regions = {c.kwargs["region_name"] for c in session.client.call_args_list}
        assert regions == {"eu-west-1", "us-east-1"}
        # LookupEvents only reads: no other CloudTrail method was called.
        assert [c[0] for c in cloudtrail.method_calls] == ["lookup_events"] * 2

    def test_poll_failure_is_recorded_on_the_feed(self, tenants_fixture, aws_provider):
        tenant_id = str(tenants_fixture[0].id)
        feed = RealtimeFeed.objects.create(tenant_id=tenant_id, provider=aws_provider)

        with patch(
            "realtime.engine.initialize_prowler_provider",
            side_effect=RuntimeError("bad creds"),
        ):
            engine.poll_feed(tenant_id, feed)

        feed.refresh_from_db()
        assert (feed.status, feed.last_error) == ("error", "bad creds")

    def test_apply_then_revert_bucket_block_with_mocked_aws(
        self, tenants_fixture, aws_provider
    ):
        tenant_id = str(tenants_fixture[0].id)
        RealtimeCredential.objects.create(
            tenant_id=tenant_id, provider=aws_provider, role_arn="arn:aws:iam::1:role/R"
        )
        action = RealtimeAction.objects.create(
            tenant_id=tenant_id,
            provider=aws_provider,
            kind="self_fix",
            status="queued",
            remediation_id="bucket_public_access_block",
            resource_uid="bucket-1",
            region="us-east-1",
            revertible=True,
        )
        s3 = MagicMock()
        previous = {
            "BlockPublicAcls": False,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }
        s3.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": previous
        }
        session = MagicMock()
        session.client.return_value = s3

        with patch(
            "realtime.engine.remediations.remediation_session", return_value=session
        ):
            engine.apply_action(action)
            engine.revert_action(action)

        assert action.status == "reverted"
        first, second = s3.put_public_access_block.call_args_list
        assert all(first.kwargs["PublicAccessBlockConfiguration"].values())
        assert second.kwargs["PublicAccessBlockConfiguration"] == previous


@pytest.mark.django_db
class TestRealtimeApi:
    def test_policy_create_list_update(self, authenticated_client, aws_provider):
        created = authenticated_client.post(
            f"{API}/policies",
            data=body(
                "realtime-policies",
                {
                    "enabled": False,
                    "mode": "monitor",
                    "dry_run": True,
                    "min_severity": "high",
                    "deny_checks": [],
                    "allow_regions": ["eu-west-1"],
                    "scope_tags": {},
                    "frameworks": [],
                },
                aws_provider.id,
            ),
            content_type=CONTENT_TYPE,
        )
        policy_id = created.json()["data"]["id"]
        listed = authenticated_client.get(
            f"{API}/policies", {"filter[provider]": str(aws_provider.id)}
        )
        updated = authenticated_client.patch(
            f"{API}/policies/{policy_id}",
            data=body("realtime-policies", {"enabled": True, "mode": "auto"}),
            content_type=CONTENT_TYPE,
        )
        bad = authenticated_client.patch(
            f"{API}/policies/{policy_id}",
            data=body("realtime-policies", {"mode": "nuke"}),
            content_type=CONTENT_TYPE,
        )

        assert created.status_code == 201, created.json()
        assert created.json()["data"]["relationships"]["provider"]["data"]["id"] == str(
            aws_provider.id
        )
        assert listed.json()["data"][0]["attributes"]["allow_regions"] == ["eu-west-1"]
        assert updated.json()["data"]["attributes"]["mode"] == "auto"
        assert bad.status_code == 400
        assert bad.json()["errors"][0]["detail"]

    def test_non_aws_provider_is_rejected(self, authenticated_client, gcp_provider):
        response = authenticated_client.get(
            f"{API}/policies", {"filter[provider]": str(gcp_provider.id)}
        )

        assert response.status_code == 404

    def test_feed_poll_queues_task(
        self, authenticated_client, aws_provider, django_capture_on_commit_callbacks
    ):
        feed = authenticated_client.post(
            f"{API}/feeds",
            data=body(
                "realtime-feeds",
                {"queue_url": "", "region": "eu-west-1"},
                aws_provider.id,
            ),
            content_type=CONTENT_TYPE,
        ).json()["data"]
        with (
            patch("tasks.tasks.realtime_poll_feed_task.apply_async") as queued,
            django_capture_on_commit_callbacks(execute=True),
        ):
            response = authenticated_client.post(
                f"{API}/feeds/{feed['id']}/poll",
                data=body("realtime-feeds", {}),
                content_type=CONTENT_TYPE,
            )

        assert response.status_code == 202
        queued.assert_called_once()

    def test_lists_and_detail(
        self, authenticated_client, tenants_fixture, aws_provider
    ):
        tenant_id = str(tenants_fixture[0].id)
        RealtimePolicy.objects.create(
            tenant_id=tenant_id, provider=aws_provider, enabled=True, mode="auto"
        )
        engine.ingest(
            tenant_id,
            aws_provider,
            [
                ct_record("AuthorizeSecurityGroupIngress", OPEN_SG),
                ct_record("CreateVolume", {"encrypted": True}),
            ],
        )
        q = {"filter[provider]": str(aws_provider.id)}

        events = authenticated_client.get(
            f"{API}/events", {"provider": str(aws_provider.id), "limit": "10"}
        )
        detections = authenticated_client.get(
            f"{API}/detections",
            {**q, "filter[status__in]": "violation", "page[size]": "1"},
        )
        actions = authenticated_client.get(f"{API}/actions", q)
        detail = authenticated_client.get(
            f"{API}/detections/{detections.json()['data'][0]['id']}"
        )

        assert {e["attributes"]["detection_status"] for e in events.json()["data"]} == {
            "violation",
            "compliant",
        }
        assert detections.json()["meta"]["pagination"] == {
            "page": 1,
            "pages": 1,
            "count": 1,
        }
        assert actions.json()["data"][0]["relationships"]["detection"]["data"]["id"]
        assert detail.json()["data"]["attributes"]["rule_id"] == "sg_open_ingress"

    def test_revert_of_dry_run_is_a_409(
        self, authenticated_client, tenants_fixture, aws_provider
    ):
        action = RealtimeAction.objects.create(
            tenant_id=tenants_fixture[0].id,
            provider=aws_provider,
            kind="self_fix",
            status="dry_run",
            remediation_id="rds_private",
            revertible=True,
        )

        response = authenticated_client.post(
            f"{API}/actions/{action.id}/revert",
            data=body("realtime-actions", {}),
            content_type=CONTENT_TYPE,
        )

        assert response.status_code == 409
        assert "applied" in response.json()["errors"][0]["detail"]

    def test_credentials_are_write_only(self, authenticated_client, aws_provider):
        saved = authenticated_client.post(
            f"{API}/credentials",
            data=body(
                "realtime-credentials",
                {
                    "role_arn": "arn:aws:iam::123456789012:role/ProwlerRemediation",
                    "external_id": "secret-ext-id",
                    "github_token": "ghp_secret",
                },
                aws_provider.id,
            ),
            content_type=CONTENT_TYPE,
        )

        assert saved.status_code == 201, saved.json()
        text = saved.content.decode()
        assert "secret-ext-id" not in text and "ghp_secret" not in text
        assert saved.json()["data"]["attributes"]["has_github_token"] is True
        stored = RealtimeCredential.objects.get()
        assert stored.secrets_decoded == {
            "external_id": "secret-ext-id",
            "github_token": "ghp_secret",
        }

    @pytest.mark.parametrize(
        "kind",
        ["overview", "findings", "cost", "simulation", "timeline", "status", "setup"],
    )
    def test_insights_return_their_kind(
        self, authenticated_client, findings_fixture, aws_provider, kind
    ):
        provider = findings_fixture[0].scan.provider
        response = authenticated_client.get(
            f"{API}/insights/{kind}", {"provider": str(provider.id)}
        )

        assert response.status_code == 200, response.json()
        attributes = response.json()["data"]["attributes"]
        assert attributes["kind"] == kind
        assert isinstance(attributes["payload"], dict)

    def test_setup_walks_required_steps(
        self, authenticated_client, tenants_fixture, aws_provider
    ):
        tenant_id = tenants_fixture[0].id
        q = {"provider": str(aws_provider.id)}
        before = authenticated_client.get(f"{API}/insights/setup", q).json()["data"][
            "attributes"
        ]["payload"]
        RealtimeFeed.objects.create(tenant_id=tenant_id, provider=aws_provider)
        RealtimePolicy.objects.create(
            tenant_id=tenant_id, provider=aws_provider, enabled=True
        )
        after = authenticated_client.get(f"{API}/insights/setup", q).json()["data"][
            "attributes"
        ]["payload"]

        assert (before["activated"], before["next_step"]) == (False, "feed")
        assert (after["activated"], after["next_step"]) == (True, None)

    @pytest.mark.parametrize(
        "kind",
        [
            "overview",
            "findings",
            "cost",
            "anomaly",
            "simulation",
            "timeline",
            "status",
            "events",
            "detections",
            "actions",
        ],
    )
    def test_demo_kinds(self, authenticated_client, kind):
        response = authenticated_client.get(f"{API}/demo/{kind}")

        assert response.status_code == 200
        payload = response.json()["data"]["attributes"]["payload"]
        if kind in ("events", "detections", "actions"):
            assert payload["items"]
        assert demo.payload(kind) is not None

    def test_remediations_and_frameworks(self, authenticated_client, aws_provider):
        remediation_rows = authenticated_client.get(
            f"{API}/remediations", {"provider": str(aws_provider.id)}
        ).json()["data"]
        frameworks = authenticated_client.get(f"{API}/frameworks").json()["data"]

        assert {r["id"] for r in remediation_rows} == set(remediations.CATALOG)
        assert frameworks and all(
            f["type"] == "realtime-frameworks" for f in frameworks
        )

    def test_writes_need_manage_scans(self, authenticated_client_no_permissions_rbac):
        response = authenticated_client_no_permissions_rbac.post(
            f"{API}/policies",
            data=body("realtime-policies", {}),
            content_type=CONTENT_TYPE,
        )
        assert response.status_code == 403


def test_insight_views_cover_every_ui_kind():
    assert set(insights.VIEWS) | {"anomaly", "setup"} == {
        "overview",
        "findings",
        "cost",
        "anomaly",
        "simulation",
        "timeline",
        "status",
        "setup",
    }
