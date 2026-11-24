"""Detection rules: which CloudTrail write events break which Prowler checks.

Each rule reads one event and returns a verdict. The verdict says whether the
change is a violation and which remediation (if any) can undo it. Rules only
read the event; they never call AWS.
"""

import json
from dataclasses import dataclass, field

OPEN_CIDRS = ("0.0.0.0/0", "::/0")
ADMIN_POLICY_SUFFIX = ":policy/AdministratorAccess"
SEVERITY_RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# The event names the Realtime feed template forwards; LookupEvents is
# narrowed to the same set.
WATCHED_EVENTS = (
    "AuthorizeSecurityGroupIngress",
    "PutBucketPublicAccessBlock",
    "DeleteBucketPublicAccessBlock",
    "PutAccountPublicAccessBlock",
    "DeletePublicAccessBlock",
    "PutBucketPolicy",
    "StopLogging",
    "DeleteTrail",
    "UpdateTrail",
    "StopConfigurationRecorder",
    "DeleteConfigurationRecorder",
    "DeleteFlowLogs",
    "ScheduleKeyDeletion",
    "DisableKey",
    "DisableEbsEncryptionByDefault",
    "CreateVolume",
    "RunInstances",
    "CreateDBInstance",
    "ModifyDBInstance",
    "AttachUserPolicy",
    "AttachRolePolicy",
    "AttachGroupPolicy",
    "CreateAccessKey",
    "ConsoleLogin",
)


@dataclass
class Verdict:
    rule_id: str
    title: str
    severity: str
    violation: bool
    check_ids: list = field(default_factory=list)
    resource: str = ""
    remediation_id: str = ""
    note: str = ""


def _params(event) -> dict:
    value = event.request_parameters
    return value if isinstance(value, dict) else {}


def _text(value) -> str:
    return value if isinstance(value, str) else json.dumps(value or {})


def _flags_off(config) -> bool:
    config = config if isinstance(config, dict) else {}
    keys = (
        "BlockPublicAcls",
        "IgnorePublicAcls",
        "BlockPublicPolicy",
        "RestrictPublicBuckets",
    )
    return any(config.get(key) is False for key in keys)


def _security_group_ingress(event) -> Verdict:
    params = _params(event)
    text = _text(params.get("ipPermissions"))
    open_to_world = any(cidr in text for cidr in OPEN_CIDRS)
    return Verdict(
        rule_id="sg_open_ingress",
        title="Security group opened to the internet",
        severity="high",
        violation=open_to_world,
        check_ids=[
            "ec2_securitygroup_allow_ingress_from_internet_to_all_ports",
            "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22",
            "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389",
        ],
        resource=params.get("groupId", ""),
        remediation_id="close_open_ports" if open_to_world else "",
        note="" if open_to_world else "The new rule does not allow 0.0.0.0/0 or ::/0.",
    )


def _bucket_public_access_block(event) -> Verdict:
    params = _params(event)
    deleted = event.event_name == "DeleteBucketPublicAccessBlock"
    violation = deleted or _flags_off(params.get("PublicAccessBlockConfiguration"))
    return Verdict(
        rule_id="s3_bucket_public_access_block",
        title="S3 bucket public access block weakened",
        severity="high",
        violation=violation,
        check_ids=["s3_bucket_level_public_access_block", "s3_bucket_public_access"],
        resource=params.get("bucketName", ""),
        remediation_id="bucket_public_access_block" if violation else "",
    )


def _account_public_access_block(event) -> Verdict:
    params = _params(event)
    deleted = event.event_name == "DeletePublicAccessBlock"
    violation = deleted or _flags_off(params.get("PublicAccessBlockConfiguration"))
    return Verdict(
        rule_id="s3_account_public_access_block",
        title="Account-wide S3 public access block weakened",
        severity="high",
        violation=violation,
        check_ids=["s3_account_level_public_access_blocks"],
        resource=params.get("accountId", ""),
        remediation_id="account_public_access_block" if violation else "",
    )


def _bucket_policy(event) -> Verdict:
    params = _params(event)
    policy = _text(params.get("bucketPolicy"))
    public = '"Principal":"*"' in policy.replace(
        " ", ""
    ) or '"AWS":"*"' in policy.replace(" ", "")
    return Verdict(
        rule_id="s3_bucket_policy_public",
        title="S3 bucket policy grants access to everyone",
        severity="critical",
        violation=public,
        check_ids=["s3_bucket_policy_public_write_access", "s3_bucket_public_access"],
        resource=params.get("bucketName", ""),
    )


def _trail(event) -> Verdict:
    params = _params(event)
    name = params.get("name", "")
    if event.event_name == "UpdateTrail":
        violation = params.get("isMultiRegionTrail") is False
        return Verdict(
            rule_id="cloudtrail_weakened",
            title="CloudTrail trail no longer multi-region",
            severity="medium",
            violation=violation,
            check_ids=["cloudtrail_multi_region_enabled"],
            resource=name,
        )
    stopped = event.event_name == "StopLogging"
    return Verdict(
        rule_id="cloudtrail_stopped" if stopped else "cloudtrail_deleted",
        title="CloudTrail logging stopped" if stopped else "CloudTrail trail deleted",
        severity="critical",
        violation=True,
        check_ids=[
            "cloudtrail_multi_region_enabled",
            "cloudtrail_multi_region_enabled_logging_management_events",
        ],
        resource=name,
        remediation_id="start_logging" if stopped else "",
    )


def _config_recorder(event) -> Verdict:
    return Verdict(
        rule_id="config_recorder_disabled",
        title="AWS Config recorder stopped or deleted",
        severity="medium",
        violation=True,
        check_ids=["config_recorder_all_regions_enabled"],
        resource=_params(event).get("configurationRecorderName", ""),
    )


def _flow_logs(event) -> Verdict:
    ids = _params(event).get("DeleteFlowLogsRequest", {}) or {}
    return Verdict(
        rule_id="vpc_flow_logs_deleted",
        title="VPC flow logs deleted",
        severity="medium",
        violation=True,
        check_ids=["vpc_flow_logs_enabled"],
        resource=_text(ids.get("FlowLogId") or ""),
    )


def _kms(event) -> Verdict:
    deletion = event.event_name == "ScheduleKeyDeletion"
    return Verdict(
        rule_id="kms_key_deletion" if deletion else "kms_key_disabled",
        title="KMS key scheduled for deletion" if deletion else "KMS key disabled",
        severity="high",
        violation=True,
        check_ids=["kms_cmk_not_deleted_unintentionally", "kms_cmk_are_used"],
        resource=_params(event).get("keyId", ""),
    )


def _ebs_default(event) -> Verdict:
    return Verdict(
        rule_id="ebs_default_encryption_disabled",
        title="EBS encryption by default turned off",
        severity="medium",
        violation=True,
        check_ids=["ec2_ebs_default_encryption"],
        resource=event.region,
        remediation_id="ebs_default_encryption",
    )


def _volume(event) -> Verdict:
    encrypted = _params(event).get("encrypted") is True
    return Verdict(
        rule_id="ebs_volume_unencrypted",
        title="Unencrypted EBS volume created",
        severity="medium",
        violation=not encrypted,
        check_ids=["ec2_ebs_volume_encryption"],
    )


def _instances(event) -> Verdict:
    params = _params(event)
    options = params.get("metadataOptions") or {}
    imdsv1 = options.get("httpTokens") != "required"
    network = _text(params.get("networkInterfaceSet"))
    public_ip = '"associatePublicIpAddress":true' in network.replace(" ", "")
    checks = (["ec2_instance_imdsv2_enabled"] if imdsv1 else []) + (
        ["ec2_instance_public_ip"] if public_ip else []
    )
    return Verdict(
        rule_id="ec2_instance_launch",
        title="EC2 instance launched with risky settings"
        if checks
        else "EC2 instance launched",
        severity="medium",
        violation=bool(checks),
        check_ids=checks or ["ec2_instance_imdsv2_enabled"],
    )


def _db_instance(event) -> Verdict:
    params = _params(event)
    public = params.get("publiclyAccessible") is True
    unencrypted = (
        event.event_name == "CreateDBInstance"
        and params.get("storageEncrypted") is not True
    )
    checks = (["rds_instance_no_public_access"] if public else []) + (
        ["rds_instance_storage_encrypted"] if unencrypted else []
    )
    return Verdict(
        rule_id="rds_instance_exposed" if public else "rds_instance_change",
        title="RDS database made public" if public else "RDS database changed",
        severity="high" if public else "medium",
        violation=bool(checks),
        check_ids=checks or ["rds_instance_no_public_access"],
        resource=params.get("dBInstanceIdentifier", ""),
        remediation_id="rds_private" if public else "",
    )


def _attach_policy(event) -> Verdict:
    params = _params(event)
    admin = str(params.get("policyArn", "")).endswith(ADMIN_POLICY_SUFFIX)
    principal = (
        params.get("userName")
        or params.get("roleName")
        or params.get("groupName")
        or ""
    )
    return Verdict(
        rule_id="iam_admin_policy_attached",
        title="AdministratorAccess attached" if admin else "IAM policy attached",
        severity="high" if admin else "low",
        violation=admin,
        check_ids=["iam_aws_attached_policy_no_administrative_privileges"],
        resource=principal,
    )


def _access_key(event) -> Verdict:
    root = event.user_type == "Root"
    return Verdict(
        rule_id="iam_root_access_key" if root else "iam_access_key_created",
        title="Root access key created" if root else "IAM access key created",
        severity="critical" if root else "low",
        violation=root,
        check_ids=["iam_no_root_access_key"]
        if root
        else ["iam_rotate_access_key_90_days"],
        resource=_params(event).get("userName", ""),
    )


def _console_login(event) -> Verdict:
    extra = event.additional_data if isinstance(event.additional_data, dict) else {}
    root = event.user_type == "Root"
    no_mfa = extra.get("MFAUsed") == "No"
    if root:
        return Verdict(
            rule_id="root_console_login",
            title="Root user signed in to the console",
            severity="critical" if no_mfa else "high",
            violation=True,
            check_ids=["iam_avoid_root_usage"]
            + (["iam_root_mfa_enabled"] if no_mfa else []),
        )
    return Verdict(
        rule_id="console_login_without_mfa",
        title="Console sign-in without MFA" if no_mfa else "Console sign-in",
        severity="medium" if no_mfa else "informational",
        violation=no_mfa,
        check_ids=["iam_user_mfa_enabled_console_access"],
    )


RULES = {
    "AuthorizeSecurityGroupIngress": _security_group_ingress,
    "PutBucketPublicAccessBlock": _bucket_public_access_block,
    "DeleteBucketPublicAccessBlock": _bucket_public_access_block,
    "PutAccountPublicAccessBlock": _account_public_access_block,
    "DeletePublicAccessBlock": _account_public_access_block,
    "PutBucketPolicy": _bucket_policy,
    "StopLogging": _trail,
    "DeleteTrail": _trail,
    "UpdateTrail": _trail,
    "StopConfigurationRecorder": _config_recorder,
    "DeleteConfigurationRecorder": _config_recorder,
    "DeleteFlowLogs": _flow_logs,
    "ScheduleKeyDeletion": _kms,
    "DisableKey": _kms,
    "DisableEbsEncryptionByDefault": _ebs_default,
    "CreateVolume": _volume,
    "RunInstances": _instances,
    "CreateDBInstance": _db_instance,
    "ModifyDBInstance": _db_instance,
    "AttachUserPolicy": _attach_policy,
    "AttachRolePolicy": _attach_policy,
    "AttachGroupPolicy": _attach_policy,
    "CreateAccessKey": _access_key,
    "ConsoleLogin": _console_login,
}


def evaluate(event) -> Verdict | None:
    rule = RULES.get(event.event_name)
    return rule(event) if rule else None


def at_least(severity: str, minimum: str) -> bool:
    return SEVERITY_RANK.get(severity, 0) >= SEVERITY_RANK.get(minimum, 0)
