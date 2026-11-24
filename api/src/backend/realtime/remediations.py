"""Fixes Realtime can apply through the customer's ProwlerRemediation role.

Every fix records what it changed so it can be reverted. AWS is only written
to when the server allows it (REALTIME_REMEDIATION_ENABLED) and the policy is
in auto mode without dry run; otherwise the fix is recorded as a dry run.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Remediation:
    id: str
    title: str
    effect: str
    checks: tuple
    iam_actions: tuple
    revertible: bool
    undo: str


CATALOG = {
    item.id: item
    for item in (
        Remediation(
            "close_open_ports",
            "Close internet-open ports",
            "Revokes the 0.0.0.0/0 and ::/0 ingress rules added to the security group.",
            (
                "ec2_securitygroup_allow_ingress_from_internet_to_all_ports",
                "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22",
                "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389",
            ),
            (
                "ec2:DescribeSecurityGroups",
                "ec2:RevokeSecurityGroupIngress",
                "ec2:AuthorizeSecurityGroupIngress",
            ),
            True,
            "Adds the revoked rules back.",
        ),
        Remediation(
            "bucket_public_access_block",
            "Block public access on the bucket",
            "Turns on the four public access block settings of the bucket.",
            ("s3_bucket_level_public_access_block", "s3_bucket_public_access"),
            ("s3:GetBucketPublicAccessBlock", "s3:PutBucketPublicAccessBlock"),
            True,
            "Restores the bucket's previous public access block settings.",
        ),
        Remediation(
            "account_public_access_block",
            "Block public access account-wide",
            "Turns on the account-wide S3 public access block. Buckets that are "
            "public on purpose stop being public.",
            ("s3_account_level_public_access_blocks",),
            ("s3:GetAccountPublicAccessBlock", "s3:PutAccountPublicAccessBlock"),
            True,
            "Restores the previous account-wide settings.",
        ),
        Remediation(
            "start_logging",
            "Start CloudTrail logging again",
            "Starts logging on the trail that was stopped.",
            (
                "cloudtrail_multi_region_enabled",
                "cloudtrail_multi_region_enabled_logging_management_events",
            ),
            (
                "cloudtrail:DescribeTrails",
                "cloudtrail:GetTrailStatus",
                "cloudtrail:StartLogging",
            ),
            False,
            "Not revertible: stopping a trail is never a fix.",
        ),
        Remediation(
            "ebs_default_encryption",
            "Encrypt new EBS volumes by default",
            "Enables EBS encryption by default in the region. Existing volumes are not changed.",
            ("ec2_ebs_default_encryption",),
            (
                "ec2:GetEbsEncryptionByDefault",
                "ec2:EnableEbsEncryptionByDefault",
                "ec2:DisableEbsEncryptionByDefault",
            ),
            True,
            "Disables encryption by default again.",
        ),
        Remediation(
            "rds_private",
            "Make the database private",
            "Sets PubliclyAccessible to false on the RDS instance.",
            ("rds_instance_no_public_access",),
            ("rds:DescribeDBInstances", "rds:ModifyDBInstance"),
            True,
            "Sets PubliclyAccessible back to true.",
        ),
    )
}

CHECK_TO_REMEDIATION = {
    check: remediation.id
    for remediation in CATALOG.values()
    for check in remediation.checks
}


class RemediationError(Exception):
    """AWS refused the change."""


def _apply_close_open_ports(session, action, event):
    ec2 = session.client("ec2", region_name=action.region)
    group_id = action.resource_uid
    group = ec2.describe_security_groups(GroupIds=[group_id])["SecurityGroups"][0]
    revoked = []
    for permission in group.get("IpPermissions", []):
        open_v4 = [
            r
            for r in permission.get("IpRanges", [])
            if r.get("CidrIp") in ("0.0.0.0/0",)
        ]
        open_v6 = [
            r
            for r in permission.get("Ipv6Ranges", [])
            if r.get("CidrIpv6") in ("::/0",)
        ]
        if not (open_v4 or open_v6):
            continue
        rule = {
            key: permission[key]
            for key in ("IpProtocol", "FromPort", "ToPort")
            if key in permission
        }
        rule["IpRanges"] = open_v4
        rule["Ipv6Ranges"] = open_v6
        revoked.append(rule)
    if revoked:
        ec2.revoke_security_group_ingress(GroupId=group_id, IpPermissions=revoked)
    return {"group_id": group_id, "revoked": revoked}


def _revert_close_open_ports(session, action):
    state = action.undo_state or {}
    if state.get("revoked"):
        session.client(
            "ec2", region_name=action.region
        ).authorize_security_group_ingress(
            GroupId=state["group_id"], IpPermissions=state["revoked"]
        )


_BLOCK_ALL = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}


def _apply_bucket_block(session, action, event):
    s3 = session.client("s3", region_name=action.region)
    try:
        previous = s3.get_public_access_block(Bucket=action.resource_uid)[
            "PublicAccessBlockConfiguration"
        ]
    except Exception:  # noqa: BLE001 - no block configured yet
        previous = None
    s3.put_public_access_block(
        Bucket=action.resource_uid, PublicAccessBlockConfiguration=_BLOCK_ALL
    )
    return {"bucket": action.resource_uid, "previous": previous}


def _revert_bucket_block(session, action):
    state = action.undo_state or {}
    s3 = session.client("s3", region_name=action.region)
    if state.get("previous"):
        s3.put_public_access_block(
            Bucket=state["bucket"], PublicAccessBlockConfiguration=state["previous"]
        )
    else:
        s3.delete_public_access_block(Bucket=state["bucket"])


def _apply_account_block(session, action, event):
    s3control = session.client("s3control", region_name=action.region or "us-east-1")
    account_id = action.provider.uid
    try:
        previous = s3control.get_public_access_block(AccountId=account_id)[
            "PublicAccessBlockConfiguration"
        ]
    except Exception:  # noqa: BLE001
        previous = None
    s3control.put_public_access_block(
        AccountId=account_id, PublicAccessBlockConfiguration=_BLOCK_ALL
    )
    return {"account_id": account_id, "previous": previous}


def _revert_account_block(session, action):
    state = action.undo_state or {}
    s3control = session.client("s3control", region_name=action.region or "us-east-1")
    if state.get("previous"):
        s3control.put_public_access_block(
            AccountId=state["account_id"],
            PublicAccessBlockConfiguration=state["previous"],
        )
    else:
        s3control.delete_public_access_block(AccountId=state["account_id"])


def _apply_start_logging(session, action, event):
    session.client("cloudtrail", region_name=action.region).start_logging(
        Name=action.resource_uid
    )
    return {"trail": action.resource_uid}


def _apply_ebs_default(session, action, event):
    session.client("ec2", region_name=action.region).enable_ebs_encryption_by_default()
    return {"region": action.region}


def _revert_ebs_default(session, action):
    session.client("ec2", region_name=action.region).disable_ebs_encryption_by_default()


def _apply_rds_private(session, action, event):
    session.client("rds", region_name=action.region).modify_db_instance(
        DBInstanceIdentifier=action.resource_uid,
        PubliclyAccessible=False,
        ApplyImmediately=True,
    )
    return {"db_instance": action.resource_uid}


def _revert_rds_private(session, action):
    session.client("rds", region_name=action.region).modify_db_instance(
        DBInstanceIdentifier=(action.undo_state or {}).get(
            "db_instance", action.resource_uid
        ),
        PubliclyAccessible=True,
        ApplyImmediately=True,
    )


APPLY = {
    "close_open_ports": _apply_close_open_ports,
    "bucket_public_access_block": _apply_bucket_block,
    "account_public_access_block": _apply_account_block,
    "start_logging": _apply_start_logging,
    "ebs_default_encryption": _apply_ebs_default,
    "rds_private": _apply_rds_private,
}
REVERT = {
    "close_open_ports": _revert_close_open_ports,
    "bucket_public_access_block": _revert_bucket_block,
    "account_public_access_block": _revert_account_block,
    "ebs_default_encryption": _revert_ebs_default,
    "rds_private": _revert_rds_private,
}


def remediation_session(credential):
    """boto3 session on the customer's ProwlerRemediation role."""
    import boto3

    sts = boto3.client("sts")
    assumed = sts.assume_role(
        RoleArn=credential.role_arn,
        RoleSessionName="prowler-realtime",
        ExternalId=credential.secrets_decoded.get("external_id", ""),
        DurationSeconds=900,
    )["Credentials"]
    return boto3.session.Session(
        aws_access_key_id=assumed["AccessKeyId"],
        aws_secret_access_key=assumed["SecretAccessKey"],
        aws_session_token=assumed["SessionToken"],
    )
