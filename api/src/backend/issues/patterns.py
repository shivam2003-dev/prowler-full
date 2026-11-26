"""Attack-path patterns: which failing checks, together, make a path.

A pattern names the checks that open each leg of the path. An issue's legs
are "yes" when a failing finding covers them, "no" when the account's latest
scan passed those checks, and "unknown" when nothing tells either way.
"""

from dataclasses import dataclass, field

LEGS = ("reachability", "access", "target", "controls", "verification")


@dataclass(frozen=True)
class Pattern:
    id: str
    title: str
    outcome: str
    attacker_start: str
    fix: str
    # leg -> checks whose failure means the leg is open to the attacker
    legs: dict = field(default_factory=dict)
    # checks a passing result of which closes the controls leg
    hygiene: bool = False

    @property
    def checks(self) -> set:
        return {check for checks in self.legs.values() for check in checks}


PATTERNS = (
    Pattern(
        id="public_storage_data_exposure",
        title="Public storage exposes data to the internet",
        outcome="data_exposure",
        attacker_start="internet",
        fix="Turn on S3 Block Public Access for the account and the bucket, then "
        "remove public grants from the bucket policy and ACLs.",
        legs={
            "reachability": ("s3_bucket_public_access", "s3_bucket_public_list_acl"),
            "access": (
                "s3_bucket_policy_public_write_access",
                "s3_bucket_public_write_acl",
            ),
            "target": ("s3_bucket_public_access",),
            "controls": (
                "s3_account_level_public_access_blocks",
                "s3_bucket_level_public_access_block",
            ),
        },
    ),
    Pattern(
        id="public_database",
        title="Database reachable from the internet",
        outcome="data_exposure",
        attacker_start="internet",
        fix="Set PubliclyAccessible to false, restrict the security group to "
        "application subnets, and make snapshots private.",
        legs={
            "reachability": ("rds_instance_no_public_access",),
            "access": ("rds_snapshots_public_access",),
            "target": ("rds_instance_storage_encrypted",),
        },
    ),
    Pattern(
        id="internet_exposed_compute",
        title="Compute open to the internet",
        outcome="code_execution",
        attacker_start="internet",
        fix="Remove 0.0.0.0/0 and ::/0 ingress rules, use SSM Session Manager "
        "instead of SSH/RDP, and require IMDSv2.",
        legs={
            "reachability": (
                "ec2_securitygroup_allow_ingress_from_internet_to_all_ports",
                "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22",
                "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389",
                "ec2_instance_port_ssh_exposed_to_internet",
            ),
            "access": ("ec2_instance_public_ip",),
            "target": ("ec2_instance_imdsv2_enabled",),
            "controls": ("guardduty_is_enabled",),
        },
    ),
    Pattern(
        id="leaked_credentials",
        title="Secrets and long-lived keys an attacker can reuse",
        outcome="privilege_escalation",
        attacker_start="credential_leak",
        fix="Move secrets to Secrets Manager or Parameter Store, delete root "
        "access keys, and rotate the remaining keys.",
        legs={
            "reachability": (
                "awslambda_function_no_secrets_in_variables",
                "ecs_task_definitions_no_environment_secrets",
                "ec2_instance_secrets_user_data",
            ),
            "access": ("iam_no_root_access_key", "iam_rotate_access_key_90_days"),
            "controls": ("iam_root_mfa_enabled", "iam_user_mfa_enabled_console_access"),
        },
    ),
    Pattern(
        id="privilege_escalation",
        title="Identities that can grant themselves more access",
        outcome="privilege_escalation",
        attacker_start="authenticated_principal",
        fix="Remove the permissions that allow privilege escalation and replace "
        "administrator policies with least-privilege ones.",
        legs={
            "access": (
                "iam_policy_allows_privilege_escalation",
                "iam_aws_attached_policy_no_administrative_privileges",
                "iam_customer_attached_policy_no_administrative_privileges",
                "iam_inline_policy_no_administrative_privileges",
            ),
            "target": (
                "iam_aws_attached_policy_no_administrative_privileges",
                "iam_customer_attached_policy_no_administrative_privileges",
            ),
        },
    ),
    Pattern(
        id="detection_gaps",
        title="Gaps in logging and threat detection",
        outcome="",
        attacker_start="",
        fix="Enable a multi-region CloudTrail trail, AWS Config in every region, "
        "VPC flow logs and GuardDuty.",
        legs={
            "verification": (
                "cloudtrail_multi_region_enabled",
                "config_recorder_all_regions_enabled",
                "vpc_flow_logs_enabled",
                "guardduty_is_enabled",
            ),
        },
        hygiene=True,
    ),
)

UNMODELLED = Pattern(
    id="unmodelled",
    title="Other failing checks",
    outcome="",
    attacker_start="",
    fix="Review each failing check in Findings; they are not part of a modelled attack path.",
    hygiene=True,
)

MODELLED_CHECKS = {check for pattern in PATTERNS for check in pattern.checks}
