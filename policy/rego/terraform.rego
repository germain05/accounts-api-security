# Structural prevention for the Terraform defects in section 4b.
# Threat T3 (database exposure), plus T4 for the ECR rules and evidence
# integrity for the CloudTrail rules.
#
# Run:  conftest test --policy policy/rego --parser hcl2 --all-namespaces terraform/
# Test: conftest verify --policy policy/rego
#
# Design choices worth defending:
#  * These rules are about DATA-PLANE EXPOSURE, not about style. Every one of
#    them blocks a merge, which is only tenable because the set is small and each
#    rule is a thing a reviewer would stop the PR for anyway.
#  * Rules assert on the *absence* of a safe value, not the presence of an unsafe
#    one, so a resource that simply omits the attribute is caught. The original
#    manifest's real risk was omission, not a wrong value.
#  * No rule names accounts-api. A policy that only defends one service is a
#    review comment with extra steps; these apply to every repo that adopts them.

package main

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# ---------------------------------------------------------------------------
# helpers

resources(kind) := {name: body |
	some name
	body := input.resource[kind][name]
}

# true when `field` is absent or falsy — the omission case
missing_or_false(body, field) if not body[field]

# ---------------------------------------------------------------------------
# B1 — the database must not be reachable from the internet.

deny contains msg if {
	some name, body in resources("aws_db_instance")
	body.publicly_accessible == true
	msg := sprintf(
		"deny_rds_publicly_accessible: aws_db_instance.%s has publicly_accessible=true. A production database holding PII must have no public endpoint. [T3/B1]",
		[name],
	)
}

deny contains msg if {
	some name, body in resources("aws_security_group_rule")
	body.type == "ingress"
	some cidr in body.cidr_blocks
	cidr in {"0.0.0.0/0", "::/0"}
	msg := sprintf(
		"deny_open_ingress: aws_security_group_rule.%s allows ingress on %v-%v from %s. Use source_security_group_id; a CIDR is a claim about the network, an SG id is a claim about identity. [T3/B1]",
		[name, body.from_port, body.to_port, cidr],
	)
}

deny contains msg if {
	some name, body in resources("aws_security_group")
	some rule in body.ingress
	some cidr in rule.cidr_blocks
	cidr in {"0.0.0.0/0", "::/0"}
	msg := sprintf(
		"deny_open_ingress: aws_security_group.%s has an inline ingress rule open to %s. [T3/B1]",
		[name, cidr],
	)
}

# ---------------------------------------------------------------------------
# B2 — the master credential must not be able to reach Terraform state.

deny contains msg if {
	some name, body in resources("aws_db_instance")
	body.password
	msg := sprintf(
		"deny_rds_inline_password: aws_db_instance.%s sets `password`, which is stored in PLAINTEXT in Terraform state. Use manage_master_user_password=true (RDS-managed secret) and iam_database_authentication_enabled=true for the app path. [T3/B2]",
		[name],
	)
}

# ---------------------------------------------------------------------------
# B3 — encryption at rest cannot be retrofitted in place, so it is a merge gate.

deny contains msg if {
	some name, body in resources("aws_db_instance")
	missing_or_false(body, "storage_encrypted")
	msg := sprintf(
		"deny_rds_unencrypted: aws_db_instance.%s is unencrypted at rest. This cannot be enabled in place — it requires a snapshot/restore/cutover — so it must be right at creation. [T3/B3]",
		[name],
	)
}

deny contains msg if {
	some name, body in resources("aws_db_instance")
	body.storage_encrypted == true
	not body.kms_key_id
	msg := sprintf(
		"deny_rds_aws_managed_key: aws_db_instance.%s is encrypted with the AWS-managed key. Use a customer-managed key so key custody, rotation and grant revocation are ours. [T3/B3]",
		[name],
	)
}

# ---------------------------------------------------------------------------
# B4 — recoverability. Integrity and availability, and a retention obligation.

deny contains msg if {
	some name, body in resources("aws_db_instance")
	# object.get with a default, NOT `body.backup_retention_period < 7`. The bare
	# comparison is UNDEFINED when the attribute is absent, so the rule silently
	# passes a resource that never set it at all — the omission case, which is the
	# one that actually happens. Same pattern for the Aurora rule below.
	retention := object.get(body, "backup_retention_period", 0)
	retention < 7
	msg := sprintf(
		"deny_rds_no_backups: aws_db_instance.%s has backup_retention_period=%v (attribute absent counts as 0). Minimum 7 days; a destructive attacker or a bad migration is unrecoverable below that. [T3/B4]",
		[name, retention],
	)
}

deny contains msg if {
	some name, body in resources("aws_db_instance")
	body.skip_final_snapshot == true
	msg := sprintf(
		"deny_rds_no_final_snapshot: aws_db_instance.%s has skip_final_snapshot=true. Deletion becomes irreversible. [T3/B4]",
		[name],
	)
}

deny contains msg if {
	some name, body in resources("aws_db_instance")
	missing_or_false(body, "deletion_protection")
	msg := sprintf(
		"deny_rds_no_deletion_protection: aws_db_instance.%s has no deletion_protection. [T3/B4]",
		[name],
	)
}

# ---------------------------------------------------------------------------
# B5 — the audit trail. Without these, nothing else here is provable.

deny contains msg if {
	some name, body in resources("aws_cloudtrail")
	missing_or_false(body, "include_global_service_events")
	msg := sprintf(
		"deny_cloudtrail_no_global_events: aws_cloudtrail.%s excludes global service events, so IAM, STS, CloudFront and Route53 calls are NOT RECORDED AT ALL — the exact API calls of an identity attack. [B5]",
		[name],
	)
}

deny contains msg if {
	some name, body in resources("aws_cloudtrail")
	missing_or_false(body, "is_multi_region_trail")
	msg := sprintf(
		"deny_cloudtrail_single_region: aws_cloudtrail.%s is single-region; an attacker operating in any other region is invisible. [B5]",
		[name],
	)
}

deny contains msg if {
	some name, body in resources("aws_cloudtrail")
	missing_or_false(body, "enable_log_file_validation")
	msg := sprintf(
		"deny_cloudtrail_no_validation: aws_cloudtrail.%s has no log file validation, so there is no digest chain and the log is not tamper-evident evidence. [B5]",
		[name],
	)
}

deny contains msg if {
	some name, body in resources("aws_cloudtrail")
	not body.kms_key_id
	msg := sprintf(
		"deny_cloudtrail_unencrypted: aws_cloudtrail.%s writes unencrypted log files. [B5]",
		[name],
	)
}

# ---------------------------------------------------------------------------
# T4 — artefact integrity, enforced at the registry.

deny contains msg if {
	some name, body in resources("aws_ecr_repository")
	body.image_tag_mutability != "IMMUTABLE"
	msg := sprintf(
		"deny_ecr_mutable_tags: aws_ecr_repository.%s allows tag mutation, so a pushed tag can be re-pointed at a different image without any change in Git. [T4]",
		[name],
	)
}

# ---------------------------------------------------------------------------
# Key custody. Regulatory rather than threat-driven — see TRACEABILITY.md.

deny contains msg if {
	some name, body in resources("aws_kms_key")
	missing_or_false(body, "enable_key_rotation")
	msg := sprintf(
		"deny_kms_no_rotation: aws_kms_key.%s has automatic rotation disabled. [regulatory: key management]",
		[name],
	)
}

# ---------------------------------------------------------------------------
# Data residency: RBI localisation means this stack exists in ap-south-1 only.
# Multi-region keys replicate key material out of the region.

deny contains msg if {
	some name, body in resources("aws_kms_key")
	body.multi_region == true
	msg := sprintf(
		"deny_kms_multi_region: aws_kms_key.%s is multi-region, which replicates key material outside ap-south-1. [regulatory: data residency]",
		[name],
	)
}

# ---------------------------------------------------------------------------
# warn: things worth saying that are not worth blocking a merge for. Kept
# deliberately short — a warn list that scrolls is a warn list nobody reads.

warn contains msg if {
	some name, body in resources("aws_db_instance")
	missing_or_false(body, "multi_az")
	msg := sprintf(
		"warn_rds_single_az: aws_db_instance.%s is single-AZ. Availability, not security; not a merge blocker.",
		[name],
	)
}

################################################################################
# Evasion shapes.
#
# Everything above this line assumes the value it inspects is a literal. That
# assumption is how most IaC policy suites are quietly defeated: `publicly_accessible
# = var.public` is not `true`, so a rule that tests `== true` passes it, and the
# resource ships public. The HCL2 parser hands us the raw interpolation string
# (`"${var.public}"`), which is neither `true` nor `false`.
#
# The posture below is FAIL CLOSED: if a security-relevant value cannot be
# statically proven safe from the HCL alone, the rule denies and asks for a literal
# or a documented waiver. That is deliberately stricter than most published rule
# sets, and it is the difference between a control and a speed bump.
################################################################################

is_bool(x) if is_boolean(x)

# --- unprovable exposure -------------------------------------------------------

deny contains msg if {
	some kind in {"aws_db_instance", "aws_rds_cluster"}
	some name, body in resources(kind)
	body.publicly_accessible
	not is_bool(body.publicly_accessible)
	msg := sprintf(
		"deny_unprovable_public: %s.%s sets publicly_accessible to %v, which cannot be evaluated from the HCL. `= var.x` is not `= false`. Use a literal, or move the decision behind a module with its own tested policy. [T3/B1 evasion]",
		[kind, name, body.publicly_accessible],
	)
}

deny contains msg if {
	some kind in {"aws_db_instance", "aws_rds_cluster"}
	some name, body in resources(kind)
	body.storage_encrypted
	not is_bool(body.storage_encrypted)
	msg := sprintf(
		"deny_unprovable_encryption: %s.%s sets storage_encrypted to a non-literal (%v). Encryption at rest cannot be enabled in place, so it is not a decision to defer to a variable. [T3/B3 evasion]",
		[kind, name, body.storage_encrypted],
	)
}

# A variable-driven CIDR list arrives as a STRING, not an array, so the
# deny_open_ingress rule above never iterates it. This is the exact shape that
# slips a 0.0.0.0/0 past an otherwise correct rule set.
deny contains msg if {
	some name, body in resources("aws_security_group_rule")
	body.type == "ingress"
	is_string(body.cidr_blocks)
	msg := sprintf(
		"deny_unprovable_ingress_cidr: aws_security_group_rule.%s takes cidr_blocks from %v, so this policy cannot prove it excludes 0.0.0.0/0. Name the source security group, or inline the CIDRs. [T3/B1 evasion]",
		[name, body.cidr_blocks],
	)
}

# `dynamic "ingress"` generates rules at plan time from a value we cannot see.
# Denying it is a real cost to module authors and I would rather pay that than
# ship a rule set with a documented hole in it.
deny contains msg if {
	some name, body in resources("aws_security_group")
	body.dynamic.ingress
	msg := sprintf(
		"deny_dynamic_ingress_block: aws_security_group.%s builds ingress with a `dynamic` block, which cannot be statically analysed. Use explicit aws_security_group_rule resources, or run this module through a plan-JSON gate as well. [T3/B1 evasion]",
		[name],
	)
}

# --- Aurora: the same defects, a different resource type -----------------------
# A rule set that only knows aws_db_instance is one `aws_rds_cluster` away from
# being bypassed, and the migration to Aurora is a normal thing for a bank to do.

deny contains msg if {
	some name, body in resources("aws_rds_cluster")
	missing_or_false(body, "storage_encrypted")
	msg := sprintf("deny_rds_cluster_unencrypted: aws_rds_cluster.%s is unencrypted at rest. [T3/B3]", [name])
}

deny contains msg if {
	some name, body in resources("aws_rds_cluster")
	body.master_password
	msg := sprintf(
		"deny_rds_cluster_inline_password: aws_rds_cluster.%s sets master_password, which lands in Terraform state in plaintext. Use manage_master_user_password. [T3/B2]",
		[name],
	)
}

deny contains msg if {
	some name, body in resources("aws_rds_cluster")
	body.skip_final_snapshot == true
	msg := sprintf("deny_rds_cluster_no_final_snapshot: aws_rds_cluster.%s has skip_final_snapshot=true. [T3/B4]", [name])
}

deny contains msg if {
	some name, body in resources("aws_rds_cluster")
	retention := object.get(body, "backup_retention_period", 0)
	retention < 7
	msg := sprintf(
		"deny_rds_cluster_no_backups: aws_rds_cluster.%s has backup_retention_period=%v (attribute absent counts as 0, minimum 7). [T3/B4]",
		[name, retention],
	)
}
