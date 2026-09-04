# Unit tests for policy/rego/terraform.rego.  `conftest verify --policy policy/rego`
#
# Each rule gets a pair: the production-today value must be denied, the
# remediated value must not be. That pairing is the "fails before the fix, passes
# after" requirement — a rule that only has a failing fixture might be denying
# everything, which is the most common way a policy suite becomes a rubber stamp.

package main

import future.keywords.every
import future.keywords.if
import future.keywords.in

# --------------------------------------------------------------- fixtures

bad_rds := {"resource": {"aws_db_instance": {"accounts": {
	"identifier": "accounts-prod",
	"engine": "postgres",
	"username": "postgres",
	"password": "${var.db_password}",
	"publicly_accessible": true,
	"storage_encrypted": false,
	"skip_final_snapshot": true,
	"backup_retention_period": 0,
}}}}

good_rds := {"resource": {"aws_db_instance": {"accounts": {
	"identifier": "accounts-prod",
	"engine": "postgres",
	"username": "rdsadmin",
	"manage_master_user_password": true,
	"iam_database_authentication_enabled": true,
	"publicly_accessible": false,
	"storage_encrypted": true,
	"kms_key_id": "${aws_kms_key.rds.arn}",
	"skip_final_snapshot": false,
	"final_snapshot_identifier": "accounts-prod-final",
	"backup_retention_period": 35,
	"deletion_protection": true,
	"multi_az": true,
}}}}

bad_sg := {"resource": {"aws_security_group_rule": {"db_ingress": {
	"type": "ingress",
	"from_port": 5432,
	"to_port": 5432,
	"protocol": "tcp",
	"cidr_blocks": ["0.0.0.0/0"],
}}}}

good_sg := {"resource": {"aws_security_group_rule": {"db_ingress": {
	"type": "ingress",
	"from_port": 5432,
	"to_port": 5432,
	"protocol": "tcp",
	"source_security_group_id": "sg-0node11223344556",
}}}}

bad_trail := {"resource": {"aws_cloudtrail": {"org": {
	"name": "org-trail",
	"is_multi_region_trail": false,
	"enable_log_file_validation": false,
	"include_global_service_events": false,
}}}}

good_trail := {"resource": {"aws_cloudtrail": {"org": {
	"name": "org-trail",
	"is_multi_region_trail": true,
	"enable_log_file_validation": true,
	"include_global_service_events": true,
	"is_organization_trail": true,
	"kms_key_id": "${aws_kms_key.trail.arn}",
}}}}

# ----------------------------------------------------------------- B1

test_denies_public_rds if {
	some m in deny with input as bad_rds
	contains(m, "deny_rds_publicly_accessible")
}

test_allows_private_rds if {
	not_denied_by(good_rds, "deny_rds_publicly_accessible")
}

test_denies_world_open_ingress if {
	some m in deny with input as bad_sg
	contains(m, "deny_open_ingress")
}

test_allows_sg_sourced_ingress if {
	count(deny) == 0 with input as good_sg
}

# ----------------------------------------------------------------- B2

test_denies_inline_password if {
	some m in deny with input as bad_rds
	contains(m, "deny_rds_inline_password")
}

test_allows_rds_managed_password if {
	not_denied_by(good_rds, "deny_rds_inline_password")
}

# ----------------------------------------------------------------- B3

test_denies_unencrypted_storage if {
	some m in deny with input as bad_rds
	contains(m, "deny_rds_unencrypted")
}

# Omission, not a wrong value: the attribute is simply absent.
test_denies_omitted_storage_encrypted if {
	some m in deny with input as {"resource": {"aws_db_instance": {"x": {"engine": "postgres"}}}}
	contains(m, "deny_rds_unencrypted")
}

test_denies_aws_managed_key if {
	some m in deny with input as {"resource": {"aws_db_instance": {"x": {
		"storage_encrypted": true,
		"backup_retention_period": 35,
		"deletion_protection": true,
	}}}}
	contains(m, "deny_rds_aws_managed_key")
}

test_allows_cmk_encrypted if {
	not_denied_by(good_rds, "deny_rds_unencrypted")
	not_denied_by(good_rds, "deny_rds_aws_managed_key")
}

# ----------------------------------------------------------------- B4

test_denies_zero_backup_retention if {
	some m in deny with input as bad_rds
	contains(m, "deny_rds_no_backups")
}

test_denies_skip_final_snapshot if {
	some m in deny with input as bad_rds
	contains(m, "deny_rds_no_final_snapshot")
}

test_denies_missing_deletion_protection if {
	some m in deny with input as bad_rds
	contains(m, "deny_rds_no_deletion_protection")
}

test_good_rds_is_clean if {
	count(deny) == 0 with input as good_rds
}

# ----------------------------------------------------------------- B5

test_denies_trail_without_global_events if {
	some m in deny with input as bad_trail
	contains(m, "deny_cloudtrail_no_global_events")
}

test_denies_single_region_trail if {
	some m in deny with input as bad_trail
	contains(m, "deny_cloudtrail_single_region")
}

test_denies_trail_without_validation if {
	some m in deny with input as bad_trail
	contains(m, "deny_cloudtrail_no_validation")
}

test_good_trail_is_clean if {
	count(deny) == 0 with input as good_trail
}

# ----------------------------------------------------------------- T4 / KMS

test_denies_mutable_ecr_tags if {
	some m in deny with input as {"resource": {"aws_ecr_repository": {"api": {
		"name": "accounts-api",
		"image_tag_mutability": "MUTABLE",
	}}}}
	contains(m, "deny_ecr_mutable_tags")
}

test_allows_immutable_ecr_tags if {
	count(deny) == 0 with input as {"resource": {"aws_ecr_repository": {"api": {
		"name": "accounts-api",
		"image_tag_mutability": "IMMUTABLE",
	}}}}
}

test_denies_kms_without_rotation if {
	some m in deny with input as {"resource": {"aws_kms_key": {"k": {"description": "x"}}}}
	contains(m, "deny_kms_no_rotation")
}

test_denies_multi_region_kms_for_residency if {
	some m in deny with input as {"resource": {"aws_kms_key": {"k": {
		"enable_key_rotation": true,
		"multi_region": true,
	}}}}
	contains(m, "deny_kms_multi_region")
}

# ----------------------------------------------------------------- warn tier

test_single_az_warns_but_does_not_deny if {
	some m in warn with input as {"resource": {"aws_db_instance": {"x": {
		"storage_encrypted": true,
		"kms_key_id": "arn:x",
		"backup_retention_period": 35,
		"deletion_protection": true,
	}}}}
	contains(m, "warn_rds_single_az")
	count(deny) == 0 with input as {"resource": {"aws_db_instance": {"x": {
		"storage_encrypted": true,
		"kms_key_id": "arn:x",
		"backup_retention_period": 35,
		"deletion_protection": true,
	}}}}
}

# ----------------------------------------------------------------- helper

not_denied_by(doc, rule_name) if {
	msgs := deny with input as doc
	every m in msgs {
		not contains(m, rule_name)
	}
}
