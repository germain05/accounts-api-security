// The Terraform as it is deployed today (section 4b), committed verbatim as a
// NEGATIVE fixture for `conftest test --parser hcl2 policy/fixtures/terraform/bad`.
// Every deny rule in policy/rego/terraform.rego must fire on this file.
//
// Do not "fix" this file. Its job is to fail.

resource "aws_db_instance" "accounts" {
  identifier              = "accounts-prod"
  engine                  = "postgres"
  instance_class          = "db.r6g.large"
  username                = "postgres"
  password                = var.db_password
  publicly_accessible     = true
  storage_encrypted       = false
  skip_final_snapshot     = true
  backup_retention_period = 0
}

resource "aws_security_group_rule" "db_ingress" {
  type              = "ingress"
  from_port         = 5432
  to_port           = 5432
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.db.id
}

resource "aws_cloudtrail" "org" {
  name                          = "org-trail"
  s3_bucket_name                = aws_s3_bucket.trail.id
  is_multi_region_trail         = false
  enable_log_file_validation    = false
  include_global_service_events = false
}
