// The same three resources as policy/fixtures/terraform/bad/main.tf, remediated.
// POSITIVE fixture: `conftest test --parser hcl2 policy/fixtures/terraform/good`
// must report zero failures. Paired with the bad fixture this is the
// "fails before the fix, passes after" evidence for section 4b.

resource "aws_db_instance" "accounts" {
  identifier     = "accounts-prod"
  engine         = "postgres"
  engine_version = "16.4"
  instance_class = "db.r6g.large"

  publicly_accessible    = false
  db_subnet_group_name   = "accounts-prod-private"
  vpc_security_group_ids = [aws_security_group.db.id]

  username                            = "rdsadmin"
  manage_master_user_password         = true
  iam_database_authentication_enabled = true

  storage_encrypted = true
  kms_key_id        = aws_kms_key.rds.arn

  backup_retention_period   = 35
  skip_final_snapshot       = false
  final_snapshot_identifier = "accounts-prod-final"
  deletion_protection       = true
  multi_az                  = true
}

resource "aws_security_group_rule" "db_ingress" {
  type                     = "ingress"
  description              = "PostgreSQL from EKS nodes only"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  source_security_group_id = "sg-0node11223344556"
  security_group_id        = aws_security_group.db.id
}

resource "aws_cloudtrail" "org" {
  name                          = "org-trail"
  s3_bucket_name                = aws_s3_bucket.trail.id
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  include_global_service_events = true
  is_organization_trail         = true
  kms_key_id                    = aws_kms_key.trail.arn
}
