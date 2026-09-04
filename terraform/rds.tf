// Section 4b, findings B1–B4. Threat T3.
// Diff against policy/fixtures/terraform/bad/main.tf.

resource "aws_db_instance" "accounts" {
  identifier     = "accounts-prod"
  engine         = "postgres"
  engine_version = "16.4"
  instance_class = "db.r6g.large"

  // B1: no public endpoint, private subnets only. Combined with the security
  // group in security_groups.tf, the only route to 5432 is from the EKS nodes.
  publicly_accessible    = false
  db_subnet_group_name   = var.db_subnet_group_name
  vpc_security_group_ids = [aws_security_group.db.id]

  // B2: no `password` argument anywhere. RDS creates and owns the master
  // credential in Secrets Manager, so it never appears in Terraform state.
  // The application does not use this credential at all — it authenticates with
  // IAM tokens (below) and reads a separate, application-scoped secret.
  username                            = "rdsadmin"
  manage_master_user_password         = true
  master_user_secret_kms_key_id       = aws_kms_key.secrets.arn
  iam_database_authentication_enabled = true

  // B3: encrypted at rest with a customer-managed key. Cannot be enabled in
  // place later, which is why it is not something to defer.
  storage_encrypted = true
  kms_key_id        = aws_kms_key.rds.arn
  storage_type      = "gp3"
  allocated_storage = 200

  // B4: recoverable. 35 days is the RDS maximum for automated backups and lines
  // up with the incident-discovery window we assume in DECISIONS.md §3.
  backup_retention_period   = 35
  backup_window             = "18:30-19:30" // 00:00 IST
  copy_tags_to_snapshot     = true
  delete_automated_backups  = false
  skip_final_snapshot       = false
  final_snapshot_identifier = "accounts-prod-final"
  deletion_protection       = true

  // Evidence and hygiene
  performance_insights_enabled          = true
  performance_insights_kms_key_id       = aws_kms_key.rds.arn
  performance_insights_retention_period = 731
  monitoring_interval                   = 30
  monitoring_role_arn                   = aws_iam_role.rds_monitoring.arn
  enabled_cloudwatch_logs_exports       = ["postgresql", "upgrade"]

  auto_minor_version_upgrade = true
  maintenance_window         = "sun:19:30-sun:20:30"
  ca_cert_identifier         = "rds-ca-rsa2048-g1"
  multi_az                   = true
  parameter_group_name       = aws_db_parameter_group.accounts.name
  apply_immediately          = false
}

// Forces TLS on every client connection. Without rds.force_ssl the application
// can be talked out of TLS by a network-position attacker, and the encryption
// in transit claim in docs/06 would be aspirational.
resource "aws_db_parameter_group" "accounts" {
  name   = "accounts-prod-pg16"
  family = "postgres16"

  parameter {
    name         = "rds.force_ssl"
    value        = "1"
    apply_method = "pending-reboot"
  }

  parameter {
    name  = "log_statement"
    value = "ddl" // never `all`: statement logs would carry IBANs into CloudWatch
  }
}

resource "aws_iam_role" "rds_monitoring" {
  name = "accounts-prod-rds-monitoring"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "monitoring.rds.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "rds_monitoring" {
  role       = aws_iam_role.rds_monitoring.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}
