// EVASION FIXTURE. Every resource below satisfies the letter of a naive rule set
// while shipping the same exposure as policy/fixtures/terraform/bad/main.tf.
//
//   publicly_accessible = var.public      -> parses as the string "${var.public}",
//                                            which is not `true`, so `== true` passes it
//   cidr_blocks         = var.allowed     -> parses as a STRING, not a list, so a rule
//                                            that iterates the list never runs
//   dynamic "ingress"                     -> the rules are generated at plan time and
//                                            are invisible to a static parser
//   ::/0                                  -> IPv6 equivalent of 0.0.0.0/0
//   aws_rds_cluster                       -> Aurora: same defects, different resource type,
//                                            and a normal migration for a bank to make
//
// This is the fixture that separates a rule set from a speed bump.
// run-policy-tests.sh asserts conftest REJECTS this file. Do not "fix" it.

variable "public" { type = bool }
variable "allowed_cidrs" { type = list(string) }

resource "aws_db_instance" "sneaky" {
  identifier              = "accounts-prod-2"
  engine                  = "postgres"
  publicly_accessible     = var.public
  storage_encrypted       = true
  kms_key_id              = aws_kms_key.rds.arn
  backup_retention_period = 35
  deletion_protection     = true
  multi_az                = true
}

resource "aws_security_group" "dyn" {
  name = "dyn"
  dynamic "ingress" {
    for_each = var.allowed_cidrs
    content {
      from_port   = 5432
      to_port     = 5432
      protocol    = "tcp"
      cidr_blocks = [ingress.value]
    }
  }
}

resource "aws_security_group_rule" "var_cidr" {
  type              = "ingress"
  from_port         = 5432
  to_port           = 5432
  protocol          = "tcp"
  cidr_blocks       = var.allowed_cidrs
  security_group_id = aws_security_group.dyn.id
}

resource "aws_security_group_rule" "v6" {
  type        = "ingress"
  from_port   = 5432
  to_port     = 5432
  protocol    = "tcp"
  cidr_blocks = ["::/0"]
  security_group_id = aws_security_group.dyn.id
}

resource "aws_rds_cluster" "aurora" {
  cluster_identifier  = "accounts-aurora"
  engine              = "aurora-postgresql"
  master_username     = "root"
  master_password     = var.db_password
  storage_encrypted   = false
  skip_final_snapshot = true
}
