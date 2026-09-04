// Section 4b, finding B1. Threat T3.

resource "aws_security_group" "db" {
  name        = "accounts-prod-db"
  description = "accounts-api PostgreSQL. Ingress from the EKS node group only."
  vpc_id      = var.vpc_id
}

// The whole fix in one resource: source_security_group_id, not cidr_blocks.
// A CIDR is a statement about the network; a security group id is a statement
// about identity, and it stays correct when the subnets are renumbered.
resource "aws_security_group_rule" "db_ingress" {
  type                     = "ingress"
  description              = "PostgreSQL from EKS nodes running ns/accounts"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  source_security_group_id = var.eks_node_security_group_id
  security_group_id        = aws_security_group.db.id
}

// Explicit and narrow. An unqualified egress rule on a database SG is a
// data-exfiltration path that nobody looks at because it is on the "outbound" side.
resource "aws_security_group_rule" "db_egress_none" {
  type              = "egress"
  description       = "No outbound. RDS does not initiate connections."
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["127.0.0.1/32"]
  security_group_id = aws_security_group.db.id
}
