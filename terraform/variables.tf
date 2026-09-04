variable "vpc_id" {
  type        = string
  description = "VPC hosting the EKS cluster and the database subnet group."
  default     = "vpc-0aa11bb22cc33dd44"
}

variable "eks_node_security_group_id" {
  type        = string
  description = "Security group attached to the EKS node group. The ONLY source permitted to reach 5432."
  default     = "sg-0node11223344556"
}

variable "db_subnet_group_name" {
  type        = string
  description = "Private, no-route-to-IGW subnets."
  default     = "accounts-prod-private"
}

variable "log_archive_account_id" {
  type        = string
  description = "Separate AWS account holding the immutable CloudTrail archive. Deliberately not the prod account: the point of the archive is that a compromised prod principal cannot reach it."
  default     = "444455556666"
}

# NOTE: there is deliberately no `db_password` variable. See rds.tf — the master
# credential is created and rotated by RDS in Secrets Manager, so it never enters
# Terraform state, CI variables, or anyone's shell history. This absence is the fix
# for finding B2 in docs/04-findings.md.
