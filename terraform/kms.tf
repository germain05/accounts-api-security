// Key custody. See docs/06-secrets-rotation.md for the one-line statement of what
// this actually defends against — and what it does not.
//
// Traceability note: these keys do NOT map to a named threat in THREAT-MODEL.md.
// They are here because key custody is a regulatory obligation (RBI / PCI DSS 3.5
// / DPDP Act) rather than because they mitigate a threat in my top five. Stated as
// such rather than retrofitted to a threat — see TRACEABILITY.md.

resource "aws_kms_key" "rds" {
  description             = "accounts-api RDS storage + performance insights"
  enable_key_rotation     = true // annual automatic rotation of the backing key
  deletion_window_in_days = 30
  multi_region            = false // residency: the key material does not leave ap-south-1
}

resource "aws_kms_alias" "rds" {
  name          = "alias/accounts-api-rds"
  target_key_id = aws_kms_key.rds.key_id
}

resource "aws_kms_key" "secrets" {
  description             = "accounts-api Secrets Manager envelope key"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  multi_region            = false

  // The grant that matters: only the pod role may decrypt, only via Secrets
  // Manager, only for this secret's encryption context. A stolen kms:Decrypt
  // permission is useless against ciphertext from any other source.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AccountRootForBreakGlassAdministration"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::123456789012:root" }
        Action    = ["kms:Describe*", "kms:Get*", "kms:List*", "kms:PutKeyPolicy"]
        Resource  = "*"
      },
      {
        Sid       = "PodRoleDecryptViaSecretsManagerOnly"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::123456789012:role/accounts-api-pod" }
        Action    = "kms:Decrypt"
        Resource  = "*"
        Condition = {
          StringEquals = {
            "kms:ViaService" = "secretsmanager.ap-south-1.amazonaws.com"
          }
        }
      },
      {
        Sid       = "RotationLambdaEncryptDecrypt"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::123456789012:role/accounts-api-secret-rotation" }
        Action    = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource  = "*"
      }
    ]
  })
}

resource "aws_kms_alias" "secrets" {
  name          = "alias/accounts-api-secrets"
  target_key_id = aws_kms_key.secrets.key_id
}

resource "aws_kms_key" "trail" {
  description             = "CloudTrail archive + log group"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  multi_region            = false
}

resource "aws_kms_alias" "trail" {
  name          = "alias/cloudtrail-archive"
  target_key_id = aws_kms_key.trail.key_id
}
