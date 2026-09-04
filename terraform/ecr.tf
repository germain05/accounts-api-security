// Threat T4 — artefact integrity. Backs the claims in docs/02-build-integrity.md.

resource "aws_ecr_repository" "accounts_api" {
  name = "accounts-api"

  // The load-bearing line for "immutable tags". ECR rejects a second push to an
  // existing tag at the registry, which is the only layer an attacker with
  // registry credentials cannot argue with. The pipeline check and the Kyverno
  // digest policy are defence in depth around this one setting.
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.ecr.arn
  }
}

resource "aws_kms_key" "ecr" {
  description             = "accounts-api ECR layer encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  multi_region            = false
}

// Push is limited to the one GitHub Actions role. Pull is limited to the prod
// account. Separating these means compromising the build account does not give
// you the ability to serve images to anyone else's cluster.
resource "aws_ecr_repository_policy" "accounts_api" {
  repository = aws_ecr_repository.accounts_api.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PushFromGitHubActionsOnly"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::210987654321:role/gha-accounts-api-ecr-push" }
        Action = [
          "ecr:PutImage",
          "ecr:InitiateLayerUpload",
          "ecr:UploadLayerPart",
          "ecr:CompleteLayerUpload",
          "ecr:BatchCheckLayerAvailability",
          "ecr:DescribeImages"
        ]
      },
      {
        Sid       = "PullFromProdClusterOnly"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::123456789012:root" }
        Action = [
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "ecr:BatchCheckLayerAvailability"
        ]
      },
      {
        // Even the push role may not remove an image. Deleting a digest is how
        // you break the audit trail between "what we scanned" and "what ran".
        Sid       = "NobodyDeletesImages"
        Effect    = "Deny"
        Principal = "*"
        Action    = ["ecr:BatchDeleteImage", "ecr:DeleteRepository", "ecr:DeleteRepositoryPolicy"]
      }
    ]
  })
}

// Retention, not deletion-on-demand: expiry is a scheduled, auditable policy
// rather than an API call an attacker can make.
resource "aws_ecr_lifecycle_policy" "accounts_api" {
  repository = aws_ecr_repository.accounts_api.name

  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Keep the last 200 images; prod rollback window plus audit."
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = 200
      }
      action = { type = "expire" }
    }]
  })
}
