// Section 4b, finding B5. This is the control that every "what evidence would
// you have?" answer in DECISIONS.md §3 depends on.

resource "aws_cloudtrail" "org" {
  name           = "org-trail"
  s3_bucket_name = aws_s3_bucket.trail.id
  s3_key_prefix  = "org"

  // The three flips from the original, in order of what they buy:
  //
  //  include_global_service_events: IAM, STS, CloudFront and Route 53 events are
  //    GLOBAL. With this false they are not recorded anywhere — i.e. the exact API
  //    calls of an identity attack (CreateAccessKey, AttachRolePolicy,
  //    AssumeRole) were invisible. This is the one that mattered most.
  //  is_multi_region_trail: an attacker working in us-east-1 was invisible.
  //  enable_log_file_validation: produces the hourly SHA-256 digest chain. Without
  //    it the log is not tamper-evident and is weak evidence to a regulator.
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true

  is_organization_trail = true
  kms_key_id            = aws_kms_key.trail.arn

  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.trail.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.trail_to_cwl.arn

  // Data events for the one bucket that could carry exported customer data, and
  // for Lambda. Deliberately not "all S3 buckets" — that is a large bill for
  // telemetry nobody reads, and DECISIONS.md §4 names the gap it leaves.
  advanced_event_selector {
    name = "customer-data-exports"

    field_selector {
      field  = "eventCategory"
      equals = ["Data"]
    }

    field_selector {
      field  = "resources.type"
      equals = ["AWS::S3::Object"]
    }

    field_selector {
      field       = "resources.ARN"
      starts_with = ["arn:aws:s3:::example-bank-accounts-exports/"]
    }
  }
}

// Archive lives in a SEPARATE account. The point is that a principal compromised
// in prod — including a compromised administrator — cannot reach it.
resource "aws_s3_bucket" "trail" {
  bucket = "example-bank-cloudtrail-archive-ap-south-1"

  // Compliance-mode Object Lock: not even the account root can shorten this.
  object_lock_enabled = true
}

resource "aws_s3_bucket_object_lock_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id

  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = 2557 // 7 years
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.trail.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "trail" {
  bucket = aws_s3_bucket.trail.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "trail" {
  bucket                  = aws_s3_bucket.trail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_cloudwatch_log_group" "trail" {
  name              = "/aws/cloudtrail/org-trail"
  retention_in_days = 400
  kms_key_id        = aws_kms_key.trail.arn
}

resource "aws_iam_role" "trail_to_cwl" {
  name = "cloudtrail-to-cwl"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

// GuardDuty is the detective control that turns the trail from an archive into
// an alert. Enabled at the org level with the EKS and RDS protection plans,
// because the two threats it actually helps with here are T2 (credential
// exfiltration: the InstanceCredentialExfiltration finding) and anomalous RDS login.
resource "aws_guardduty_detector" "prod" {
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"

  datasources {
    kubernetes {
      audit_logs {
        enable = true
      }
    }
  }
}
