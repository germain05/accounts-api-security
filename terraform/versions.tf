terraform {
  required_version = ">= 1.9.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.80"
    }
  }

  # State holds the plan, not the credentials — see rds.tf: the DB password is
  # managed by RDS in Secrets Manager, so it is never in this file.
  backend "s3" {
    bucket       = "example-bank-tfstate-ap-south-1"
    key          = "accounts-api/prod/terraform.tfstate"
    region       = "ap-south-1"
    encrypt      = true
    kms_key_id   = "arn:aws:kms:ap-south-1:123456789012:key/tfstate"
    use_lockfile = true
  }
}

provider "aws" {
  region = "ap-south-1" # RBI localisation: this stack does not exist elsewhere

  default_tags {
    tags = {
      Service            = "accounts-api"
      Environment        = "production"
      DataClassification = "pii-and-cardholder-adjacent"
      Owner              = "retail-banking-platform"
      ThreatModel        = "THREAT-MODEL.md"
    }
  }
}
