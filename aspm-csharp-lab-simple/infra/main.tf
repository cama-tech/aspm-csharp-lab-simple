terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# LAB-IAC-001: intentionally public bucket configuration for Checkov testing.
# Do not apply this Terraform configuration.
resource "aws_s3_bucket" "aspm_lab" {
  bucket = "aspm-lab-never-deploy-example"
}

resource "aws_s3_bucket_public_access_block" "aspm_lab" {
  bucket                  = aws_s3_bucket.aspm_lab.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# LAB-IAC-CRITICAL-001: database port exposed to the Internet.
resource "aws_security_group" "database" {
  name = "aspm-lab-database"

  ingress {
    description = "LAB ONLY - intentionally public database port"
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Encrypted control resource: AES256 is enabled. This is not an expected finding.
resource "aws_s3_bucket_server_side_encryption_configuration" "aspm_lab" {
  bucket = aws_s3_bucket.aspm_lab.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# LAB-IAC-MEDIUM-001: flow logging is intentionally absent from the VPC.
resource "aws_vpc" "lab" {
  cidr_block           = "10.90.0.0/16"
  enable_dns_hostnames = true
}

# LAB-IAC-LOW-001: unrestricted egress for scanner classification testing.
resource "aws_security_group_rule" "all_egress" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.database.id
}
