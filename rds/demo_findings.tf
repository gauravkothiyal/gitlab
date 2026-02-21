# Demo file — intentional policy violations for audit report demonstration.
# This file exists purely to produce scanner findings in CI.
# Remove or replace with real resources before production use.

resource "aws_s3_bucket" "demo_audit" {
  bucket = "demo-audit-bucket-${var.environment}"
  # Missing: versioning, encryption, public access block → Checkov will flag these
}

resource "aws_security_group" "demo_open" {
  name        = "demo-open-sg-${var.environment}"
  description = "Demo SG with open ingress intentional finding"

  ingress {
    # checkov:skip=CKV_AWS_25: intentional demo finding
    description = "Open SSH intentional finding for demo"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
