# ╔══════════════════════════════════════════════════════════════════════╗
# ║  INTENTIONALLY NON-COMPLIANT TERRAFORM                              ║
# ║  This file contains one deliberate violation per policy category.   ║
# ║  It exists solely to demonstrate the gatekeeper blocking bad infra. ║
# ║  DO NOT apply this to any real AWS account.                         ║
# ╚══════════════════════════════════════════════════════════════════════╝

# ──────────────────────────────────────────────
# VIOLATION 1: S3 — Public ACL
# Policy:      policies/s3.rego → deny (public-read ACL)
# ──────────────────────────────────────────────

resource "aws_s3_bucket" "public_bucket" {
  bucket = "demo-gatekeeper-public-bucket"

  tags = {
    Environment = "demo"
    Project     = "policy-gatekeeper"
  }
}

resource "aws_s3_bucket_acl" "public_bucket_acl" {
  bucket = aws_s3_bucket.public_bucket.id
  acl    = "public-read" # ← VIOLATION: public-read ACL
}

# VIOLATION 1b: S3 — Public access block disabled
# Policy:       policies/s3.rego → deny (block flags false)

resource "aws_s3_bucket_public_access_block" "disabled" {
  bucket = aws_s3_bucket.public_bucket.id

  block_public_acls       = false # ← VIOLATION
  block_public_policy     = false # ← VIOLATION
  ignore_public_acls      = false # ← VIOLATION
  restrict_public_buckets = false # ← VIOLATION
}

# VIOLATION 1c: S3 — Versioning not enabled
# Policy:       policies/s3.rego → warn (versioning disabled)

resource "aws_s3_bucket_versioning" "disabled" {
  bucket = aws_s3_bucket.public_bucket.id

  versioning_configuration {
    status = "Suspended" # ← VIOLATION (warn)
  }
}

# ──────────────────────────────────────────────
# VIOLATION 2: Security Group — SSH open to world
# Policy:      policies/security_groups.rego → deny (0.0.0.0/0 on port 22)
# ──────────────────────────────────────────────

resource "aws_security_group" "open_ssh" {
  name        = "demo-open-ssh"
  description = "INTENTIONALLY INSECURE - SSH open to world for demo"

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # ← VIOLATION: SSH from the entire internet
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Environment = "demo"
    Project     = "policy-gatekeeper"
  }
}

# ──────────────────────────────────────────────
# VIOLATION 3: Tagging — Missing required tags
# Policy:      policies/tagging.rego → deny (no Environment, no Project)
# ──────────────────────────────────────────────

resource "aws_s3_bucket" "untagged_bucket" {
  bucket = "demo-gatekeeper-untagged-bucket"
  # ← VIOLATION: No tags block at all — missing Environment and Project
}

# ──────────────────────────────────────────────
# VIOLATION 4: EC2 Sizing — Oversized instance
# Policy:      policies/ec2_sizing.rego → deny (not in allow-list)
# ──────────────────────────────────────────────

resource "aws_instance" "oversized" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "m5.24xlarge" # ← VIOLATION: way outside the allow-list

  tags = {
    Environment = "demo"
    Project     = "policy-gatekeeper"
  }
}

# ──────────────────────────────────────────────
# VIOLATION 5: Encryption — Unencrypted EBS volume
# Policy:      policies/encryption.rego → deny (encrypted = false)
# ──────────────────────────────────────────────

resource "aws_ebs_volume" "unencrypted" {
  availability_zone = "ap-south-1a"
  size              = 20
  encrypted         = false # ← VIOLATION: no encryption

  tags = {
    Environment = "demo"
    Project     = "policy-gatekeeper"
  }
}

# ──────────────────────────────────────────────
# VIOLATION 5b: Encryption — Unencrypted RDS instance
# Policy:       policies/encryption.rego → deny (storage_encrypted = false)
# ──────────────────────────────────────────────

resource "aws_db_instance" "unencrypted" {
  allocated_storage   = 20
  engine              = "mysql"
  engine_version      = "8.0"
  instance_class      = "db.t3.micro"
  db_name             = "demodb"
  username            = "admin"
  password            = "CHANGE_ME_this_is_a_demo"
  skip_final_snapshot = true

  storage_encrypted = false # ← VIOLATION: no encryption

  tags = {
    Environment = "demo"
    Project     = "policy-gatekeeper"
  }
}

# ──────────────────────────────────────────────
# VIOLATION 6: IAM — Wildcard admin policy
# Policy:      policies/iam.rego → deny (Action: *, Resource: *)
# ──────────────────────────────────────────────

resource "aws_iam_policy" "admin_wildcard" {
  name        = "demo-admin-wildcard"
  description = "INTENTIONALLY OVERPERMISSIVE - for demo only"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"       # ← VIOLATION: wildcard action
        Resource = "*"       # ← VIOLATION: wildcard resource
      }
    ]
  })

  tags = {
    Environment = "demo"
    Project     = "policy-gatekeeper"
  }
}
