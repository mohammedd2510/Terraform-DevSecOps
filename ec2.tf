# ============================================================
# SECURITY GROUP + EC2 - Intentionally Insecure
# ============================================================
# BOTH tfsec & Checkov detect:
#   - Ingress open to 0.0.0.0/0 on port 22 (SSH)
#   - Egress open to 0.0.0.0/0 (unrestricted outbound)
#   - No description on security group rule
#
# CHECKOV additionally detects (relationship-based):
#   - EC2 instance has no IAM instance profile attached
#     (checks that aws_instance references an iam_instance_profile)
#   - EC2 instance not launched inside a VPC subnet
#     (checks that aws_instance has a subnet_id)
#   - EC2 instance has no metadata service v2 (IMDSv2) enforced
#     (checks for metadata_options block with http_tokens = required)
#   - EC2 uses default security group rather than a purpose-built one
#     (Checkov cross-checks SG attachment patterns)
#   - EBS root volume not encrypted
#     (checks root_block_device.encrypted = true)
# ============================================================

resource "aws_security_group" "web" {
  name = "web-sg"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "web" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.micro"

  vpc_security_group_ids = [aws_security_group.web.id]

  # No iam_instance_profile    -> Checkov CKV_AWS_79
  # No subnet_id               -> Checkov CKV2_AWS_41
  # No metadata_options block   -> Checkov CKV_AWS_79 (IMDSv2)
  # No root_block_device encrypt -> Checkov CKV_AWS_8

  tags = {
    Name = "web-server"
  }
}
