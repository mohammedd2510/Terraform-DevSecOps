# ============================================================
# SECURITY GROUP + EC2 - Intentionally Insecure
# ============================================================
#
# tfsec detects:
#   - aws-ec2-no-public-ingress-sgr             (CRITICAL) Ingress open to 0.0.0.0/0 on port 22
#   - aws-ec2-no-public-ingress-sgr             (CRITICAL) Ingress open to 0.0.0.0/0 on port 443
#   - aws-ec2-no-public-egress-sgr              (CRITICAL) Egress open to 0.0.0.0/0
#   - aws-ec2-enforce-http-token-imds           (HIGH)     Instance does not require IMDSv2 token
#   - aws-ec2-enable-at-rest-encryption         (HIGH)     Root block device is not encrypted
#   - aws-ec2-add-description-to-security-group (LOW)      Security group uses default description
#   - aws-ec2-add-description-to-security-group-rule (LOW) Security group rules have no description (x3)
#
# Checkov detects (overlapping with tfsec):
#   - CKV_AWS_24   No security groups allow ingress from 0.0.0.0/0 to port 22
#   - CKV_AWS_382  No security groups allow egress from 0.0.0.0/0 to port -1
#   - CKV_AWS_23   Every security group and rule has a description
#   - CKV_AWS_79   Instance Metadata Service Version 1 is not enabled (IMDSv2)
#   - CKV_AWS_8    EBS data is securely encrypted
#
# Checkov-only (cross-resource and deeper attribute checks):
#   - CKV2_AWS_41  Checks that an IAM role is attached to EC2 instance
#                  (looks for iam_instance_profile linking to aws_iam_instance_profile)
#   - CKV_AWS_135  Checks that EC2 is EBS optimized (ebs_optimized = true)
#   - CKV_AWS_126  Checks that detailed monitoring is enabled (monitoring = true)
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
  ami           = "ami-02dfbd4ff395f2a1b"
  instance_type = "t3.micro"

  vpc_security_group_ids = [aws_security_group.web.id]

  tags = {
    Name = "web-server"
  }
}
