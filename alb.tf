# ============================================================
# ALB + LISTENER - Intentionally Insecure
# ============================================================
#
# tfsec detects:
#   - aws-elb-http-not-used       (CRITICAL) Listener uses HTTP instead of HTTPS
#   - aws-elb-alb-not-public      (HIGH)     Load balancer is exposed publicly
#   - aws-elb-drop-invalid-headers (HIGH)     ALB not set to drop invalid headers
#
# Checkov detects (overlapping with tfsec):
#   - CKV_AWS_2    ALB protocol is HTTPS
#   - CKV_AWS_131  ALB drops HTTP headers
#   - CKV_AWS_91   ELBv2 has access logging enabled
#   - CKV_AWS_150  Load Balancer has deletion protection enabled
#
# Checkov-only (cross-resource relationship checks):
#   - CKV2_AWS_28  Checks for a separate aws_wafv2_web_acl_association resource
#                  linked to the ALB (public ALB protected by WAF)
#   - CKV2_AWS_20  Checks for a separate aws_lb_listener on port 443
#                  that redirects HTTP to HTTPS (cross-listener relationship)
#   - CKV_AWS_103  Checks that load balancer listener is using TLS 1.2
# ============================================================

resource "aws_lb" "web" {
  name               = "insecure-web-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.web.id]
  subnets            = data.aws_subnets.default.ids

  enable_deletion_protection = false
  drop_invalid_header_fields = false

  tags = {
    Name = "web-alb"
  }
}

data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.web.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "fixed-response"

    fixed_response {
      content_type = "text/plain"
      message_body = "OK"
      status_code  = "200"
    }
  }
}
