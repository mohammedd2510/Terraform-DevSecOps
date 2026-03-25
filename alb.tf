# ============================================================
# ALB + LISTENER - Intentionally Insecure
# ============================================================
# BOTH tfsec & Checkov detect:
#   - ALB listener using HTTP instead of HTTPS
#   - ALB has no access logging enabled
#   - ALB not dropping invalid headers
#
# CHECKOV additionally detects (relationship-based):
#   - No aws_wafv2_web_acl_association resource linked to ALB
#     (Checkov checks if a WAF ACL is associated - cross-resource)
#   - No HTTPS listener resource with SSL certificate
#     (Checkov checks for a companion aws_lb_listener on 443
#      with an aws_acm_certificate - multi-resource relationship)
#   - ALB not configured with deletion protection
#   - Security group attached to ALB allows all inbound
#     (Checkov traces the SG referenced by ALB and inspects
#      its rules - a cross-resource relationship check)
# ============================================================

resource "aws_lb" "web" {
  name               = "insecure-web-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.web.id]

  enable_deletion_protection = false
  drop_invalid_header_fields = false

  tags = {
    Name = "web-alb"
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
