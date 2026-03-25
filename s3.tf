# ============================================================
# S3 BUCKET - Intentionally Insecure
# ============================================================
# BOTH tfsec & Checkov detect:
#   - No server-side encryption (aws_s3_bucket without SSE)
#   - No versioning enabled
#   - No public access block
#
# CHECKOV additionally detects (relationship-based):
#   - No S3 bucket logging configured (needs a SEPARATE
#     aws_s3_bucket_logging resource pointing to a log bucket)
#   - No lifecycle configuration resource attached
#   - No bucket policy resource restricting SSL-only access
#   - No replication configuration for cross-region DR
# ============================================================

resource "aws_s3_bucket" "data" {
  bucket = "my-insecure-data-bucket"

  tags = {
    Name = "data-bucket"
  }
}
