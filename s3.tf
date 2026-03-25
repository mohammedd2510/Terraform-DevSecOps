# ============================================================
# S3 BUCKET - Intentionally Insecure
# ============================================================
#
# tfsec detects:
#   - aws-s3-block-public-acls           (HIGH)   No public access block - not blocking public ACLs
#   - aws-s3-block-public-policy         (HIGH)   No public access block - not blocking public policies
#   - aws-s3-enable-bucket-encryption    (HIGH)   Bucket does not have encryption enabled
#   - aws-s3-ignore-public-acls          (HIGH)   No public access block - not ignoring public ACLs
#   - aws-s3-no-public-buckets           (HIGH)   No public access block - not restricting public buckets
#   - aws-s3-encryption-customer-key     (HIGH)   Bucket not encrypted with customer managed KMS key
#   - aws-s3-enable-bucket-logging       (MEDIUM) Bucket does not have logging enabled
#   - aws-s3-enable-versioning           (MEDIUM) Bucket does not have versioning enabled
#   - aws-s3-specify-public-access-block (LOW)    No corresponding public access block resource
#
# Checkov detects (overlapping with tfsec):
#   - CKV_AWS_145  S3 bucket not encrypted with KMS by default
#   - CKV_AWS_18   S3 bucket has no access logging enabled
#   - CKV_AWS_21   S3 bucket has no versioning enabled
#
# Checkov-only (cross-resource relationship checks):
#   - CKV2_AWS_6   Checks for a separate aws_s3_bucket_public_access_block resource
#   - CKV2_AWS_62  Checks for a separate aws_s3_bucket_notification resource
#   - CKV2_AWS_61  Checks for a separate aws_s3_bucket_lifecycle_configuration resource
#   - CKV_AWS_144  Checks for a separate aws_s3_bucket_replication_configuration resource
# ============================================================

resource "aws_s3_bucket" "data" {
  bucket = "my-insecure-data-bucket"

  tags = {
    Name = "data-bucket"
  }
}
