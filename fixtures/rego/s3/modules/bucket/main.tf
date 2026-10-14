resource "aws_s3_bucket" "b" { bucket = "c" }
resource "aws_s3_bucket_public_access_block" "good" {
  bucket = aws_s3_bucket.b.id
  block_public_acls = true
  block_public_policy = true
  ignore_public_acls = true
  restrict_public_buckets = true
}
