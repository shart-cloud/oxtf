resource "aws_s3_bucket" "a" {
  bucket = "bucket-a"
}

resource "aws_s3_bucket" "b" {
  bucket = "bucket-b"
}

resource "aws_s3_bucket_public_access_block" "a" {
  bucket                  = aws_s3_bucket.a.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
