variable "name" {
  type = string
}

resource "aws_s3_bucket" "named" {
  bucket = var.name
}

resource "aws_s3_bucket_public_access_block" "named" {
  bucket                  = "fixed-name"
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
