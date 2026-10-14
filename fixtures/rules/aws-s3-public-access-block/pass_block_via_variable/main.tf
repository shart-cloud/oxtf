variable "block_public" {
  type    = bool
  default = true
}

resource "aws_s3_bucket" "data" {
  bucket = "my-data"
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = var.block_public
  block_public_policy     = var.block_public
  ignore_public_acls      = var.block_public
  restrict_public_buckets = var.block_public
}
