variable "names" {
  type = list(string)
}

resource "aws_s3_bucket" "b" {
  for_each = toset(var.names)
  bucket   = "store-${each.key}"
}

resource "aws_s3_bucket_public_access_block" "b" {
  for_each                = toset(var.names)
  bucket                  = aws_s3_bucket.b[each.key].id
  block_public_acls       = true
  block_public_policy     = false
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket" "logs" {
  bucket = "store-logs"
}
