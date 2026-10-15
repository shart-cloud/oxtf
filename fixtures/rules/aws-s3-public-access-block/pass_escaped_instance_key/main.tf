# Instance keys that need escaping in an address. Both front ends must spell
# the key the way Terraform does: aws_s3_bucket.b["quote\"back\\slash"].
resource "aws_s3_bucket" "b" {
  for_each = toset(["quote\"back\\slash", "plain"])
  bucket   = "bucket-${each.key}"
}

resource "aws_s3_bucket_public_access_block" "p" {
  for_each                = toset(["quote\"back\\slash", "plain"])
  bucket                  = aws_s3_bucket.b[each.key].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
