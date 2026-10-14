variable "exists" { type = bool }
resource "aws_s3_bucket" "b" {
  for_each = toset(["a", "b", "c"])
  bucket = each.key
}
resource "aws_s3_bucket_public_access_block" "conditional" {
  count = var.exists ? 1 : 0
  bucket = aws_s3_bucket.b["a"].id
  block_public_acls = true
  block_public_policy = true
  ignore_public_acls = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_public_access_block" "bad" {
  bucket = aws_s3_bucket.b["b"].id
  block_public_acls = false
}
resource "aws_s3_bucket_public_access_block" "good" {
  bucket = aws_s3_bucket.b["b"].id
  block_public_acls = true
  block_public_policy = true
  ignore_public_acls = true
  restrict_public_buckets = true
}
module "isolated" { source = "./modules/bucket" }
