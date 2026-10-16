resource "aws_s3_bucket" "b" {
  bucket        = "b"
  force_destroy = true
}
