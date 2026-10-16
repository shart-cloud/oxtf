provider "aws" {}

module "net" {
  source = "git::https://example.com/net.git"
}

resource "aws_s3_bucket" "a" {
  bucket = "a"
}

resource "aws_s3_bucket" "b" {
  bucket = "b"
}

resource "aws_s3_bucket_versioning" "b" {
  bucket = "b"
  versioning_configuration {
    status = "Enabled"
  }
}
