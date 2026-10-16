resource "aws_s3_bucket" "protected" {
  bucket = "protected"
}

resource "aws_s3_bucket_public_access_block" "protected" {
  bucket                  = "protected"
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket" "exposed" {
  bucket = "exposed"
}

resource "aws_db_instance" "db" {
  engine            = "postgres"
  instance_class    = "db.t3.micro"
  storage_encrypted = false
}
