resource "aws_db_instance" "skipped" {
  # checkov:skip=CKV2_SKIP_ENC:encrypted by the platform
  engine = "postgres"
}

resource "aws_db_instance" "other_id" {
  # checkov:skip=CKV2_OTHER:not this rule
  engine = "postgres"
}

resource "aws_db_instance" "bare_skip" {
  engine = "postgres" # checkov:skip=CKV2_SKIP_ENC
}

# checkov:skip=CKV2_SKIP_ENC:outside any block applies to nothing
resource "aws_db_instance" "outside" {
  engine = "postgres"
}

module "child" {
  source = "./child"
  # checkov:skip=CKV2_SKIP_ENC:module-wide
}

module "child2" {
  source = "./child"
}
