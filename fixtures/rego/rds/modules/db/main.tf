variable "encrypted" { type = bool }
locals { encrypted = var.encrypted }
resource "aws_db_instance" "db" {
  storage_encrypted = local.encrypted
}
