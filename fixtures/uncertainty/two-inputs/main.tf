variable "a" { type = bool }
variable "b" { type = bool }
resource "aws_db_instance" "db" {
  storage_encrypted = var.a == var.b
}
