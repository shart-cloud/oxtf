variable "encrypt" {
  type    = bool
  default = false
}

resource "aws_db_instance" "db" {
  identifier        = "db"
  engine            = "postgres"
  instance_class    = "db.t3.micro"
  allocated_storage = 20
  storage_encrypted = var.encrypt
}
