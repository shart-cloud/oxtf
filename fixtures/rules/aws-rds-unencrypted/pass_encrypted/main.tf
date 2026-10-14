variable "encrypt" {
  type    = bool
  default = false
}

resource "aws_db_instance" "a" {
  identifier        = "a"
  engine            = "postgres"
  instance_class    = "db.t3.micro"
  allocated_storage = 20
  storage_encrypted = true
}

resource "aws_db_instance" "b" {
  identifier        = "b"
  engine            = "postgres"
  instance_class    = "db.t3.micro"
  allocated_storage = 20
  storage_encrypted = var.encrypt
}
