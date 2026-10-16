resource "aws_db_instance" "db" {
  engine            = "postgres"
  storage_encrypted = false
}
