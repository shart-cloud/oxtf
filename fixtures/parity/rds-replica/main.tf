resource "aws_db_instance" "replica" {
  replicate_source_db = "existing-encrypted-db"
  instance_class = "db.t3.micro"
}
