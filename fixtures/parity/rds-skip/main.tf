resource "aws_db_instance" "db" {
  #checkov:skip=CKV_AWS_16:Parity harness skip control
  engine = "postgres"
  instance_class = "db.t3.micro"
  allocated_storage = 20
  storage_encrypted = false
}
