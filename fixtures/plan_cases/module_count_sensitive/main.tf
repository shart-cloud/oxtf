# W5 plan-only case: local child module with for_each, count, and a
# sensitive variable. Expected findings are in EXPECT (same format as
# fixtures/rules/*/*/EXPECT, all rules).

variable "db_password" {
  type      = string
  sensitive = true
  default   = "not-a-real-password"
}

module "store" {
  source = "./modules/store"
  names  = ["a", "b"]
}

resource "aws_security_group" "ssh" {
  count = 2
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [count.index == 0 ? "0.0.0.0/0" : "10.0.0.0/8"]
  }
}

resource "aws_db_instance" "db" {
  identifier        = "db"
  engine            = "postgres"
  instance_class    = "db.t3.micro"
  allocated_storage = 20
  username          = "app"
  password          = var.db_password
  storage_encrypted = false
}
