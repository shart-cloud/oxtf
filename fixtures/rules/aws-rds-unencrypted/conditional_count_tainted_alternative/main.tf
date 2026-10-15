# count chooses between an unconstrained variable and 0 on an apply-time
# condition: the instance may exist depending on var.replicas.
variable "replicas" {
  type = number
}

data "aws_subnets" "remote" {}

resource "aws_db_instance" "db" {
  count             = length(data.aws_subnets.remote.ids) > 0 ? var.replicas : 0
  identifier        = "db"
  engine            = "postgres"
  instance_class    = "db.t3.micro"
  allocated_storage = 20
  storage_encrypted = false
}
