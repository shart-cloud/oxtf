variable "encrypted" { type = bool }
variable "exists" { type = bool }
variable "choice" { type = bool }
locals { encrypted = var.encrypted }
module "db" {
  source = "./modules/db"
  encrypted = local.encrypted
}
data "aws_subnets" "remote" {}
resource "aws_db_instance" "conditional_existence" {
  count = var.exists ? 1 : 0
  storage_encrypted = false
}
resource "aws_db_instance" "unknown_existence" {
  count = length(data.aws_subnets.remote.ids)
  storage_encrypted = false
}
resource "aws_db_instance" "absent" {
  count = 0
  storage_encrypted = false
}
resource "aws_db_instance" "choice" {
  storage_encrypted = var.choice ? true : false
}
resource "aws_db_instance" "computed" {
  storage_encrypted = data.aws_subnets.remote.id
}
