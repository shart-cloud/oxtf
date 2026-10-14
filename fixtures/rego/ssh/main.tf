variable "cidrs" { type = list(string) }
variable "choice" { type = bool }
variable "port" { type = number }
locals { cidrs = var.cidrs }
module "network" {
  source = "./modules/network"
  cidrs = local.cidrs
}
resource "aws_security_group_rule" "legacy" {
  type = "ingress"
  protocol = "tcp"
  from_port = 22
  to_port = 22
  cidr_blocks = var.choice ? ["0.0.0.0/0"] : ["10.0.0.0/8"]
}
resource "aws_security_group_rule" "egress" {
  type = "egress"
  protocol = "-1"
  cidr_blocks = ["0.0.0.0/0"]
}
resource "aws_vpc_security_group_ingress_rule" "port" {
  ip_protocol = "6"
  from_port = var.port
  to_port = 22
  cidr_ipv6 = "::/0"
}
resource "aws_vpc_security_group_ingress_rule" "all" {
  ip_protocol = "-1"
  cidr_ipv6 = "::/0"
}
resource "aws_security_group" "choice" {
  ingress = var.choice ? [{ protocol = "tcp", from_port = 22, to_port = 22, cidr_blocks = ["0.0.0.0/0"] }] : []
}
