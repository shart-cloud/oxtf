variable "cidrs" { type = list(string) }
locals { cidrs = var.cidrs }
resource "aws_security_group" "ssh" {
  dynamic "ingress" {
    for_each = local.cidrs
    content {
      protocol = "tcp"
      from_port = 22
      to_port = 22
      cidr_blocks = [ingress.value]
    }
  }
}
