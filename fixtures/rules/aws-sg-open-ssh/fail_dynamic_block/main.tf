variable "ingress_rules" {
  type = list(object({ port = number, cidr = string }))
  default = [
    { port = 443, cidr = "0.0.0.0/0" },
    { port = 22, cidr = "0.0.0.0/0" },
  ]
}

resource "aws_security_group" "dyn" {
  dynamic "ingress" {
    for_each = var.ingress_rules
    content {
      from_port   = ingress.value.port
      to_port     = ingress.value.port
      protocol    = "tcp"
      cidr_blocks = [ingress.value.cidr]
    }
  }
}
