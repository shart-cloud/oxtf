locals {
  rules = {
    ssh   = { port = 22, cidr = "10.1.0.0/16" }
    https = { port = 443, cidr = "0.0.0.0/0" }
  }
}

resource "aws_security_group" "dyn" {
  dynamic "ingress" {
    for_each = local.rules
    iterator = rule
    content {
      from_port   = rule.value.port
      to_port     = rule.value.port
      protocol    = "tcp"
      cidr_blocks = [rule.value.cidr]
    }
  }
}
