variable "ssh_cidr" {
  type = string
}

resource "aws_security_group" "maybe" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.ssh_cidr]
  }
}
