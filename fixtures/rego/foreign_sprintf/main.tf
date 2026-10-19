# The policy's required-tags rule formats its message with Go's %q verb,
# which regorus 0.12 did not implement. The violation must read as OPA
# words it.
resource "aws_security_group_rule" "open" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = "sg-123"
}
