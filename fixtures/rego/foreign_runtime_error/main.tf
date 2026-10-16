# The policy reads `protocol` as a number. "tcp" is not one, so
# to_number fails at runtime (in OPA too, with --strict-builtin-errors).
# The scan must fail loudly on this file rather than silently drop the
# violation.
resource "aws_security_group_rule" "open" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = "sg-123"
}
