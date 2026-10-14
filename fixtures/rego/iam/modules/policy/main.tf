variable "actions" { type = list(string) }
locals { actions = var.actions }
resource "aws_iam_role_policy" "policy" {
  policy = jsonencode({ Statement = [for action in local.actions : { Effect = "Allow", Action = action, Resource = "*" }] })
}
