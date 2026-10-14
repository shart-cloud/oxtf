variable "grants" {
  type = list(object({ actions = list(string), resources = list(string) }))
  default = [
    { actions = ["s3:GetObject"], resources = ["arn:aws:s3:::bucket/*"] },
    { actions = ["*"], resources = ["*"] },
  ]
}

data "aws_iam_policy_document" "dyn" {
  dynamic "statement" {
    for_each = var.grants
    content {
      actions   = statement.value.actions
      resources = statement.value.resources
    }
  }
}

resource "aws_iam_policy" "dyn" {
  name   = "dyn"
  policy = data.aws_iam_policy_document.dyn.json
}
