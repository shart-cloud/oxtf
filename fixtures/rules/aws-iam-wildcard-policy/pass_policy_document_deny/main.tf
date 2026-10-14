data "aws_iam_policy_document" "deny_all" {
  statement {
    effect    = "Deny"
    actions   = ["*"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "deny_all" {
  name   = "deny-all"
  role   = "some-role"
  policy = data.aws_iam_policy_document.deny_all.json
}
