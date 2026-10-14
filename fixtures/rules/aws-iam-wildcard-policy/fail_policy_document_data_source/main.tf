data "aws_iam_policy_document" "admin" {
  statement {
    sid       = "ReadObjects"
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::bucket/*"]
  }

  statement {
    actions   = ["*"]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "admin" {
  name   = "admin"
  policy = data.aws_iam_policy_document.admin.json
}
