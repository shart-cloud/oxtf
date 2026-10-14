locals {
  admin_statement = {
    Effect   = "Allow"
    Action   = ["s3:GetObject", "*"]
    Resource = ["*"]
  }
}

resource "aws_iam_role_policy" "admin" {
  name = "admin"
  role = "some-role"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [local.admin_statement]
  })
}
