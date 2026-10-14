variable "statements" {
  default = [
    { actions = ["s3:GetObject"], resources = ["arn:aws:s3:::b/*"] },
    { actions = ["*"], resources = ["*"] },
  ]
}

resource "aws_iam_policy" "dyn" {
  name = "dyn"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [for s in var.statements : {
      Effect   = "Allow"
      Action   = s.actions
      Resource = s.resources
    }]
  })
}
