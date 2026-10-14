resource "aws_iam_policy" "read" {
  name = "read"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = "s3:GetObject", Resource = "*" },
      { Effect = "Allow", Action = "*", Resource = "arn:aws:s3:::bucket/*" },
      { Effect = "Deny", Action = "*", Resource = "*" },
    ]
  })
}
