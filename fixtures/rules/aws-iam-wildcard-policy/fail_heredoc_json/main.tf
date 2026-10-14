resource "aws_iam_user_policy" "admin" {
  name = "admin"
  user = "bob"
  policy = <<-EOF
    {
      "Version": "2012-10-17",
      "Statement": [
        { "Effect": "Allow", "Action": "*", "Resource": "*" }
      ]
    }
  EOF
}
