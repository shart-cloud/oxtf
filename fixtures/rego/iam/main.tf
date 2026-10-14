variable "action" { type = string }
variable "choice" { type = bool }
locals { actions = ["s3:GetObject", var.action] }
module "policy" {
  source = "./modules/policy"
  actions = local.actions
}
resource "aws_iam_user_policy" "choice" {
  policy = jsonencode({ Statement = var.choice ? [{ Effect = "Allow", Action = "*", Resource = "*" }] : [] })
}
resource "aws_iam_group_policy" "raw" {
  policy = "{\"Statement\": {\"Effect\":\"Allow\",\"Action\":[\"*\"],\"Resource\":\"*\"}}"
}
resource "aws_iam_policy" "invalid" { policy = "not JSON" }
resource "aws_iam_policy" "deny" {
  policy = jsonencode({ Statement = [{ Effect = "Deny", Action = "*", Resource = "*" }] })
}
