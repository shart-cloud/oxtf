locals {
  a = "lit $${not} %%{no}"
  b = "x${var.y}z"
  c = "${var.y}"
  d = "${1}"
  e = "${[1, 2]}"
  f = "pre ${var.c ? "t" : "f"} post"
  g = "%{if var.c}yes%{else}no%{endif}"
  h = "%{for k, v in var.m}${k}=${v},%{endfor}"
  i = "a ${~ var.s ~} b"
  j = <<EOT
heredoc ${var.x}
line2
EOT
  k = <<-EOT
    indented
      more
    EOT
  l = (var.p)
  m = lower(var.s)
  n = -1
  o = !true
  p = -var.n
  q = { plain = 1, "quoted" = 2, (var.k) = 3, "t${var.x}" = 4, aws.east = 5 }
  r = [for x in var.l : upper(x) if x != ""]
  s = var.a[0].b[*].c
  t = 1.50
  u = 1e3
  v = 0.000001
  w = "unicode é é \t tab"
  x = null
  y = "%{if var.c}only%{endif}"
  z = try(var.a, "d")
  aa = "${var.a}${var.b}"
  bb = 12345678901234567890
  cc = "${true}"
  dd = "${null}"
  ee = "a ${"inner ${var.x}"} b"
  ff = 1 + 2
  gg = var.x == "y" ? "a" : "b"
  hh = "${~"x"}"
}
resource "a" "b" {
  dynamic "x" {
    for_each = var.l
    content {
      v = x.value
    }
  }
  nested {
    deep { k = 1 }
  }
}
terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}
