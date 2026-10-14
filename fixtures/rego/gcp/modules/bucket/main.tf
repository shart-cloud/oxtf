variable "uniform" { type = bool }
locals { uniform = var.uniform }
resource "google_storage_bucket" "bucket" {
  uniform_bucket_level_access = local.uniform
}
