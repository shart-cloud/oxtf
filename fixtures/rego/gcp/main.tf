variable "uniform" { type = bool }
variable "exists" { type = bool }
variable "choice" { type = bool }
locals { uniform = var.uniform }
module "bucket" {
  source = "./modules/bucket"
  uniform = local.uniform
}
data "google_storage_bucket" "remote" { name = "remote" }
resource "google_storage_bucket" "conditional_existence" {
  count = var.exists ? 1 : 0
  uniform_bucket_level_access = false
}
resource "google_storage_bucket" "unknown_existence" {
  count = data.google_storage_bucket.remote.uniform_bucket_level_access ? 1 : 0
  uniform_bucket_level_access = false
}
resource "google_storage_bucket" "absent" {
  count = 0
  uniform_bucket_level_access = false
}
resource "google_storage_bucket" "choice" {
  uniform_bucket_level_access = var.choice ? true : false
}
resource "google_storage_bucket" "tainted" {
  uniform_bucket_level_access = var.choice
}
resource "google_storage_bucket" "computed" {
  uniform_bucket_level_access = data.google_storage_bucket.remote.uniform_bucket_level_access
}
resource "google_storage_bucket" "explicit_null" {
  uniform_bucket_level_access = null
}
resource "google_storage_bucket" "default" {}
resource "google_storage_bucket" "string_true" {
  uniform_bucket_level_access = "true"
}
