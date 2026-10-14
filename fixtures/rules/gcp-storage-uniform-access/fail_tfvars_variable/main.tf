variable "uniform_access" {
  type    = bool
  default = true
}

resource "google_storage_bucket" "b" {
  name                        = "my-bucket"
  location                    = "US"
  uniform_bucket_level_access = var.uniform_access
}
