resource "google_storage_bucket" "b" {
  name                        = "my-bucket"
  location                    = "US"
  uniform_bucket_level_access = true
}
