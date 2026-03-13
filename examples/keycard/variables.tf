variable "google_client_id" {
  description = "Google OAuth client ID (from Google Cloud Console)"
  type        = string
}

variable "google_client_secret" {
  description = "Google OAuth client secret"
  type        = string
  sensitive   = true
}
