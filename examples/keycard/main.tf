terraform {
  required_providers {
    keycard = {
      source  = "keycardai/keycard"
      version = "~> 0.1"
    }
  }
}

# Authenticate via env vars:
#   export KEYCARD_CLIENT_ID="your-service-account-client-id"
#   export KEYCARD_CLIENT_SECRET="your-service-account-client-secret"
provider "keycard" {}

# --- 1. Zone: isolated environment for this project ---
resource "keycard_zone" "demo" {
  name        = "opencloak-demo"
  description = "Demo zone for OpenCloak + Daytona integration"

  oauth2 = {
    pkce_required = true
    dcr_enabled   = true
  }
}

# --- 2. Provider: Google as the user identity provider ---
resource "keycard_provider" "google" {
  name    = "Google"
  zone_id = keycard_zone.demo.id

  identifier    = "google"
  client_id     = var.google_client_id
  client_secret = var.google_client_secret

  oauth2 = {
    issuer                 = "https://accounts.google.com"
    authorization_endpoint = "https://accounts.google.com/o/oauth2/v2/auth"
    token_endpoint         = "https://oauth2.googleapis.com/token"
  }
}

# --- 3. Set Google as the zone's user identity provider ---
resource "keycard_zone_user_identity_config" "google" {
  zone_id     = keycard_zone.demo.id
  provider_id = keycard_provider.google.id
}

# --- 4. Application: your MCP server / AI agent ---
resource "keycard_application" "mcp_agent" {
  name       = "OpenClaw Agent"
  identifier = "openclaw-agent"
  zone_id    = keycard_zone.demo.id

  description = "AI agent running in Daytona sandbox"

  oauth2 = {
    redirect_uris = ["https://id.opencloak.org/auth/google/callback"]
  }
}

# --- 5. Client credentials for the application ---
resource "keycard_application_client_secret" "mcp_agent_creds" {
  application_id = keycard_application.mcp_agent.id
  zone_id        = keycard_zone.demo.id
}

# --- 6. Resources: the APIs your agent needs to access ---

# Google Calendar API
resource "keycard_resource" "google_calendar" {
  name                   = "Google Calendar"
  identifier             = "google-calendar"
  zone_id                = keycard_zone.demo.id
  credential_provider_id = keycard_provider.google.id

  description = "Google Calendar API"

  oauth2 = {
    scopes = ["https://www.googleapis.com/auth/calendar.readonly"]
  }
}

# Google Drive API
resource "keycard_resource" "google_drive" {
  name                   = "Google Drive"
  identifier             = "google-drive"
  zone_id                = keycard_zone.demo.id
  credential_provider_id = keycard_provider.google.id

  description = "Google Drive API"

  oauth2 = {
    scopes = ["https://www.googleapis.com/auth/drive.readonly"]
  }
}

# --- 7. Dependencies: grant the agent access to resources ---

resource "keycard_application_dependency" "agent_calendar" {
  application_id = keycard_application.mcp_agent.id
  resource_id    = keycard_resource.google_calendar.id
  zone_id        = keycard_zone.demo.id
}

resource "keycard_application_dependency" "agent_drive" {
  application_id = keycard_application.mcp_agent.id
  resource_id    = keycard_resource.google_drive.id
  zone_id        = keycard_zone.demo.id
}

# --- Outputs ---

output "zone_issuer_uri" {
  description = "OIDC issuer URI for this zone"
  value       = keycard_zone.demo.oauth2.issuer_uri
}

output "app_client_id" {
  description = "Client ID for the MCP agent"
  value       = keycard_application_client_secret.mcp_agent_creds.client_id
  sensitive   = true
}

output "app_client_secret" {
  description = "Client secret for the MCP agent (only shown at creation)"
  value       = keycard_application_client_secret.mcp_agent_creds.client_secret
  sensitive   = true
}
