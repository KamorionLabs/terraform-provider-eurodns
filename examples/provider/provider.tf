# Direct mode: the provider talks to EuroDNS with an API key.
provider "eurodns" {
  app_id  = var.eurodns_app_id  # or EURODNS_APP_ID
  api_key = var.eurodns_api_key # or EURODNS_API_KEY
}
