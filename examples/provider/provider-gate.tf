# Gate mode: the provider talks to an eurodns-gate, which holds the EuroDNS
# key and enforces RBAC and record ownership. Terraform only proves its
# identity, here with a JWT signed by AWS STS for the current IAM role.
provider "eurodns" {
  gate {
    url = "https://eurodns-gate.example.com" # or EURODNS_GATE_URL

    auth {
      aws_web_identity {
        audience = "eurodns-gate"
      }
    }
  }
}

# Other authentication methods, exactly one per provider:
#   auth { token_file    = "/var/run/secrets/tokens/eurodns-gate" }
#   auth { token_command = ["my-oidc-helper", "--audience", "eurodns-gate"] }
#   auth { token         = var.gate_token }
# Without an auth block, EURODNS_GATE_TOKEN or EURODNS_GATE_TOKEN_FILE is used.
