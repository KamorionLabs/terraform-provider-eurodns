# Gate mode: the provider talks to a dns-gate, which holds the EuroDNS
# key and enforces RBAC and record ownership. Terraform only proves its
# identity, here with a JWT signed by AWS STS for the current IAM role.
provider "eurodns" {
  gate {
    url = "https://dns-gate.example.com" # or DNS_GATE_URL

    auth {
      aws_web_identity {
        audience = "dns-gate"
      }
    }
  }
}

# Other authentication methods, exactly one per provider:
#   auth { token_file    = "/var/run/secrets/tokens/dns-gate" }
#   auth { token_command = ["my-oidc-helper", "--audience", "dns-gate"] }
#   auth { token         = var.gate_token }
# Without an auth block, DNS_GATE_TOKEN or DNS_GATE_TOKEN_FILE is used.
