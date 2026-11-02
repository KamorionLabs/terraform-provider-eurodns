# Gate mode with a Microsoft Entra ID token for the gate application.
provider "eurodns" {
  gate {
    url = "https://eurodns-gate.example.com"

    auth {
      azure_identity {
        scope = "api://eurodns-gate/.default"
        # tenant_id = "00000000-0000-0000-0000-000000000000"
        # client_id = "11111111-1111-1111-1111-111111111111" # user-assigned managed identity
      }
    }
  }
}
