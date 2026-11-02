# Gate mode with the Azure DevOps OIDC token of a service connection. In the
# pipeline, azure_devops is used; on a workstation (no SYSTEM_OIDCREQUESTURI),
# azure_identity takes over with the Azure CLI login of the person running
# Terraform, so the same configuration works in both places.
provider "eurodns" {
  gate {
    url = "https://eurodns-gate.example.com"

    auth {
      azure_devops {
        service_connection_id = "22222222-2222-2222-2222-222222222222"
      }
      azure_identity {
        scope = "api://eurodns-gate/.default"
      }
    }
  }
}
