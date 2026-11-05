# Gate mode with the Azure DevOps OIDC token of a service connection. In the
# pipeline, azure_devops is used; on a workstation (no SYSTEM_OIDCREQUESTURI),
# azure_identity takes over with the Azure CLI login of the person running
# Terraform, so the same configuration works in both places.
provider "eurodns" {
  gate {
    url = "https://dns-gate.example.com"

    auth {
      # service_connection_id defaults to DNS_GATE_ADO_SERVICE_CONNECTION_ID,
      # for example from a variable group of the pipeline.
      azure_devops {}
      azure_identity {
        scope = "api://dns-gate/.default"
      }
    }
  }
}
