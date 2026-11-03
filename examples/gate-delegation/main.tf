# The stack that creates pipelines runs with the identity of the gate
# delegation (here its own Azure DevOps service connection).
provider "eurodns" {
  gate {
    url = "https://eurodns-gate.example.com"
    auth {
      azure_devops {} # EURODNS_GATE_ADO_SERVICE_CONNECTION_ID
    }
  }
}

module "pipeline_web" {
  source       = "./modules/pipeline"
  organization = "org"
  project_name = "project"
  project_id   = var.project_id
  pipeline_id  = 42
  name         = "web"
  zone         = "example.com"
  hosts        = ["web.apps", "_acme-challenge.web.apps"]
}

variable "project_id" { type = string }
