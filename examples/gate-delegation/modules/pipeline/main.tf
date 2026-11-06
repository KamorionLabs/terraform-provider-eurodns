# One pipeline: its dedicated Azure DevOps service connection, the gate role
# that lets it write only its own DNS names, and the binding of that role to
# the service connection. The stack that creates pipelines calls this module
# once per pipeline, as it creates each pipeline's cloud role and policy.

terraform {
  required_providers {
    azuredevops = { source = "microsoft/azuredevops" }
    eurodns     = { source = "kamorionlabs/eurodns" }
  }
}

variable "project_id" { type = string }
variable "project_name" { type = string }
variable "organization" { type = string }
variable "pipeline_id" { type = number }
variable "name" {
  type        = string
  description = "Pipeline short name: the service connection is dns-gate-<name>."
}
variable "zone" { type = string }
variable "hosts" { type = list(string) }

locals {
  connection = "dns-gate-${var.name}"
  subject    = "sc://${var.organization}/${var.project_name}/${local.connection}"
}

# Generic service connection without credentials, used only for its OIDC
# token (gate.auth.azure_devops in the pipeline's provider block).
resource "azuredevops_serviceendpoint_generic" "gate" {
  project_id            = var.project_id
  service_endpoint_name = local.connection
  server_url            = "https://dns-gate.example.com"
  description           = "dns-gate identity of pipeline ${var.name}"
}

resource "azuredevops_pipeline_authorization" "gate" {
  project_id  = var.project_id
  resource_id = azuredevops_serviceendpoint_generic.gate.id
  type        = "endpoint"
  pipeline_id = var.pipeline_id
}

resource "eurodns_gate_role" "this" {
  name        = local.connection
  description = "DNS names of pipeline ${var.name}"
  rules = [{
    zones   = [var.zone]
    actions = ["dns.read", "dns.record.write"]
    hosts   = var.hosts
    types   = ["CNAME", "TXT"]
  }]
}

resource "eurodns_gate_binding" "this" {
  name = local.connection
  role = eurodns_gate_role.this.name
  team = local.connection # derived by the delegation from the subject
  subjects = [{
    issuer = "azure-devops"
    claims = { sub = [local.subject] }
  }]
}

output "service_connection_id" {
  value = azuredevops_serviceendpoint_generic.gate.id
}
