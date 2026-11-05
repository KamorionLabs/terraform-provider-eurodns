# Bind the role to the Azure DevOps service connection of the web pipeline.
# The team is the one the delegation derives from the subject
# (allow.teams.from_subject), so the pipeline owns the RRsets it creates.
resource "eurodns_gate_binding" "web" {
  name = "dns-gate-web"
  role = eurodns_gate_role.web.name
  team = "dns-gate-web"
  subjects = [{
    issuer = "azure-devops"
    claims = { sub = ["sc://org/project/dns-gate-web"] }
  }]
}

# Same, deriving the team from the token of each subject instead.
resource "eurodns_gate_binding" "web_team_from" {
  name = "dns-gate-web-derived"
  role = eurodns_gate_role.web.name
  team_from = {
    claim = "sub"
    regex = "^sc://[^/]+/[^/]+/(dns-gate-[a-z0-9-]+)$"
  }
  subjects = [{
    issuer = "azure-devops"
    claims = { sub = ["sc://org/project/dns-gate-web"] }
  }]
}
