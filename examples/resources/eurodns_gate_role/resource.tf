# Gate mode only. The provider identity must be a subject of a policy
# delegation of the gate (policy.delegations); the role must stay within it.
resource "eurodns_gate_role" "web" {
  name        = "dns-gate-web"
  description = "DNS names of the web pipeline"
  rules = [{
    zones   = ["example.com"]
    actions = ["dns.read", "dns.record.write"]
    hosts   = ["web.apps", "_acme-challenge.web.apps"]
    types   = ["CNAME", "TXT"]
  }]
}
