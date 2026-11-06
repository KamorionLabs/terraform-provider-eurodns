package provider

import (
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

const pipelineSC = "sc://org/project/dns-gate-x"

func policyGate(t *testing.T) *fakeGate {
	t.Helper()
	g := newFakeGate(t, seededUpstream(t), featurePolicyDelegation)
	g.policy = newFakePolicy()
	return g
}

func fastDelegatedRetry(t *testing.T) {
	saved := defaultDelegatedRetry
	defaultDelegatedRetry.base, defaultDelegatedRetry.max = time.Millisecond, 5*time.Millisecond
	t.Cleanup(func() { defaultDelegatedRetry = saved })
}

func gateRoleTF(hosts string) string {
	return fmt.Sprintf(`
resource "eurodns_gate_role" "x" {
  name        = "dns-gate-x"
  description = "DNS names of pipeline x"
  rules = [{
    zones   = ["example.com"]
    actions = ["dns.read", "dns.record.write"]
    hosts   = [%s]
    types   = ["CNAME", "TXT"]
  }]
}
`, hosts)
}

const gateBindingTF = `
resource "eurodns_gate_binding" "x" {
  name = "dns-gate-x"
  role = eurodns_gate_role.x.name
  team = "dns-gate-x"
  subjects = [{
    issuer = "azure-devops"
    claims = { sub = ["` + pipelineSC + `"] }
  }]
}
`

func checkFake(g *fakeGate, f func(p *fakePolicy) error) resource.TestCheckFunc {
	return func(*terraform.State) error {
		g.mu.Lock()
		defer g.mu.Unlock()
		return f(g.policy)
	}
}

func TestAccGateRoleAndBinding(t *testing.T) {
	clearEnv(t)
	g := policyGate(t)
	p := gateProvider(g.URL)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		CheckDestroy: checkFake(g, func(p *fakePolicy) error {
			if len(p.objects) != 0 {
				return fmt.Errorf("objects left after destroy: %v", p.objects)
			}
			return nil
		}),
		Steps: []resource.TestStep{
			{
				Config: p + gateRoleTF(`"x.apps"`) + gateBindingTF,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("eurodns_gate_role.x", "id", "dns-gate-x"),
					resource.TestCheckResourceAttr("eurodns_gate_role.x", "delegation", "ci"),
					resource.TestCheckResourceAttr("eurodns_gate_role.x", "rebase_on_save", "false"),
					resource.TestCheckResourceAttr("eurodns_gate_role.x", "max_changes_per_request", "0"),
					resource.TestCheckResourceAttrSet("eurodns_gate_role.x", "etag"),
					resource.TestCheckResourceAttr("eurodns_gate_binding.x", "team", "dns-gate-x"),
					resource.TestCheckResourceAttr("eurodns_gate_binding.x", "subjects.0.claims.sub.0", pipelineSC),
					checkFake(g, func(p *fakePolicy) error {
						role := p.objects["role/dns-gate-x"]
						if role == nil || role.Role.Rules[0].Records == nil || role.Role.Rules[0].Records.Hosts[0] != "x.apps" {
							return fmt.Errorf("role in the gate: %+v", role)
						}
						if p.ifNoneMatch != 2 || p.managedBy[0] != "terraform" {
							return fmt.Errorf("create preconditions %d, managed_by %v", p.ifNoneMatch, p.managedBy)
						}
						return nil
					}),
				),
			},
			{
				// In-place update, with the ETag of the state as If-Match.
				Config: p + gateRoleTF(`"x.apps", "_acme-challenge.x.apps"`) + gateBindingTF,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("eurodns_gate_role.x", plancheck.ResourceActionUpdate),
						plancheck.ExpectResourceAction("eurodns_gate_binding.x", plancheck.ResourceActionNoop),
					},
				},
				Check: checkFake(g, func(p *fakePolicy) error {
					if hosts := p.objects["role/dns-gate-x"].Role.Rules[0].Records.Hosts; len(hosts) != 2 || p.ifMatch != 1 {
						return fmt.Errorf("update: hosts %v, if-match %d", hosts, p.ifMatch)
					}
					return nil
				}),
			},
			{
				// Drift: changed in the gate outside Terraform; the plan restores it.
				PreConfig: func() {
					g.mu.Lock()
					defer g.mu.Unlock()
					obj := g.policy.objects["role/dns-gate-x"]
					obj.Role.Rules[0].Actions = []string{"dns.read"}
					obj.ETag = `"drifted"`
				},
				Config: p + gateRoleTF(`"x.apps", "_acme-challenge.x.apps"`) + gateBindingTF,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction("eurodns_gate_role.x", plancheck.ResourceActionUpdate)},
				},
				Check: checkFake(g, func(p *fakePolicy) error {
					if a := p.objects["role/dns-gate-x"].Role.Rules[0].Actions; len(a) != 2 {
						return fmt.Errorf("drift not corrected: %v", a)
					}
					return nil
				}),
			},
			{
				// Deleted outside Terraform: planned for creation again.
				PreConfig: func() {
					g.mu.Lock()
					defer g.mu.Unlock()
					delete(g.policy.objects, "binding/dns-gate-x")
				},
				Config: p + gateRoleTF(`"x.apps", "_acme-challenge.x.apps"`) + gateBindingTF,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction("eurodns_gate_binding.x", plancheck.ResourceActionCreate)},
				},
			},
			{ResourceName: "eurodns_gate_role.x", ImportState: true, ImportStateId: "dns-gate-x", ImportStateVerify: true},
			{ResourceName: "eurodns_gate_binding.x", ImportState: true, ImportStateId: "dns-gate-x", ImportStateVerify: true},
		},
	})
}

func TestAccGateBindingTeamFromAndGroups(t *testing.T) {
	clearEnv(t)
	g := policyGate(t)
	p := gateProvider(g.URL)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{{
			Config: p + `
resource "eurodns_gate_binding" "all" {
  name = "gate-pipelines"
  role = "pipeline-writer"
  team_from = {
    claim = "sub"
    regex = "^sc://[^/]+/[^/]+/(dns-gate-[a-z0-9-]+)$"
  }
  subjects = [{
    issuer = "azure-devops"
    claims = { sub = ["sc://org/project/dns-gate-*"] }
  }]
  groups = ["release-pipelines"]
}
`,
			Check: resource.ComposeTestCheckFunc(
				resource.TestCheckNoResourceAttr("eurodns_gate_binding.all", "team"),
				resource.TestCheckResourceAttr("eurodns_gate_binding.all", "team_from.claim", "sub"),
				resource.TestCheckResourceAttr("eurodns_gate_binding.all", "groups.0", "release-pipelines"),
				checkFake(g, func(p *fakePolicy) error {
					b := p.objects["binding/gate-pipelines"].Binding
					if b.TeamFrom == nil || b.Team != "" || len(b.Groups) != 1 {
						return fmt.Errorf("binding in the gate: %+v", b)
					}
					return nil
				}),
			),
		}},
	})
}

func TestAccGateRoleBusyRetried(t *testing.T) {
	clearEnv(t)
	fastDelegatedRetry(t)
	g := policyGate(t)
	g.set(func(g *fakeGate) { g.policy.busy = 3 })
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{{
			Config: gateProvider(g.URL) + gateRoleTF(`"x.apps"`),
			Check: checkFake(g, func(p *fakePolicy) error {
				if p.busyRefusals != 3 || p.objects["role/dns-gate-x"] == nil {
					return fmt.Errorf("busy refusals %d", p.busyRefusals)
				}
				return nil
			}),
		}},
	})
}

func TestAccGateRoleErrors(t *testing.T) {
	clearEnv(t)
	fastDelegatedRetry(t)
	g := policyGate(t)
	g.set(func(g *fakeGate) { g.policy.forbiddenZone = "example.org" })
	p := gateProvider(g.URL)
	outside := `
resource "eurodns_gate_role" "o" {
  name  = "outside"
  rules = [{ zones = ["example.org"], actions = ["dns.record.write"] }]
}
`
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{
			{Config: p + outside, ExpectError: regexp.MustCompile(`(?s)invalid_policy.*delegated\.roles\.outside\.rules\[0\]\.zones\[0\].*allow\.zones`)},
			{
				PreConfig: func() {
					g.mu.Lock()
					defer g.mu.Unlock()
					g.policy.objects["role/dns-gate-x"] = &gateObject{Kind: "role", Name: "dns-gate-x", Role: &gateRole{Rules: []gateRule{{Zones: []string{"example.com"}, Actions: []string{"dns.read"}}}}, Owner: gateOwner{Delegation: "ci"}, ETag: `"other"`}
				},
				Config:      p + gateRoleTF(`"x.apps"`),
				ExpectError: regexp.MustCompile(`already exists[\s\S]*terraform import`),
			},
			{
				PreConfig:   func() { g.set(func(g *fakeGate) { g.policy.busy = 100 }) },
				Config:      p + `resource "eurodns_gate_role" "b" {` + "\n" + `  name = "busy"` + "\n" + `  rules = [{ zones = ["example.com"], actions = ["dns.read"] }]` + "\n}\n",
				ExpectError: regexp.MustCompile(`policy_busy`),
			},
			{
				Config:      p + `resource "eurodns_gate_binding" "n" {` + "\n" + `  name = "n"` + "\n" + `  role = "r"` + "\n" + `  groups = ["g"]` + "\n}\n",
				ExpectError: regexp.MustCompile(`one \(and only one\) of \[team,team_from\]`),
			},
			{
				Config:      p + `resource "eurodns_gate_role" "t" {` + "\n" + `  name = "t"` + "\n" + `  ephemeral_ttl = "soon"` + "\n" + `  rules = [{ zones = ["example.com"], actions = ["dns.read"] }]` + "\n}\n",
				ExpectError: regexp.MustCompile(`Invalid duration`),
			},
		},
	})
}

func TestAccGateRoleModes(t *testing.T) {
	clearEnv(t)
	up := seededUpstream(t)
	cfg := gateRoleTF(`"x.apps"`)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{
			{Config: directProvider(up.URL) + cfg, ExpectError: regexp.MustCompile(`requires gate mode`)},
			{Config: gateProvider(newFakeGate(t, up).URL) + cfg, ExpectError: regexp.MustCompile(`does not serve the delegation API`)},
		},
	})
}
