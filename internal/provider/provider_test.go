package provider

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"

	eurodns "github.com/KamorionLabs/eurodns-go"
	"github.com/KamorionLabs/eurodns-go/eurodnstest"
	"github.com/KamorionLabs/eurodns-go/rrset"
)

var testProviders = map[string]func() (tfprotov6.ProviderServer, error){
	"eurodns": providerserver.NewProtocol6WithError(New("test")()),
}

func TestMain(m *testing.M) {
	if os.Getenv("TF_ACC_TERRAFORM_PATH") == "" {
		if p, err := exec.LookPath("terraform"); err == nil {
			os.Setenv("TF_ACC_TERRAFORM_PATH", p)
		}
	}
	os.Setenv("CHECKPOINT_DISABLE", "1")
	os.Exit(m.Run())
}

func clearEnv(t *testing.T) {
	for _, k := range []string{envAppID, envAPIKey, envBaseURL, envGateURL, envGateToken, envGateTokenFile, envADOOIDCRequestURI, envADOAccessToken, envADOServiceConnectionID} {
		t.Setenv(k, "")
	}
}

func boolPtr(b bool) *bool { return &b }

// seededUpstream starts a fake EuroDNS with records nobody manages.
func seededUpstream(t *testing.T) *eurodnstest.Server {
	t.Helper()
	s := eurodnstest.NewServer(eurodnstest.Options{AppID: testAppID, APIKey: testAPIKey})
	t.Cleanup(s.Close)
	s.Seed(&eurodns.Zone{Name: testZone, Records: []eurodns.Record{
		{Type: "A", Host: "@", TTL: 3600, RData: "192.0.2.10"},
		{Type: "MX", Host: "@", TTL: 3600, RData: "10 mail.example.com."},
		{Type: "TXT", Host: "legacy", TTL: 600, RData: "keep-me"},
		{Type: "CNAME", Host: "locked", TTL: 3600, RData: "target.example.net.", Locked: boolPtr(true)},
	}})
	return s
}

func directProvider(url string) string {
	return fmt.Sprintf(`
provider "eurodns" {
  app_id           = %q
  api_key          = %q
  base_url         = %q
  request_interval = "1ms"
  max_retries      = 0
}
`, testAppID, testAPIKey, url)
}

func gateProvider(url string) string {
	return fmt.Sprintf(`
provider "eurodns" {
  request_interval = "1ms"
  max_retries      = 0
  gate {
    url = %q
    auth {
      token = %q
    }
  }
}
`, url, testToken)
}

func recordSet(name, host, typ string, ttl int, values ...string) string {
	q := make([]string, len(values))
	for i, v := range values {
		q[i] = fmt.Sprintf("%q", v)
	}
	return fmt.Sprintf(`
resource "eurodns_record_set" %q {
  zone   = %q
  host   = %q
  type   = %q
  ttl    = %d
  values = [%s]
}
`, name, testZone, host, typ, ttl, join(q))
}

func join(s []string) string {
	out := ""
	for i, v := range s {
		if i > 0 {
			out += ", "
		}
		out += v
	}
	return out
}

// upstreamSet returns the sorted values of an RRset in the fake EuroDNS.
func upstreamSet(s *eurodnstest.Server, host, typ string) []string {
	z := s.Zone(testZone)
	if z == nil {
		return nil
	}
	set, ok := rrset.Group(testZone, z.Records)[rrset.Key{Host: host, Type: typ}]
	if !ok {
		return nil
	}
	v := append([]string(nil), set.Values...)
	sort.Strings(v)
	return v
}

// checkUnmanagedPreserved verifies records outside the configuration are
// unchanged, including their ids and the locked flag.
func checkUnmanagedPreserved(s *eurodnstest.Server, before []eurodns.Record) resource.TestCheckFunc {
	return func(*terraform.State) error {
		after := map[string]eurodns.Record{}
		for _, r := range s.Zone(testZone).Records {
			after[r.Type+"|"+r.Host+"|"+r.RData] = r
		}
		for _, b := range before {
			if rrset.ServerManaged(b) {
				continue // SOA serial and locked records are rewritten by EuroDNS
			}
			a, ok := after[b.Type+"|"+b.Host+"|"+b.RData]
			if !ok {
				return fmt.Errorf("unmanaged record %s %s %s was removed", b.Host, b.Type, b.RData)
			}
			if a.TTL != b.TTL || deref(a.ID) != deref(b.ID) || flag(a.Locked) != flag(b.Locked) {
				return fmt.Errorf("unmanaged record %s %s changed: %+v -> %+v", b.Host, b.Type, b, a)
			}
		}
		return nil
	}
}

func flag(b *bool) bool { return b != nil && *b }

func deref(p *int64) int64 {
	if p == nil {
		return -1
	}
	return *p
}

func checkUpstream(s *eurodnstest.Server, host, typ string, want ...string) resource.TestCheckFunc {
	return func(*terraform.State) error {
		got := upstreamSet(s, host, typ)
		sort.Strings(want)
		if fmt.Sprint(got) != fmt.Sprint(want) {
			return fmt.Errorf("upstream %s %s = %v, want %v", host, typ, got, want)
		}
		return nil
	}
}

func TestAccRecordSet_direct(t *testing.T) {
	clearEnv(t)
	up := seededUpstream(t)
	before := up.Zone(testZone).Records
	p := directProvider(up.URL)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		CheckDestroy: resource.ComposeTestCheckFunc(
			checkUpstream(up, "app", "A"),
			checkUnmanagedPreserved(up, before),
		),
		Steps: []resource.TestStep{
			{
				Config: p + recordSet("app", "app", "A", 600, "192.0.2.1", "192.0.2.2"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("eurodns_record_set.app", "id", "example.com/app/A"),
					resource.TestCheckResourceAttr("eurodns_record_set.app", "values.#", "2"),
					checkUpstream(up, "app", "A", "192.0.2.1", "192.0.2.2"),
					checkUnmanagedPreserved(up, before),
				),
			},
			{
				Config: p + recordSet("app", "app", "A", 3600, "192.0.2.3"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("eurodns_record_set.app", "ttl", "3600"),
					checkUpstream(up, "app", "A", "192.0.2.3"),
					checkUnmanagedPreserved(up, before),
				),
			},
			{
				ResourceName:      "eurodns_record_set.app",
				ImportState:       true,
				ImportStateId:     "example.com/app/A",
				ImportStateVerify: true,
			},
			{
				Config: p + recordSet("app", "app", "A", 3600, "192.0.2.3") + `
data "eurodns_zone" "z" {
  zone = "example.com"
}
data "eurodns_record_set" "mx" {
  zone = "example.com"
  host = "@"
  type = "MX"
}
`,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckTypeSetElemNestedAttrs("data.eurodns_zone.z", "records.*", map[string]string{"host": "@", "type": "MX", "rdata": "10 mail.example.com."}),
					resource.TestCheckTypeSetElemNestedAttrs("data.eurodns_zone.z", "records.*", map[string]string{"host": "app", "type": "A", "rdata": "192.0.2.3"}),
					resource.TestCheckResourceAttr("data.eurodns_record_set.mx", "values.0", "10 mail.example.com."),
					resource.TestCheckResourceAttr("data.eurodns_record_set.mx", "ttl", "3600"),
				),
			},
		},
	})
}

func TestAccRecordSet_typeChangeInPlace(t *testing.T) {
	clearEnv(t)
	up := seededUpstream(t)
	before := up.Zone(testZone).Records
	p := directProvider(up.URL)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{
			{
				Config: p + recordSet("site", "site", "A", 600, "192.0.2.1"),
				Check:  checkUpstream(up, "site", "A", "192.0.2.1"),
			},
			{
				Config: p + recordSet("site", "site", "CNAME", 600, "relay.example.net."),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction("eurodns_record_set.site", plancheck.ResourceActionUpdate)},
				},
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("eurodns_record_set.site", "id", "example.com/site/CNAME"),
					checkUpstream(up, "site", "A"),
					checkUpstream(up, "site", "CNAME", "relay.example.net."),
					checkUnmanagedPreserved(up, before),
				),
			},
		},
	})
}

func TestAccRecordSet_hostChangeInPlace(t *testing.T) {
	clearEnv(t)
	up := seededUpstream(t)
	before := up.Zone(testZone).Records
	p := directProvider(up.URL)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		CheckDestroy:             checkUpstream(up, "new", "A"),
		Steps: []resource.TestStep{
			{
				Config: p + recordSet("site", "old", "A", 600, "192.0.2.1"),
				Check:  checkUpstream(up, "old", "A", "192.0.2.1"),
			},
			{
				Config: p + recordSet("site", "new", "A", 600, "192.0.2.1"),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("eurodns_record_set.site", plancheck.ResourceActionUpdate),
						plancheck.ExpectUnknownValue("eurodns_record_set.site", tfjsonpath.New("id")),
					},
				},
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("eurodns_record_set.site", "id", "example.com/new/A"),
					checkUpstream(up, "old", "A"),
					checkUpstream(up, "new", "A", "192.0.2.1"),
					checkUnmanagedPreserved(up, before),
				),
			},
			{
				// Host and type together, still one update.
				Config: p + recordSet("site", "edge", "CNAME", 600, "relay.example.net."),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction("eurodns_record_set.site", plancheck.ResourceActionUpdate)},
				},
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("eurodns_record_set.site", "id", "example.com/edge/CNAME"),
					checkUpstream(up, "new", "A"),
					checkUpstream(up, "edge", "CNAME", "relay.example.net."),
					checkUnmanagedPreserved(up, before),
				),
			},
			{
				Config: p + recordSet("site", "new", "A", 600, "192.0.2.1"),
				Check:  checkUpstream(up, "new", "A", "192.0.2.1"),
			},
			{
				// Moving onto an RRset this configuration does not manage is refused.
				Config:      p + recordSet("site", "legacy", "TXT", 600, "overwrite"),
				ExpectError: regexp.MustCompile(`already exists`),
			},
		},
	})
	if got := upstreamSet(up, "legacy", "TXT"); fmt.Sprint(got) != `[keep-me]` {
		t.Fatalf("existing RRset was modified: %v", got)
	}
}

func TestAccRecordSet_gateHostChangeInPlace(t *testing.T) {
	clearEnv(t)
	up := seededUpstream(t)
	g := newFakeGate(t, up, eurodns.FeatureIfMatch, eurodns.FeatureOwnership, eurodns.FeatureAdopt)
	p := gateProvider(g.URL)
	var saves int

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{
			{
				Config: p + recordSet("acme", "_acme-challenge.old", "TXT", 600, "token"),
				Check:  func(*terraform.State) error { saves = g.saves; return nil },
			},
			{
				// The gate lets the owner delete the old RRset and create the
				// new one in the same save.
				Config: p + recordSet("acme", "_acme-challenge.new", "TXT", 600, "token"),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction("eurodns_record_set.acme", plancheck.ResourceActionUpdate)},
				},
				Check: resource.ComposeTestCheckFunc(
					checkUpstream(up, "_acme-challenge.old", "TXT"),
					checkUpstream(up, "_acme-challenge.new", "TXT", "token"),
					func(*terraform.State) error {
						if g.saves-saves != 1 {
							return fmt.Errorf("expected one zone save, got %d", g.saves-saves)
						}
						return nil
					},
				),
			},
		},
	})
}

// A host unknown at plan time (for example from an ACM certificate being
// created) plans an update, not a replacement, and writes nothing when it
// resolves to the current host.
func TestAccRecordSet_unknownHostUnchanged(t *testing.T) {
	clearEnv(t)
	up := seededUpstream(t)
	g := newFakeGate(t, up, eurodns.FeatureIfMatch, eurodns.FeatureOwnership)
	p := gateProvider(g.URL)
	config := func(trigger string) string {
		return p + fmt.Sprintf(`
resource "terraform_data" "host" {
  input            = "_validation.www"
  triggers_replace = [%q]
}

resource "eurodns_record_set" "validation" {
  zone   = %q
  host   = terraform_data.host.output
  type   = "CNAME"
  ttl    = 600
  values = ["_token.acm-validations.example.net."]
}
`, trigger, testZone)
	}
	var saves int

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{
			{
				Config: config("cert-1"),
				Check: resource.ComposeTestCheckFunc(
					checkUpstream(up, "_validation.www", "CNAME", "_token.acm-validations.example.net."),
					func(*terraform.State) error { saves = g.saves; return nil },
				),
			},
			{
				Config: config("cert-2"),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("terraform_data.host", plancheck.ResourceActionReplace),
						plancheck.ExpectResourceAction("eurodns_record_set.validation", plancheck.ResourceActionUpdate),
						plancheck.ExpectUnknownValue("eurodns_record_set.validation", tfjsonpath.New("host")),
					},
				},
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("eurodns_record_set.validation", "id", "example.com/_validation.www/CNAME"),
					checkUpstream(up, "_validation.www", "CNAME", "_token.acm-validations.example.net."),
					func(*terraform.State) error {
						if g.saves != saves {
							return fmt.Errorf("expected no zone save, got %d", g.saves-saves)
						}
						return nil
					},
				),
			},
		},
	})
}

func TestAccRecordSet_refusesExisting(t *testing.T) {
	clearEnv(t)
	up := seededUpstream(t)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{{
			Config:      directProvider(up.URL) + recordSet("legacy", "legacy", "TXT", 600, "overwrite"),
			ExpectError: regexp.MustCompile(`already exists`),
		}},
	})
	if got := upstreamSet(up, "legacy", "TXT"); fmt.Sprint(got) != `[keep-me]` {
		t.Fatalf("existing RRset was modified: %v", got)
	}
}

func TestAccProvider_modeConflict(t *testing.T) {
	clearEnv(t)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{{
			Config: `
provider "eurodns" {
  app_id  = "a"
  api_key = "b"
  gate {
    url = "https://gate.example.com"
    auth {
      token = "t"
    }
  }
}
data "eurodns_zone" "z" {
  zone = "example.com"
}
`,
			ExpectError: regexp.MustCompile(`mutually exclusive`),
		}},
	})
}

func TestAccProvider_gateURLIsNotAGate(t *testing.T) {
	clearEnv(t)
	up := seededUpstream(t)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{{
			Config:      gateProvider(up.URL) + `data "eurodns_zone" "z" { zone = "example.com" }`,
			ExpectError: regexp.MustCompile(`Not an eurodns-gate`),
		}},
	})
}

func TestAccRecordSet_gate(t *testing.T) {
	clearEnv(t)
	up := seededUpstream(t)
	before := up.Zone(testZone).Records
	g := newFakeGate(t, up, eurodns.FeatureIfMatch, eurodns.FeatureOwnership, eurodns.FeatureAdopt)
	p := gateProvider(g.URL)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{
			{
				// The gate answers 412 once: the provider re-reads and succeeds.
				PreConfig: func() { g.mu.Lock(); g.fail412 = 1; g.mu.Unlock() },
				Config:    p + recordSet("acme", "_acme-challenge.www", "TXT", 600, "token-1"),
				Check: resource.ComposeTestCheckFunc(
					checkUpstream(up, "_acme-challenge.www", "TXT", "token-1"),
					checkUnmanagedPreserved(up, before),
					func(*terraform.State) error {
						if g.preconditions != 1 {
							return fmt.Errorf("expected one 412, got %d", g.preconditions)
						}
						return nil
					},
				),
			},
			{
				Config: p + recordSet("acme", "_acme-challenge.www", "TXT", 600, "token-2"),
				Check:  checkUpstream(up, "_acme-challenge.www", "TXT", "token-2"),
			},
			{
				// Importing a foreign RRset adopts it in the gate.
				Config:             p + recordSet("acme", "_acme-challenge.www", "TXT", 600, "token-2") + recordSet("legacy", "legacy", "TXT", 600, "keep-me"),
				ResourceName:       "eurodns_record_set.legacy",
				ImportState:        true,
				ImportStateId:      "example.com/legacy/TXT",
				ImportStatePersist: true,
			},
			{
				Config: p + recordSet("acme", "_acme-challenge.www", "TXT", 600, "token-2") + recordSet("legacy", "legacy", "TXT", 600, "updated"),
				Check: resource.ComposeTestCheckFunc(
					checkUpstream(up, "legacy", "TXT", "updated"),
					func(*terraform.State) error {
						if len(g.adopted) != 1 || g.adopted[0].Host != "legacy" || g.adopted[0].Type != "TXT" {
							return fmt.Errorf("unexpected adoptions: %+v", g.adopted)
						}
						return nil
					},
				),
			},
		},
	})
}

func TestAccRecordSet_gateRefusesForeign(t *testing.T) {
	clearEnv(t)
	up := seededUpstream(t)
	g := newFakeGate(t, up, eurodns.FeatureIfMatch) // no adopt: import is a plain read
	p := gateProvider(g.URL)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{
			{
				Config:             p + recordSet("legacy", "legacy", "TXT", 600, "keep-me"),
				ResourceName:       "eurodns_record_set.legacy",
				ImportState:        true,
				ImportStateId:      "example.com/legacy/TXT",
				ImportStatePersist: true,
			},
			{
				Config:      p + recordSet("legacy", "legacy", "TXT", 600, "hijack"),
				ExpectError: regexp.MustCompile(`Gate reason: foreign_rrset`),
			},
			{
				// Forget the foreign RRset without deleting it, so the final
				// destroy does not hit the gate refusal.
				Config: p + `
removed {
  from = eurodns_record_set.legacy
  lifecycle {
    destroy = false
  }
}
`,
			},
		},
	})
	if got := upstreamSet(up, "legacy", "TXT"); fmt.Sprint(got) != `[keep-me]` {
		t.Fatalf("foreign RRset was modified: %v", got)
	}
}

// Values unknown at validation time (variables, other resources) must not
// break ValidateConfig: the trailing-dot check runs once they are known.
func TestAccRecordSet_unknownValues(t *testing.T) {
	clearEnv(t)
	up := seededUpstream(t)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{{
			Config: directProvider(up.URL) + `
resource "terraform_data" "target" {
  input = "edge.example.net."
}

resource "eurodns_record_set" "from_other_resource" {
  zone   = "` + testZone + `"
  host   = "computed"
  type   = "CNAME"
  ttl    = 600
  values = [terraform_data.target.output]
}
`,
			Check: checkUpstream(up, "computed", "CNAME", "edge.example.net."),
		}},
	})
}
