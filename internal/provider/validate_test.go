package provider

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	tfresource "github.com/hashicorp/terraform-plugin-testing/helper/resource"

	eurodns "github.com/KamorionLabs/eurodns-go"
)

func validateRecordSet(t *testing.T, host, typ string, values ...string) diag.Diagnostics {
	t.Helper()
	ctx := context.Background()
	r := &recordSetResource{}
	var sch resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &sch)
	vals := make([]tftypes.Value, len(values))
	for i, v := range values {
		vals[i] = tftypes.NewValue(tftypes.String, v)
	}
	raw := tftypes.NewValue(sch.Schema.Type().TerraformType(ctx), map[string]tftypes.Value{
		"id":     tftypes.NewValue(tftypes.String, nil),
		"zone":   tftypes.NewValue(tftypes.String, testZone),
		"host":   tftypes.NewValue(tftypes.String, host),
		"type":   tftypes.NewValue(tftypes.String, typ),
		"ttl":    tftypes.NewValue(tftypes.Number, nil),
		"values": tftypes.NewValue(tftypes.Set{ElementType: tftypes.String}, vals),
	})
	var resp resource.ValidateConfigResponse
	r.ValidateConfig(ctx, resource.ValidateConfigRequest{Config: tfsdk.Config{Schema: sch.Schema, Raw: raw}}, &resp)
	return resp.Diagnostics
}

func TestValidateRecordSet(t *testing.T) {
	cases := []struct {
		name, host, typ string
		values          []string
		errs, warns     int
		match           string
	}{
		{"cname with dot", "www", "CNAME", []string{"target.example.net."}, 0, 0, ""},
		{"cname without dot", "www", "CNAME", []string{"target.example.net"}, 1, 0, "relative to the zone"},
		{"mx without dot", "@", "MX", []string{"10 mx.example.net"}, 1, 0, `"10 mx.example.net."`},
		{"srv without dot", "_sip._tcp", "SRV", []string{"10 5 5060 sip.example.net"}, 1, 0, "relative to the zone"},
		{"txt raw", "@", "TXT", []string{"v=spf1 -all"}, 0, 0, ""},
		{"txt quoted", "@", "TXT", []string{`"v=spf1 -all"`}, 0, 1, "quotes included"},
		{"soa", "@", "SOA", []string{"ns1.example.net. hostmaster.example.com. 1 7200 3600 1209600 600"}, 1, 0, "serial"},
		{"apex ns", "@", "NS", []string{"ns1.example.net."}, 1, 0, "apex NS records are locked"},
		{"sub ns", "sub", "NS", []string{"ns1.example.net."}, 0, 0, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := validateRecordSet(t, c.host, c.typ, c.values...)
			if d.ErrorsCount() != c.errs || d.WarningsCount() != c.warns {
				t.Fatalf("errors %d warnings %d: %v", d.ErrorsCount(), d.WarningsCount(), d)
			}
			if c.match != "" {
				all := ""
				for _, x := range d {
					all += x.Summary() + " " + x.Detail()
				}
				if !strings.Contains(all, c.match) {
					t.Fatalf("diagnostics %q do not mention %q", all, c.match)
				}
			}
		})
	}
}

func TestAPIErrorDiagnostics(t *testing.T) {
	recErr, _ := json.Marshal(eurodns.RecordError{
		Messages: []string{"Invalid TTL"},
		Record:   &eurodns.Record{Type: "A", Host: "app"},
		Severity: eurodns.SeverityError,
	})
	err := &eurodns.APIError{
		StatusCode: 400, Method: "PUT", Path: "/dns-zones/example.com",
		Code: "INVALID_ZONE", Message: "Zone is not valid",
		Report: &eurodns.ValidationReport{RecordErrors: []json.RawMessage{recErr}},
	}
	var d diag.Diagnostics
	addAPIError(&d, "Cannot update the record set", err)
	detail := d[0].Detail()
	for _, want := range []string{"EuroDNS error: INVALID_ZONE (HTTP 400)", "Message: Zone is not valid", "Validation report:", "Invalid TTL"} {
		if !strings.Contains(detail, want) {
			t.Fatalf("detail %q lacks %q", detail, want)
		}
	}
}

func TestAccRecordSet_planTimeRefusals(t *testing.T) {
	clearEnv(t)
	up := seededUpstream(t)
	p := directProvider(up.URL)
	for _, c := range []struct{ cfg, re string }{
		{recordSet("cname", "www", "CNAME", 3600, "target.example.net"), `trailing dot`},
		{recordSet("soa", "@", "SOA", 3600, "ns1.example.net. hostmaster.example.com. 1 7200 3600 1209600 600"), `cannot be managed`},
		{recordSet("ns", "@", "NS", 3600, "ns1.example.net."), `cannot be managed`},
	} {
		tfresource.UnitTest(t, tfresource.TestCase{
			ProtoV6ProviderFactories: testProviders,
			Steps:                    []tfresource.TestStep{{Config: p + c.cfg, ExpectError: regexp.MustCompile(c.re)}},
		})
	}
	if n := up.Requests(); n != 0 {
		t.Fatalf("plan-time refusals must not call the API, got %d requests", n)
	}
}
