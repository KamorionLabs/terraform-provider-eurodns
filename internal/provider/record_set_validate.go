package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/KamorionLabs/eurodns-go/rrset"
)

var _ resource.ResourceWithValidateConfig = (*recordSetResource)(nil)

// unmanageableReason explains why EuroDNS keeps an RRset to itself, empty if
// the RRset can be managed.
func unmanageableReason(host, typ string) string {
	switch {
	case typ == "SOA":
		return "The SOA record is locked by EuroDNS, which increments its serial on every zone write. It cannot be managed."
	case typ == "NS" && host == "@":
		return "The apex NS records are locked by EuroDNS. Change the nameservers of the domain in the EuroDNS console instead."
	}
	return ""
}

func (r *recordSetResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var cfg recordSetModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() || cfg.Type.IsUnknown() || cfg.Host.IsUnknown() {
		return
	}
	typ, host := cfg.Type.ValueString(), cfg.Host.ValueString()
	if reason := unmanageableReason(host, typ); reason != "" {
		resp.Diagnostics.AddAttributeError(path.Root("type"), "Record set cannot be managed", reason)
		return
	}
	if cfg.Values.IsNull() || cfg.Values.IsUnknown() {
		return
	}
	var elems []types.String
	resp.Diagnostics.Append(cfg.Values.ElementsAs(ctx, &elems, false)...)
	for _, e := range elems {
		if e.IsUnknown() || e.IsNull() {
			continue
		}
		v := e.ValueString()
		if typ == "TXT" && len(v) >= 2 && strings.HasPrefix(v, `"`) && strings.HasSuffix(v, `"`) {
			resp.Diagnostics.AddAttributeWarning(path.Root("values"), "Quoted TXT value",
				fmt.Sprintf("EuroDNS stores TXT values as sent, quotes included: %s will be published with its quotes. "+
					"Write the value without surrounding quotes unless they are part of the data.", v))
		}
		validateTarget(typ, v, &resp.Diagnostics)
	}
}

// validateTarget requires fully qualified targets: without a trailing dot
// EuroDNS appends the zone name.
func validateTarget(typ, value string, diags *diag.Diagnostics) {
	if !rrset.NeedsFQDN(typ) {
		return
	}
	target := rrset.TargetOf(typ, value)
	if target == "" || strings.HasSuffix(target, ".") {
		return
	}
	diags.AddAttributeError(path.Root("values"), "Target without trailing dot",
		fmt.Sprintf("EuroDNS treats names without a trailing dot as relative to the zone: %q would point to %q.<zone>. "+
			"Write %q instead.", value, target, strings.TrimSuffix(value, target)+target+"."))
}
