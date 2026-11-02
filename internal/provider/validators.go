package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"

	eurodns "github.com/KamorionLabs/eurodns-go"
	"github.com/KamorionLabs/eurodns-go/rrset"
)

func ttlList() string {
	s := make([]string, len(eurodns.AllowedTTLs))
	for i, t := range eurodns.AllowedTTLs {
		s[i] = fmt.Sprint(t)
	}
	return strings.Join(s, ", ")
}

type allowedTTL struct{}

func (allowedTTL) Description(context.Context) string {
	return "TTL must be a value accepted by EuroDNS"
}
func (v allowedTTL) MarkdownDescription(ctx context.Context) string { return v.Description(ctx) }

func (allowedTTL) ValidateInt64(_ context.Context, req validator.Int64Request, resp *validator.Int64Response) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	ttl := req.ConfigValue.ValueInt64()
	for _, t := range eurodns.AllowedTTLs {
		if int64(t) == ttl {
			return
		}
	}
	resp.Diagnostics.AddAttributeError(req.Path, "Unsupported TTL",
		fmt.Sprintf("EuroDNS only accepts these TTLs: %s (got %d).", ttlList(), ttl))
}

type lowercaseNoDot struct{}

func (lowercaseNoDot) Description(context.Context) string {
	return "lowercase name without trailing dot"
}
func (v lowercaseNoDot) MarkdownDescription(ctx context.Context) string { return v.Description(ctx) }

func (lowercaseNoDot) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	v := req.ConfigValue.ValueString()
	if v != strings.ToLower(v) || strings.HasSuffix(v, ".") || v == "" {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid zone name",
			fmt.Sprintf("Use the lowercase zone name without trailing dot, for example %q.", strings.TrimSuffix(strings.ToLower(v), ".")))
	}
}

// relativeHost requires the canonical form rrset.NormalizeHost produces, so
// that state always matches what the API returns.
type relativeHost struct{}

func (relativeHost) Description(context.Context) string {
	return "lowercase name relative to the zone, @ for the apex"
}
func (v relativeHost) MarkdownDescription(ctx context.Context) string { return v.Description(ctx) }

func (relativeHost) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	v := req.ConfigValue.ValueString()
	if v == "" || v != strings.ToLower(v) || strings.HasSuffix(v, ".") || strings.Contains(v, " ") {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid host",
			fmt.Sprintf("Use a lowercase name relative to the zone without trailing dot, or @ for the apex (got %q).", v))
	}
}

// keyHost returns the canonical host for a zone, used by data sources that
// accept fully qualified names.
func keyHost(host, zone string) string { return rrset.NormalizeHost(host, zone) }
