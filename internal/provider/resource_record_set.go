package provider

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	eurodns "github.com/KamorionLabs/eurodns-go"
	"github.com/KamorionLabs/eurodns-go/rrset"
	"github.com/KamorionLabs/eurodns-go/zonediff"
)

// recordTypes are the DnsRecordType values a record set can manage. SOA and
// the URL/MAIL pseudo types are left to the EuroDNS console.
var recordTypes = []string{"A", "AAAA", "CNAME", "MX", "NS", "PTR", "SRV", "TXT", "SPF", "CAA", "APEX", "TLSA", "SVCB", "HTTPS", "DS"}

var (
	_ resource.ResourceWithConfigure   = (*recordSetResource)(nil)
	_ resource.ResourceWithImportState = (*recordSetResource)(nil)
)

type recordSetResource struct {
	api *apiClient
}

func newRecordSetResource() resource.Resource { return &recordSetResource{} }

type recordSetModel struct {
	ID     types.String `tfsdk:"id"`
	Zone   types.String `tfsdk:"zone"`
	Host   types.String `tfsdk:"host"`
	Type   types.String `tfsdk:"type"`
	TTL    types.Int64  `tfsdk:"ttl"`
	Values types.Set    `tfsdk:"values"`
}

func (r *recordSetResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_record_set"
}

func (r *recordSetResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	replace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	resp.Schema = schema.Schema{
		MarkdownDescription: "All records of one name and type (an RRset) in a EuroDNS zone. " +
			"Creation fails if the RRset already exists: import it instead. Records not managed by this " +
			"resource are written back unchanged on every save.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "`<zone>/<host>/<type>`.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"zone": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Zone (domain) name, for example `example.com`.",
				PlanModifiers:       replace,
				Validators:          []validator.String{lowercaseNoDot{}},
			},
			"host": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Name relative to the zone, lowercase, `@` for the apex (for example `www`, `_acme-challenge.www`).",
				PlanModifiers:       replace,
				Validators:          []validator.String{relativeHost{}},
			},
			"type": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Record type: " + strings.Join(recordTypes, ", ") + ". SOA and apex NS records are locked by EuroDNS and cannot be managed.",
				PlanModifiers:       replace,
				Validators:          []validator.String{stringvalidator.OneOf(append(recordTypes, "SOA")...)}, // SOA refused with an explicit message
			},
			"ttl": schema.Int64Attribute{
				Optional:            true,
				Computed:            true,
				Default:             int64default.StaticInt64(3600),
				MarkdownDescription: "TTL in seconds, one of the values EuroDNS accepts: " + ttlList() + ". Default 3600.",
				Validators:          []validator.Int64{allowedTTL{}},
			},
			"values": schema.SetAttribute{
				Required:    true,
				ElementType: types.StringType,
				MarkdownDescription: "Record data (rdata), one entry per record, sent to EuroDNS as is. Names (CNAME, MX, NS, SRV... targets) " +
					"must end with a dot: EuroDNS treats names without a trailing dot as relative to the zone. TXT values are sent " +
					"raw: do not wrap them in quotes.",
				Validators: []validator.Set{setvalidator.SizeAtLeast(1)},
			},
		},
	}
}

func (r *recordSetResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	api, ok := req.ProviderData.(*apiClient)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data", fmt.Sprintf("got %T", req.ProviderData))
		return
	}
	r.api = api
}

func (m *recordSetModel) key() rrset.Key {
	return rrset.Key{Host: m.Host.ValueString(), Type: m.Type.ValueString()}
}

func (m *recordSetModel) values(ctx context.Context, diags *diag.Diagnostics) []string {
	var v []string
	diags.Append(m.Values.ElementsAs(ctx, &v, false)...)
	sort.Strings(v)
	return v
}

func (r *recordSetResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan recordSetModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	values := plan.values(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	zone, key, ttl := plan.Zone.ValueString(), plan.key(), int(plan.TTL.ValueInt64())

	err := r.api.write(ctx, zone, func(current *eurodns.Zone) (*zonediff.Change, error) {
		if findSet(zone, current, key) != nil {
			return nil, &existsError{zone: zone, key: key}
		}
		return &zonediff.Change{Op: zonediff.OpCreate, Key: key, New: buildSet(key, ttl, values, nil)}, nil
	})
	if err != nil {
		var e *existsError
		if errors.As(err, &e) {
			resp.Diagnostics.AddError("Record set already exists", e.Error())
			return
		}
		addAPIError(&resp.Diagnostics, "Cannot create the record set", err)
		return
	}
	plan.ID = types.StringValue(recordSetID(zone, key))
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *recordSetResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state recordSetModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	zone := state.Zone.ValueString()
	z, err := r.api.zone(ctx, zone)
	if err != nil {
		if eurodns.IsNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		addAPIError(&resp.Diagnostics, "Cannot read the zone", err)
		return
	}
	set := findSet(zone, z, state.key())
	if set == nil {
		resp.State.RemoveResource(ctx)
		return
	}
	state.ID = types.StringValue(recordSetID(zone, state.key()))
	state.TTL = types.Int64Value(int64(set.TTL))
	state.Values = stringSet(set.Values)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *recordSetResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan recordSetModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	values := plan.values(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	zone, key, ttl := plan.Zone.ValueString(), plan.key(), int(plan.TTL.ValueInt64())

	err := r.api.write(ctx, zone, func(current *eurodns.Zone) (*zonediff.Change, error) {
		old := findSet(zone, current, key)
		if old == nil {
			return &zonediff.Change{Op: zonediff.OpCreate, Key: key, New: buildSet(key, ttl, values, nil)}, nil
		}
		return &zonediff.Change{Op: zonediff.OpUpdate, Key: key, Old: old, New: buildSet(key, ttl, values, old)}, nil
	})
	if err != nil {
		addAPIError(&resp.Diagnostics, "Cannot update the record set", err)
		return
	}
	plan.ID = types.StringValue(recordSetID(zone, key))
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *recordSetResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state recordSetModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	zone, key := state.Zone.ValueString(), state.key()
	err := r.api.write(ctx, zone, func(current *eurodns.Zone) (*zonediff.Change, error) {
		old := findSet(zone, current, key)
		if old == nil {
			return nil, nil
		}
		return &zonediff.Change{Op: zonediff.OpDelete, Key: key, Old: old}, nil
	})
	if err != nil && !eurodns.IsNotFound(err) {
		addAPIError(&resp.Diagnostics, "Cannot delete the record set", err)
	}
}

// ImportState accepts "<zone>/<host>/<type>". In gate mode the RRset is
// adopted first, so the gate lets this configuration manage it.
func (r *recordSetResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parts := strings.Split(req.ID, "/")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		resp.Diagnostics.AddError("Invalid import id", fmt.Sprintf("expected <zone>/<host>/<type>, got %q", req.ID))
		return
	}
	zone, host, typ := parts[0], parts[1], strings.ToUpper(parts[2])
	if reason := unmanageableReason(host, typ); reason != "" {
		resp.Diagnostics.AddError("Record set cannot be managed", reason)
		return
	}
	if r.api.mode == modeGate && r.api.hasFeature(eurodns.FeatureAdopt) {
		err := r.api.client.Adopt(ctx, zone, eurodns.AdoptRequest{RRsets: []eurodns.AdoptRRset{{Host: host, Type: typ}}})
		if err != nil {
			addAPIError(&resp.Diagnostics, "The gate refused to adopt the record set", err)
			return
		}
		r.api.invalidate(zone)
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), recordSetID(zone, rrset.Key{Host: host, Type: typ}))...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("zone"), zone)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("host"), host)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("type"), typ)...)
}

type existsError struct {
	zone string
	key  rrset.Key
}

func (e *existsError) Error() string {
	return fmt.Sprintf("%s %s already exists in zone %s and is not managed by this configuration. "+
		"Import it first: terraform import <address> %s", e.key.Host, e.key.Type, e.zone, recordSetID(e.zone, e.key))
}

func stringSet(values []string) types.Set {
	elems := make([]attr.Value, len(values))
	for i, v := range values {
		elems[i] = types.StringValue(v)
	}
	return types.SetValueMust(types.StringType, elems)
}
