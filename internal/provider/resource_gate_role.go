package provider

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// gateNameRe is the name syntax of gate roles, bindings and teams.
var gateNameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?$`)

var (
	_ resource.ResourceWithConfigure   = (*gateRoleResource)(nil)
	_ resource.ResourceWithImportState = (*gateRoleResource)(nil)
)

type gateRoleResource struct {
	api *apiClient
}

func newGateRoleResource() resource.Resource { return &gateRoleResource{} }

type gateRoleModel struct {
	ID           types.String    `tfsdk:"id"`
	Name         types.String    `tfsdk:"name"`
	Description  types.String    `tfsdk:"description"`
	Rules        []gateRuleModel `tfsdk:"rules"`
	RebaseOnSave types.Bool      `tfsdk:"rebase_on_save"`
	EphemeralTTL types.String    `tfsdk:"ephemeral_ttl"`
	MaxChanges   types.Int64     `tfsdk:"max_changes_per_request"`
	Delegation   types.String    `tfsdk:"delegation"`
	ETag         types.String    `tfsdk:"etag"`
}

type gateRuleModel struct {
	Zones   []string `tfsdk:"zones"`
	Actions []string `tfsdk:"actions"`
	Hosts   []string `tfsdk:"hosts"`
	Types   []string `tfsdk:"types"`
}

func (r *gateRoleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_gate_role"
}

// nameAttribute is the stable name of a delegated object.
func nameAttribute(kind string) schema.StringAttribute {
	return schema.StringAttribute{
		Required: true,
		MarkdownDescription: fmt.Sprintf("Name of the %s in the gate, a lowercase identifier (`[a-z0-9._-]`, up to 64 characters). "+
			"Changing it replaces the %s.", kind, kind),
		PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
		Validators:    []validator.String{stringvalidator.RegexMatches(gateNameRe, "must be a lowercase identifier")},
	}
}

// commonDelegatedAttributes are id, delegation and etag.
func commonDelegatedAttributes(kind string) map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"id": schema.StringAttribute{
			Computed:            true,
			MarkdownDescription: "The name.",
			PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
		},
		"delegation": schema.StringAttribute{
			Optional: true,
			Computed: true,
			MarkdownDescription: fmt.Sprintf("Gate delegation (`policy.delegations[].name`) that owns the %s. Needed only when the "+
				"provider identity matches several delegations; otherwise the gate picks the only one. Changing it replaces the %s.", kind, kind),
			PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown(), stringplanmodifier.RequiresReplaceIfConfigured()},
		},
		"etag": schema.StringAttribute{
			Computed:            true,
			MarkdownDescription: fmt.Sprintf("Version of the %s in the gate, sent back as `If-Match` on updates so that a concurrent change is detected.", kind),
		},
	}
}

func (r *gateRoleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	nonEmpty := []validator.List{listvalidator.SizeAtLeast(1)}
	attrs := commonDelegatedAttributes("role")
	attrs["name"] = nameAttribute("role")
	attrs["description"] = schema.StringAttribute{
		Optional:            true,
		MarkdownDescription: "Free text shown in the gate UI.",
		Validators:          []validator.String{stringvalidator.LengthBetween(1, 500)},
	}
	attrs["rules"] = schema.ListNestedAttribute{
		Required: true,
		MarkdownDescription: "Grants of the role. Each rule must stay within the delegation of the provider identity " +
			"(`allow.zones`, `allow.actions`, `allow.records`) and within `policy.bounds` of the gate.",
		Validators: nonEmpty,
		NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
			"zones": schema.ListAttribute{
				Required: true, ElementType: types.StringType, Validators: nonEmpty,
				MarkdownDescription: "Zone globs (`*` wildcards), for example `example.com` or `*.example.com`.",
			},
			"actions": schema.ListAttribute{
				Required: true, ElementType: types.StringType, Validators: nonEmpty,
				MarkdownDescription: "Actions: `dns.read`, `dns.record.write`, `dns.record.adopt`, `dns.zone.admin`, `domain.read`, `ui.read` " +
					"(as far as the delegation allows; `policy.*` actions are never delegated).",
			},
			"hosts": schema.ListAttribute{
				Optional: true, ElementType: types.StringType, Validators: nonEmpty,
				MarkdownDescription: "Host patterns relative to the zone: `@` is the apex, `*` one label, `**` one or more labels. " +
					"Omit to cover every host (if the delegation allows it).",
			},
			"types": schema.ListAttribute{
				Optional: true, ElementType: types.StringType, Validators: nonEmpty,
				MarkdownDescription: "Record types, `*` for any. Omit to cover every type (if the delegation allows it).",
			},
		}},
	}
	attrs["rebase_on_save"] = schema.BoolAttribute{
		Optional: true, Computed: true, Default: booldefault.StaticBool(false),
		MarkdownDescription: "On a full-zone PUT, ignore differences outside the role's scope instead of refusing them (stale zones sent by ACME clients). Default `false`.",
	}
	attrs["ephemeral_ttl"] = schema.StringAttribute{
		Optional:            true,
		MarkdownDescription: "Go duration after which the RRsets created through the role expire and are removed by the gate (ACME challenges), for example `24h`.",
		Validators:          []validator.String{durationString{}},
	}
	attrs["max_changes_per_request"] = schema.Int64Attribute{
		Optional: true, Computed: true, Default: int64default.StaticInt64(0),
		MarkdownDescription: "Blast-radius limit (RRset changes per request), `0` for the gate default, at most 1000.",
	}
	resp.Schema = schema.Schema{
		MarkdownDescription: "A role of the dns-gate managed policy, owned by a policy delegation of the gate (gate mode only). " +
			"The gate validates it against the delegation of the provider identity and activates the change at once, " +
			"without approval. Bind it with `eurodns_gate_binding`.",
		Attributes: attrs,
	}
}

func (r *gateRoleResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	api, ok := req.ProviderData.(*apiClient)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data", fmt.Sprintf("got %T", req.ProviderData))
		return
	}
	if !api.requireDelegation(&resp.Diagnostics, "eurodns_gate_role") {
		return
	}
	r.api = api
}

type gateRoleRequest struct {
	gateRole
	Delegation string `json:"delegation,omitempty"`
	ManagedBy  string `json:"managed_by,omitempty"`
}

func (m *gateRoleModel) request() gateRoleRequest {
	req := gateRoleRequest{
		gateRole: gateRole{
			Description:          m.Description.ValueString(),
			RebaseOnSave:         m.RebaseOnSave.ValueBool(),
			EphemeralTTL:         m.EphemeralTTL.ValueString(),
			MaxChangesPerRequest: int(m.MaxChanges.ValueInt64()),
			Rules:                []gateRule{},
		},
		Delegation: m.Delegation.ValueString(),
		ManagedBy:  managedBy,
	}
	for _, rule := range m.Rules {
		gr := gateRule{Zones: rule.Zones, Actions: rule.Actions}
		if len(rule.Hosts) > 0 || len(rule.Types) > 0 {
			gr.Records = &gateRecordScope{Hosts: rule.Hosts, Types: rule.Types}
		}
		req.Rules = append(req.Rules, gr)
	}
	return req
}

func (m *gateRoleModel) fromObject(obj *gateObject) {
	m.ID, m.Name = types.StringValue(obj.Name), types.StringValue(obj.Name)
	m.Delegation, m.ETag = types.StringValue(obj.Owner.Delegation), types.StringValue(obj.ETag)
	role := obj.Role
	if role == nil {
		role = &gateRole{}
	}
	m.Description = optionalString(role.Description)
	m.EphemeralTTL = optionalString(role.EphemeralTTL)
	m.RebaseOnSave = types.BoolValue(role.RebaseOnSave)
	m.MaxChanges = types.Int64Value(int64(role.MaxChangesPerRequest))
	m.Rules = make([]gateRuleModel, 0, len(role.Rules))
	for _, rule := range role.Rules {
		rm := gateRuleModel{Zones: rule.Zones, Actions: rule.Actions}
		if rule.Records != nil {
			rm.Hosts, rm.Types = nilIfEmpty(rule.Records.Hosts), nilIfEmpty(rule.Records.Types)
		}
		m.Rules = append(m.Rules, rm)
	}
}

func optionalString(s string) types.String {
	if s == "" {
		return types.StringNull()
	}
	return types.StringValue(s)
}

func nilIfEmpty(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return s
}

func (r *gateRoleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan gateRoleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	putDelegated(ctx, r.api, "role", plan.Name.ValueString(), ifNoneMatchAny(), plan.request(), true, &resp.Diagnostics, func(obj *gateObject) {
		plan.fromObject(obj)
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	})
}

func (r *gateRoleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state gateRoleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	obj := readDelegated(ctx, r.api, "role", state.Name.ValueString(), &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if obj == nil {
		resp.State.RemoveResource(ctx)
		return
	}
	state.fromObject(obj)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *gateRoleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state gateRoleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	putDelegated(ctx, r.api, "role", plan.Name.ValueString(), ifMatch(state.ETag.ValueString()), plan.request(), false, &resp.Diagnostics, func(obj *gateObject) {
		plan.fromObject(obj)
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	})
}

func (r *gateRoleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state gateRoleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	deleteDelegated(ctx, r.api, "role", state.Name.ValueString(), &resp.Diagnostics)
}

func (r *gateRoleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	importByName(ctx, req, resp)
}

// Shared CRUD steps of the delegated resources.

func importByName(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	if !gateNameRe.MatchString(req.ID) {
		resp.Diagnostics.AddError("Invalid import id", fmt.Sprintf("expected the name of the object in the gate (a lowercase identifier), got %q", req.ID))
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
}

func readDelegated(ctx context.Context, api *apiClient, kind, name string, diags *diag.Diagnostics) *gateObject {
	obj, err := api.getDelegated(ctx, kind, name)
	if err != nil {
		addGatePolicyError(diags, fmt.Sprintf("Cannot read gate %s %s", kind, name), err)
		return nil
	}
	if obj == nil {
		tflog.Info(ctx, "delegated object not found in the gate (deleted, or taken over by an administrator)", map[string]any{"kind": kind, "name": name})
	}
	return obj
}

func putDelegated(ctx context.Context, api *apiClient, kind, name string, hdr http.Header, body any, create bool, diags *diag.Diagnostics, done func(*gateObject)) {
	res, err := api.writeDelegated(ctx, http.MethodPut, kind, name, hdr, body)
	if err != nil {
		if !preconditionDiag(diags, kind, name, create, err) {
			addGatePolicyError(diags, fmt.Sprintf("Cannot write gate %s %s", kind, name), err)
		}
		return
	}
	if res.Object == nil {
		diags.AddError(fmt.Sprintf("Cannot write gate %s %s", kind, name), "the gate answered without the object")
		return
	}
	done(res.Object)
}

func deleteDelegated(ctx context.Context, api *apiClient, kind, name string, diags *diag.Diagnostics) {
	_, err := api.writeDelegated(ctx, http.MethodDelete, kind, name, nil, nil)
	if status, _ := gateStatus(err); status == http.StatusNotFound {
		return
	}
	if err != nil {
		addGatePolicyError(diags, fmt.Sprintf("Cannot delete gate %s %s", kind, name), err)
	}
}

// durationString validates a Go duration.
type durationString struct{}

func (durationString) Description(context.Context) string {
	return "must be a Go duration, for example 24h"
}
func (v durationString) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (durationString) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	if d, err := time.ParseDuration(req.ConfigValue.ValueString()); err != nil || d <= 0 {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid duration", fmt.Sprintf("%q is not a positive Go duration (for example 24h).", req.ConfigValue.ValueString()))
	}
}
