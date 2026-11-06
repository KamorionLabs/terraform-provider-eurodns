package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/mapvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.ResourceWithConfigure   = (*gateBindingResource)(nil)
	_ resource.ResourceWithImportState = (*gateBindingResource)(nil)
)

type gateBindingResource struct {
	api *apiClient
}

func newGateBindingResource() resource.Resource { return &gateBindingResource{} }

type gateBindingModel struct {
	ID         types.String       `tfsdk:"id"`
	Name       types.String       `tfsdk:"name"`
	Role       types.String       `tfsdk:"role"`
	Team       types.String       `tfsdk:"team"`
	TeamFrom   *gateTeamFromModel `tfsdk:"team_from"`
	Subjects   []gateSubjectModel `tfsdk:"subjects"`
	Groups     []string           `tfsdk:"groups"`
	Delegation types.String       `tfsdk:"delegation"`
	ETag       types.String       `tfsdk:"etag"`
}

type gateTeamFromModel struct {
	Claim  types.String `tfsdk:"claim"`
	Regex  types.String `tfsdk:"regex"`
	Prefix types.String `tfsdk:"prefix"`
}

type gateSubjectModel struct {
	Issuer types.String        `tfsdk:"issuer"`
	Claims map[string][]string `tfsdk:"claims"`
}

func (r *gateBindingResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_gate_binding"
}

func (r *gateBindingResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	attrs := commonDelegatedAttributes("binding")
	attrs["name"] = nameAttribute("binding")
	attrs["role"] = schema.StringAttribute{
		Required: true,
		MarkdownDescription: "Role granted: an `eurodns_gate_role` of the same delegation, or a base or managed role " +
			"listed in the `allow.roles` of the delegation.",
		Validators: []validator.String{stringvalidator.RegexMatches(gateNameRe, "must be a lowercase identifier")},
	}
	attrs["team"] = schema.StringAttribute{
		Optional: true,
		MarkdownDescription: "Owner team of the RRsets created through the binding. Allowed when it matches the " +
			"`allow.teams.names` of the delegation, or when it is the team that `allow.teams.from_subject` derives from the " +
			"single, literal subject claim of the binding (\"team from the subject\"). Exactly one of `team` and `team_from`.",
		Validators: []validator.String{
			stringvalidator.RegexMatches(gateNameRe, "must be a lowercase identifier"),
			stringvalidator.ExactlyOneOf(path.MatchRoot("team"), path.MatchRoot("team_from")),
		},
	}
	attrs["team_from"] = schema.SingleNestedAttribute{
		Optional: true,
		MarkdownDescription: "Derive the team of each subject from one of its claims; must be exactly the " +
			"`allow.teams.from_subject` rule of the delegation.",
		Attributes: map[string]schema.Attribute{
			"claim":  schema.StringAttribute{Required: true, MarkdownDescription: "String claim, typically `sub`."},
			"regex":  schema.StringAttribute{Required: true, MarkdownDescription: "Anchored RE2 expression with exactly one capture group."},
			"prefix": schema.StringAttribute{Optional: true, MarkdownDescription: "Prefix of the derived team."},
		},
	}
	attrs["subjects"] = schema.ListNestedAttribute{
		Optional: true,
		MarkdownDescription: "Identities bound, each an issuer of the gate plus claim globs that must all match. Each must be " +
			"covered by the `allow.binding_subjects` of the delegation. At least one of `subjects` and `groups`.",
		Validators: []validator.List{
			listvalidator.SizeAtLeast(1),
			listvalidator.AtLeastOneOf(path.MatchRoot("subjects"), path.MatchRoot("groups")),
		},
		NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
			"issuer": schema.StringAttribute{Required: true, MarkdownDescription: "Issuer name in the gate configuration (`issuers[].name`)."},
			"claims": schema.MapAttribute{
				Required:            true,
				ElementType:         types.ListType{ElemType: types.StringType},
				MarkdownDescription: "Claim name to accepted globs, for example `{ sub = [\"sc://org/project/dns-gate-web\"] }`.",
				Validators:          []validator.Map{mapvalidator.SizeAtLeast(1)},
			},
		}},
	}
	attrs["groups"] = schema.ListAttribute{
		Optional:            true,
		ElementType:         types.StringType,
		MarkdownDescription: "Gate groups whose members are bound, among the `allow.groups` of the delegation.",
		Validators:          []validator.List{listvalidator.SizeAtLeast(1)},
	}
	resp.Schema = schema.Schema{
		MarkdownDescription: "A binding of the dns-gate managed policy, owned by a policy delegation of the gate " +
			"(gate mode only): it grants a role, acting for a team, to identities. The gate validates it against the " +
			"delegation of the provider identity and activates the change at once, without approval.\n\n" +
			"~> **Deprecated:** gate policy objects now belong to the `dnsgate_binding` resource of the " +
			"[KamorionLabs/dnsgate](https://github.com/KamorionLabs/terraform-provider-dnsgate) provider, " +
			"which works with every DNS provider of dns-gate. This resource keeps working.",
		DeprecationMessage: "Use dnsgate_binding of the KamorionLabs/dnsgate provider. The gate object stays the same: " +
			"forget it here with a removed block (lifecycle { destroy = false }) and import it into dnsgate_binding by name.",
		Attributes: attrs,
	}
}

func (r *gateBindingResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	api, ok := req.ProviderData.(*apiClient)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data", fmt.Sprintf("got %T", req.ProviderData))
		return
	}
	if !api.requireDelegation(&resp.Diagnostics, "eurodns_gate_binding") {
		return
	}
	r.api = api
}

type gateBindingRequest struct {
	gateBinding
	Delegation string `json:"delegation,omitempty"`
	ManagedBy  string `json:"managed_by,omitempty"`
}

func (m *gateBindingModel) request() gateBindingRequest {
	req := gateBindingRequest{
		gateBinding: gateBinding{Role: m.Role.ValueString(), Team: m.Team.ValueString(), Groups: m.Groups},
		Delegation:  m.Delegation.ValueString(),
		ManagedBy:   managedBy,
	}
	if m.TeamFrom != nil {
		req.TeamFrom = &gateTeamFrom{Claim: m.TeamFrom.Claim.ValueString(), Regex: m.TeamFrom.Regex.ValueString(), Prefix: m.TeamFrom.Prefix.ValueString()}
	}
	for _, s := range m.Subjects {
		req.Subjects = append(req.Subjects, gateSubject{Issuer: s.Issuer.ValueString(), Claims: s.Claims})
	}
	return req
}

func (m *gateBindingModel) fromObject(obj *gateObject) {
	m.ID, m.Name = types.StringValue(obj.Name), types.StringValue(obj.Name)
	m.Delegation, m.ETag = types.StringValue(obj.Owner.Delegation), types.StringValue(obj.ETag)
	b := obj.Binding
	if b == nil {
		b = &gateBinding{}
	}
	m.Role, m.Team = types.StringValue(b.Role), optionalString(b.Team)
	m.TeamFrom = nil
	if b.TeamFrom != nil {
		m.TeamFrom = &gateTeamFromModel{Claim: types.StringValue(b.TeamFrom.Claim), Regex: types.StringValue(b.TeamFrom.Regex), Prefix: optionalString(b.TeamFrom.Prefix)}
	}
	m.Groups = nilIfEmpty(b.Groups)
	m.Subjects = nil
	for _, s := range b.Subjects {
		m.Subjects = append(m.Subjects, gateSubjectModel{Issuer: types.StringValue(s.Issuer), Claims: s.Claims})
	}
}

func (r *gateBindingResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan gateBindingModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	putDelegated(ctx, r.api, "binding", plan.Name.ValueString(), ifNoneMatchAny(), plan.request(), true, &resp.Diagnostics, func(obj *gateObject) {
		plan.fromObject(obj)
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	})
}

func (r *gateBindingResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state gateBindingModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	obj := readDelegated(ctx, r.api, "binding", state.Name.ValueString(), &resp.Diagnostics)
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

func (r *gateBindingResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state gateBindingModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	putDelegated(ctx, r.api, "binding", plan.Name.ValueString(), ifMatch(state.ETag.ValueString()), plan.request(), false, &resp.Diagnostics, func(obj *gateObject) {
		plan.fromObject(obj)
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	})
}

func (r *gateBindingResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state gateBindingModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	deleteDelegated(ctx, r.api, "binding", state.Name.ValueString(), &resp.Diagnostics)
}

func (r *gateBindingResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	importByName(ctx, req, resp)
}
