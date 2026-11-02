package provider

import (
	"context"
	"fmt"
	"sort"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/KamorionLabs/eurodns-go/rrset"
)

func configureDataSource(req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) *apiClient {
	if req.ProviderData == nil {
		return nil
	}
	api, ok := req.ProviderData.(*apiClient)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data", fmt.Sprintf("got %T", req.ProviderData))
	}
	return api
}

// eurodns_zone

type zoneDataSource struct{ api *apiClient }

func newZoneDataSource() datasource.DataSource { return &zoneDataSource{} }

type zoneRecordModel struct {
	ID     types.Int64  `tfsdk:"id"`
	Host   types.String `tfsdk:"host"`
	Type   types.String `tfsdk:"type"`
	TTL    types.Int64  `tfsdk:"ttl"`
	RData  types.String `tfsdk:"rdata"`
	Locked types.Bool   `tfsdk:"locked"`
}

type zoneDataModel struct {
	Zone    types.String      `tfsdk:"zone"`
	Records []zoneRecordModel `tfsdk:"records"`
}

func (d *zoneDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_zone"
}

func (d *zoneDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "All DNS records of a EuroDNS zone (URL and mail forwards excluded).",
		Attributes: map[string]schema.Attribute{
			"zone": schema.StringAttribute{Required: true, MarkdownDescription: "Zone name, for example `example.com`."},
			"records": schema.ListNestedAttribute{
				Computed:            true,
				MarkdownDescription: "Records sorted by host, type and rdata.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id":     schema.Int64Attribute{Computed: true, MarkdownDescription: "EuroDNS record id."},
						"host":   schema.StringAttribute{Computed: true, MarkdownDescription: "Host relative to the zone, `@` for the apex."},
						"type":   schema.StringAttribute{Computed: true},
						"ttl":    schema.Int64Attribute{Computed: true},
						"rdata":  schema.StringAttribute{Computed: true},
						"locked": schema.BoolAttribute{Computed: true, MarkdownDescription: "Locked by EuroDNS, cannot be changed."},
					},
				},
			},
		},
	}
}

func (d *zoneDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.api = configureDataSource(req, resp)
}

func (d *zoneDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data zoneDataModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	zone := data.Zone.ValueString()
	z, err := d.api.zone(ctx, zone)
	if err != nil {
		addAPIError(&resp.Diagnostics, "Cannot read the zone", err)
		return
	}
	data.Records = make([]zoneRecordModel, 0, len(z.Records))
	for _, r := range z.Records {
		m := zoneRecordModel{
			ID:     types.Int64Null(),
			Host:   types.StringValue(rrset.NormalizeHost(r.Host, zone)),
			Type:   types.StringValue(r.Type),
			TTL:    types.Int64Value(int64(r.TTL)),
			RData:  types.StringValue(r.RData),
			Locked: types.BoolValue(r.Locked != nil && *r.Locked),
		}
		if r.ID != nil {
			m.ID = types.Int64Value(*r.ID)
		}
		data.Records = append(data.Records, m)
	}
	sort.SliceStable(data.Records, func(i, j int) bool {
		a, b := data.Records[i], data.Records[j]
		if a.Host.ValueString() != b.Host.ValueString() {
			return a.Host.ValueString() < b.Host.ValueString()
		}
		if a.Type.ValueString() != b.Type.ValueString() {
			return a.Type.ValueString() < b.Type.ValueString()
		}
		return a.RData.ValueString() < b.RData.ValueString()
	})
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// eurodns_record_set

type recordSetDataSource struct{ api *apiClient }

func newRecordSetDataSource() datasource.DataSource { return &recordSetDataSource{} }

type recordSetDataModel struct {
	ID     types.String `tfsdk:"id"`
	Zone   types.String `tfsdk:"zone"`
	Host   types.String `tfsdk:"host"`
	Type   types.String `tfsdk:"type"`
	TTL    types.Int64  `tfsdk:"ttl"`
	Values types.Set    `tfsdk:"values"`
}

func (d *recordSetDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_record_set"
}

func (d *recordSetDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "One RRset (all records of a name and type) of a EuroDNS zone. Fails if it does not exist.",
		Attributes: map[string]schema.Attribute{
			"id":     schema.StringAttribute{Computed: true, MarkdownDescription: "`<zone>/<host>/<type>`."},
			"zone":   schema.StringAttribute{Required: true},
			"host":   schema.StringAttribute{Required: true, MarkdownDescription: "Host relative to the zone, `@` for the apex."},
			"type":   schema.StringAttribute{Required: true},
			"ttl":    schema.Int64Attribute{Computed: true},
			"values": schema.SetAttribute{Computed: true, ElementType: types.StringType},
		},
	}
}

func (d *recordSetDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.api = configureDataSource(req, resp)
}

func (d *recordSetDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data recordSetDataModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	zone := data.Zone.ValueString()
	key := rrset.Key{Host: keyHost(data.Host.ValueString(), zone), Type: data.Type.ValueString()}
	z, err := d.api.zone(ctx, zone)
	if err != nil {
		addAPIError(&resp.Diagnostics, "Cannot read the zone", err)
		return
	}
	set := findSet(zone, z, key)
	if set == nil {
		resp.Diagnostics.AddError("Record set not found", fmt.Sprintf("No %s record named %s in zone %s.", key.Type, key.Host, zone))
		return
	}
	data.ID = types.StringValue(recordSetID(zone, key))
	data.TTL = types.Int64Value(int64(set.TTL))
	data.Values = stringSet(set.Values)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
