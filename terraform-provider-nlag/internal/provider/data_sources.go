package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ datasource.DataSource = &TunnelDataSource{}

// TunnelDataSource defines the data source implementation.
type TunnelDataSource struct {
	client *APIClient
}

// TunnelDataSourceModel describes the data source model.
type TunnelDataSourceModel struct {
	ID        types.String `tfsdk:"id"`
	Protocol  types.String `tfsdk:"protocol"`
	PublicURL types.String `tfsdk:"public_url"`
	Subdomain types.String `tfsdk:"subdomain"`
	State     types.String `tfsdk:"state"`
}

// NewTunnelDataSource creates a new tunnel data source.
func NewTunnelDataSource() datasource.DataSource {
	return &TunnelDataSource{}
}

func (d *TunnelDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_tunnel"
}

func (d *TunnelDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Fetches information about an existing NLAG tunnel.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The ID of the tunnel to fetch.",
				Required:    true,
			},
			"protocol": schema.StringAttribute{
				Description: "The protocol of the tunnel.",
				Computed:    true,
			},
			"public_url": schema.StringAttribute{
				Description: "The public URL of the tunnel.",
				Computed:    true,
			},
			"subdomain": schema.StringAttribute{
				Description: "The subdomain of the tunnel.",
				Computed:    true,
			},
			"state": schema.StringAttribute{
				Description: "The current state of the tunnel.",
				Computed:    true,
			},
		},
	}
}

func (d *TunnelDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*APIClient)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Data Source Configure Type", fmt.Sprintf("Expected *APIClient, got: %T", req.ProviderData))
		return
	}
	d.client = client
}

func (d *TunnelDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data TunnelDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tunnel, err := d.client.GetTunnel(data.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Failed to read tunnel", err.Error())
		return
	}

	data.Protocol = types.StringValue(tunnel.Protocol)
	data.PublicURL = types.StringValue(tunnel.PublicURL)
	data.Subdomain = types.StringValue(tunnel.Subdomain)
	data.State = types.StringValue(tunnel.State)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// DomainsDataSource

var _ datasource.DataSource = &DomainsDataSource{}

type DomainsDataSource struct {
	client *APIClient
}

type DomainModel struct {
	ID       types.String `tfsdk:"id"`
	Domain   types.String `tfsdk:"domain"`
	Verified types.Bool   `tfsdk:"verified"`
	TunnelID types.String `tfsdk:"tunnel_id"`
}

type DomainsDataSourceModel struct {
	Domains []DomainModel `tfsdk:"domains"`
}

func NewDomainsDataSource() datasource.DataSource {
	return &DomainsDataSource{}
}

func (d *DomainsDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_domains"
}

func (d *DomainsDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Fetches all configured domains.",
		Attributes: map[string]schema.Attribute{
			"domains": schema.ListNestedAttribute{
				Description: "List of domains.",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Description: "The domain ID.",
							Computed:    true,
						},
						"domain": schema.StringAttribute{
							Description: "The domain name.",
							Computed:    true,
						},
						"verified": schema.BoolAttribute{
							Description: "Whether the domain is verified.",
							Computed:    true,
						},
						"tunnel_id": schema.StringAttribute{
							Description: "The associated tunnel ID.",
							Computed:    true,
						},
					},
				},
			},
		},
	}
}

func (d *DomainsDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*APIClient)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Data Source Configure Type", fmt.Sprintf("Expected *APIClient, got: %T", req.ProviderData))
		return
	}
	d.client = client
}

func (d *DomainsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	domains, err := d.client.ListDomains()
	if err != nil {
		resp.Diagnostics.AddError("Failed to list domains", err.Error())
		return
	}

	var data DomainsDataSourceModel
	for _, domain := range domains {
		data.Domains = append(data.Domains, DomainModel{
			ID:       types.StringValue(domain.ID),
			Domain:   types.StringValue(domain.Domain),
			Verified: types.BoolValue(domain.Verified),
			TunnelID: types.StringValue(domain.TunnelID),
		})
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// RegionsDataSource

var _ datasource.DataSource = &RegionsDataSource{}

type RegionsDataSource struct {
	client *APIClient
}

type RegionModel struct {
	ID        types.String `tfsdk:"id"`
	Name      types.String `tfsdk:"name"`
	Location  types.String `tfsdk:"location"`
	Available types.Bool   `tfsdk:"available"`
}

type RegionsDataSourceModel struct {
	Regions []RegionModel `tfsdk:"regions"`
}

func NewRegionsDataSource() datasource.DataSource {
	return &RegionsDataSource{}
}

func (d *RegionsDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_regions"
}

func (d *RegionsDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Fetches all available NLAG regions.",
		Attributes: map[string]schema.Attribute{
			"regions": schema.ListNestedAttribute{
				Description: "List of regions.",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Description: "The region ID.",
							Computed:    true,
						},
						"name": schema.StringAttribute{
							Description: "The region name.",
							Computed:    true,
						},
						"location": schema.StringAttribute{
							Description: "The geographic location.",
							Computed:    true,
						},
						"available": schema.BoolAttribute{
							Description: "Whether the region is available.",
							Computed:    true,
						},
					},
				},
			},
		},
	}
}

func (d *RegionsDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*APIClient)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Data Source Configure Type", fmt.Sprintf("Expected *APIClient, got: %T", req.ProviderData))
		return
	}
	d.client = client
}

func (d *RegionsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	regions, err := d.client.ListRegions()
	if err != nil {
		resp.Diagnostics.AddError("Failed to list regions", err.Error())
		return
	}

	var data RegionsDataSourceModel
	for _, region := range regions {
		data.Regions = append(data.Regions, RegionModel{
			ID:        types.StringValue(region.ID),
			Name:      types.StringValue(region.Name),
			Location:  types.StringValue(region.Location),
			Available: types.BoolValue(region.Available),
		})
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
