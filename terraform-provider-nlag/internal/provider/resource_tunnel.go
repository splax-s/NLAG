package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure TunnelResource implements resource.Resource.
var _ resource.Resource = &TunnelResource{}
var _ resource.ResourceWithImportState = &TunnelResource{}

// TunnelResource defines the tunnel resource implementation.
type TunnelResource struct {
	client *APIClient
}

// TunnelResourceModel describes the resource data model.
type TunnelResourceModel struct {
	ID        types.String `tfsdk:"id"`
	Protocol  types.String `tfsdk:"protocol"`
	LocalPort types.Int64  `tfsdk:"local_port"`
	Subdomain types.String `tfsdk:"subdomain"`
	PublicURL types.String `tfsdk:"public_url"`
	IPAllow   types.List   `tfsdk:"ip_allow"`
	IPDeny    types.List   `tfsdk:"ip_deny"`
	BasicAuth types.Map    `tfsdk:"basic_auth"`
	Headers   types.Map    `tfsdk:"headers"`
	Region    types.String `tfsdk:"region"`
	State     types.String `tfsdk:"state"`
}

// NewTunnelResource creates a new tunnel resource.
func NewTunnelResource() resource.Resource {
	return &TunnelResource{}
}

// Metadata returns the resource type name.
func (r *TunnelResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_tunnel"
}

// Schema returns the resource schema.
func (r *TunnelResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages an NLAG tunnel. A tunnel exposes a local service to the internet through the NLAG edge network.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The unique identifier of the tunnel.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"protocol": schema.StringAttribute{
				Description: "The protocol for the tunnel. Valid values: http, https, tcp, udp, grpc, websocket.",
				Required:    true,
			},
			"local_port": schema.Int64Attribute{
				Description: "The local port to forward traffic to.",
				Required:    true,
			},
			"subdomain": schema.StringAttribute{
				Description: "The subdomain for the tunnel. If not specified, a random subdomain is assigned.",
				Optional:    true,
				Computed:    true,
			},
			"public_url": schema.StringAttribute{
				Description: "The public URL of the tunnel.",
				Computed:    true,
			},
			"ip_allow": schema.ListAttribute{
				Description: "List of IP addresses or CIDR ranges to allow.",
				Optional:    true,
				ElementType: types.StringType,
			},
			"ip_deny": schema.ListAttribute{
				Description: "List of IP addresses or CIDR ranges to deny.",
				Optional:    true,
				ElementType: types.StringType,
			},
			"basic_auth": schema.MapAttribute{
				Description: "Map of username to password for basic authentication.",
				Optional:    true,
				Sensitive:   true,
				ElementType: types.StringType,
			},
			"headers": schema.MapAttribute{
				Description: "Custom headers to add to requests.",
				Optional:    true,
				ElementType: types.StringType,
			},
			"region": schema.StringAttribute{
				Description: "The region for the tunnel.",
				Optional:    true,
				Computed:    true,
			},
			"state": schema.StringAttribute{
				Description: "The current state of the tunnel.",
				Computed:    true,
			},
		},
	}
}

// Configure sets up the resource client.
func (r *TunnelResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*APIClient)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *APIClient, got: %T", req.ProviderData),
		)
		return
	}

	r.client = client
}

// Create creates a new tunnel.
func (r *TunnelResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data TunnelResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Build request
	tunnelReq := TunnelRequest{
		Protocol:  data.Protocol.ValueString(),
		LocalPort: int(data.LocalPort.ValueInt64()),
		Subdomain: data.Subdomain.ValueString(),
		Region:    data.Region.ValueString(),
	}

	// Handle IP lists
	if !data.IPAllow.IsNull() {
		var ipAllow []string
		data.IPAllow.ElementsAs(ctx, &ipAllow, false)
		tunnelReq.IPAllow = ipAllow
	}

	if !data.IPDeny.IsNull() {
		var ipDeny []string
		data.IPDeny.ElementsAs(ctx, &ipDeny, false)
		tunnelReq.IPDeny = ipDeny
	}

	// Handle maps
	if !data.BasicAuth.IsNull() {
		basicAuth := make(map[string]string)
		data.BasicAuth.ElementsAs(ctx, &basicAuth, false)
		tunnelReq.BasicAuth = basicAuth
	}

	if !data.Headers.IsNull() {
		headers := make(map[string]string)
		data.Headers.ElementsAs(ctx, &headers, false)
		tunnelReq.Headers = headers
	}

	// Create tunnel
	tunnel, err := r.client.CreateTunnel(tunnelReq)
	if err != nil {
		resp.Diagnostics.AddError("Failed to create tunnel", err.Error())
		return
	}

	// Update state
	data.ID = types.StringValue(tunnel.ID)
	data.PublicURL = types.StringValue(tunnel.PublicURL)
	data.Subdomain = types.StringValue(tunnel.Subdomain)
	data.State = types.StringValue(tunnel.State)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Read reads the tunnel state.
func (r *TunnelResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data TunnelResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tunnel, err := r.client.GetTunnel(data.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Failed to read tunnel", err.Error())
		return
	}

	data.PublicURL = types.StringValue(tunnel.PublicURL)
	data.Subdomain = types.StringValue(tunnel.Subdomain)
	data.State = types.StringValue(tunnel.State)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Update updates the tunnel.
func (r *TunnelResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data TunnelResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tunnelReq := TunnelRequest{
		Protocol:  data.Protocol.ValueString(),
		LocalPort: int(data.LocalPort.ValueInt64()),
		Subdomain: data.Subdomain.ValueString(),
		Region:    data.Region.ValueString(),
	}

	if !data.IPAllow.IsNull() {
		var ipAllow []string
		data.IPAllow.ElementsAs(ctx, &ipAllow, false)
		tunnelReq.IPAllow = ipAllow
	}

	if !data.IPDeny.IsNull() {
		var ipDeny []string
		data.IPDeny.ElementsAs(ctx, &ipDeny, false)
		tunnelReq.IPDeny = ipDeny
	}

	if !data.BasicAuth.IsNull() {
		basicAuth := make(map[string]string)
		data.BasicAuth.ElementsAs(ctx, &basicAuth, false)
		tunnelReq.BasicAuth = basicAuth
	}

	if !data.Headers.IsNull() {
		headers := make(map[string]string)
		data.Headers.ElementsAs(ctx, &headers, false)
		tunnelReq.Headers = headers
	}

	tunnel, err := r.client.UpdateTunnel(data.ID.ValueString(), tunnelReq)
	if err != nil {
		resp.Diagnostics.AddError("Failed to update tunnel", err.Error())
		return
	}

	data.PublicURL = types.StringValue(tunnel.PublicURL)
	data.State = types.StringValue(tunnel.State)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Delete deletes the tunnel.
func (r *TunnelResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data TunnelResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.client.DeleteTunnel(data.ID.ValueString()); err != nil {
		resp.Diagnostics.AddError("Failed to delete tunnel", err.Error())
		return
	}
}

// ImportState imports an existing tunnel.
func (r *TunnelResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
