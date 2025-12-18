package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ resource.Resource = &IPRestrictionResource{}

// IPRestrictionResource defines the IP restriction resource implementation.
type IPRestrictionResource struct {
	client *APIClient
}

// IPRestrictionResourceModel describes the resource data model.
type IPRestrictionResourceModel struct {
	ID          types.String `tfsdk:"id"`
	TunnelID    types.String `tfsdk:"tunnel_id"`
	Type        types.String `tfsdk:"type"`
	CIDR        types.String `tfsdk:"cidr"`
	Description types.String `tfsdk:"description"`
}

// NewIPRestrictionResource creates a new IP restriction resource.
func NewIPRestrictionResource() resource.Resource {
	return &IPRestrictionResource{}
}

func (r *IPRestrictionResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_ip_restriction"
}

func (r *IPRestrictionResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages IP restrictions for NLAG tunnels.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The unique identifier of the IP restriction.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"tunnel_id": schema.StringAttribute{
				Description: "The ID of the tunnel this restriction applies to.",
				Required:    true,
			},
			"type": schema.StringAttribute{
				Description: "The type of restriction: 'allow' or 'deny'.",
				Required:    true,
			},
			"cidr": schema.StringAttribute{
				Description: "The CIDR range to allow or deny (e.g., '10.0.0.0/8').",
				Required:    true,
			},
			"description": schema.StringAttribute{
				Description: "A description for this restriction.",
				Optional:    true,
			},
		},
	}
}

func (r *IPRestrictionResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*APIClient)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Resource Configure Type", fmt.Sprintf("Expected *APIClient, got: %T", req.ProviderData))
		return
	}
	r.client = client
}

func (r *IPRestrictionResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data IPRestrictionResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get current tunnel
	tunnel, err := r.client.GetTunnel(data.TunnelID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Failed to get tunnel", err.Error())
		return
	}

	// Add restriction
	var ipList []string
	if data.Type.ValueString() == "allow" {
		ipList = append(tunnel.IPAllow, data.CIDR.ValueString())
	} else {
		ipList = append(tunnel.IPDeny, data.CIDR.ValueString())
	}

	updateReq := TunnelRequest{
		Protocol:  tunnel.Protocol,
		LocalPort: 0, // Not changed
		IPAllow:   tunnel.IPAllow,
		IPDeny:    tunnel.IPDeny,
	}

	if data.Type.ValueString() == "allow" {
		updateReq.IPAllow = ipList
	} else {
		updateReq.IPDeny = ipList
	}

	_, err = r.client.UpdateTunnel(data.TunnelID.ValueString(), updateReq)
	if err != nil {
		resp.Diagnostics.AddError("Failed to add IP restriction", err.Error())
		return
	}

	// Generate ID
	data.ID = types.StringValue(fmt.Sprintf("%s-%s-%s", data.TunnelID.ValueString(), data.Type.ValueString(), data.CIDR.ValueString()))

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *IPRestrictionResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data IPRestrictionResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tunnel, err := r.client.GetTunnel(data.TunnelID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Failed to read tunnel", err.Error())
		return
	}

	// Check if restriction still exists
	found := false
	if data.Type.ValueString() == "allow" {
		for _, ip := range tunnel.IPAllow {
			if ip == data.CIDR.ValueString() {
				found = true
				break
			}
		}
	} else {
		for _, ip := range tunnel.IPDeny {
			if ip == data.CIDR.ValueString() {
				found = true
				break
			}
		}
	}

	if !found {
		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *IPRestrictionResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError("Update not supported", "IP restrictions cannot be updated. Delete and recreate instead.")
}

func (r *IPRestrictionResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data IPRestrictionResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tunnel, err := r.client.GetTunnel(data.TunnelID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Failed to get tunnel", err.Error())
		return
	}

	// Remove restriction
	updateReq := TunnelRequest{
		Protocol: tunnel.Protocol,
		IPAllow:  tunnel.IPAllow,
		IPDeny:   tunnel.IPDeny,
	}

	if data.Type.ValueString() == "allow" {
		var newList []string
		for _, ip := range tunnel.IPAllow {
			if ip != data.CIDR.ValueString() {
				newList = append(newList, ip)
			}
		}
		updateReq.IPAllow = newList
	} else {
		var newList []string
		for _, ip := range tunnel.IPDeny {
			if ip != data.CIDR.ValueString() {
				newList = append(newList, ip)
			}
		}
		updateReq.IPDeny = newList
	}

	_, err = r.client.UpdateTunnel(data.TunnelID.ValueString(), updateReq)
	if err != nil {
		resp.Diagnostics.AddError("Failed to remove IP restriction", err.Error())
		return
	}
}
