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

var _ resource.Resource = &DomainResource{}
var _ resource.ResourceWithImportState = &DomainResource{}

// DomainResource defines the domain resource implementation.
type DomainResource struct {
	client *APIClient
}

// DomainResourceModel describes the resource data model.
type DomainResourceModel struct {
	ID              types.String `tfsdk:"id"`
	Domain          types.String `tfsdk:"domain"`
	TunnelID        types.String `tfsdk:"tunnel_id"`
	Verified        types.Bool   `tfsdk:"verified"`
	VerificationTXT types.String `tfsdk:"verification_txt"`
	Certificate     types.String `tfsdk:"certificate"`
	PrivateKey      types.String `tfsdk:"private_key"`
}

// NewDomainResource creates a new domain resource.
func NewDomainResource() resource.Resource {
	return &DomainResource{}
}

func (r *DomainResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_domain"
}

func (r *DomainResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a custom domain for NLAG tunnels.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The unique identifier of the domain.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"domain": schema.StringAttribute{
				Description: "The custom domain name.",
				Required:    true,
			},
			"tunnel_id": schema.StringAttribute{
				Description: "The ID of the tunnel to route this domain to.",
				Optional:    true,
			},
			"verified": schema.BoolAttribute{
				Description: "Whether the domain ownership has been verified.",
				Computed:    true,
			},
			"verification_txt": schema.StringAttribute{
				Description: "The TXT record value to add for domain verification.",
				Computed:    true,
			},
			"certificate": schema.StringAttribute{
				Description: "Custom TLS certificate (PEM format).",
				Optional:    true,
				Sensitive:   true,
			},
			"private_key": schema.StringAttribute{
				Description: "Custom TLS private key (PEM format).",
				Optional:    true,
				Sensitive:   true,
			},
		},
	}
}

func (r *DomainResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *DomainResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data DomainResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	domain, err := r.client.CreateDomain(DomainRequest{
		Domain:      data.Domain.ValueString(),
		TunnelID:    data.TunnelID.ValueString(),
		Certificate: data.Certificate.ValueString(),
		PrivateKey:  data.PrivateKey.ValueString(),
	})
	if err != nil {
		resp.Diagnostics.AddError("Failed to create domain", err.Error())
		return
	}

	data.ID = types.StringValue(domain.ID)
	data.Verified = types.BoolValue(domain.Verified)
	data.VerificationTXT = types.StringValue(domain.VerificationTXT)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *DomainResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data DomainResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	domain, err := r.client.GetDomain(data.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Failed to read domain", err.Error())
		return
	}

	data.Domain = types.StringValue(domain.Domain)
	data.Verified = types.BoolValue(domain.Verified)
	data.VerificationTXT = types.StringValue(domain.VerificationTXT)
	data.TunnelID = types.StringValue(domain.TunnelID)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *DomainResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	// Domains are immutable, recreate on change
	resp.Diagnostics.AddError("Update not supported", "Domains cannot be updated. Delete and recreate instead.")
}

func (r *DomainResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data DomainResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.client.DeleteDomain(data.ID.ValueString()); err != nil {
		resp.Diagnostics.AddError("Failed to delete domain", err.Error())
		return
	}
}

func (r *DomainResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
