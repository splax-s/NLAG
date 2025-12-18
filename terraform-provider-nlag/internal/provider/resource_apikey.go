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

var _ resource.Resource = &APIKeyResource{}
var _ resource.ResourceWithImportState = &APIKeyResource{}

// APIKeyResource defines the API key resource implementation.
type APIKeyResource struct {
	client *APIClient
}

// APIKeyResourceModel describes the resource data model.
type APIKeyResourceModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Key         types.String `tfsdk:"key"`
	Prefix      types.String `tfsdk:"prefix"`
	Permissions types.List   `tfsdk:"permissions"`
	ExpiresAt   types.String `tfsdk:"expires_at"`
}

// NewAPIKeyResource creates a new API key resource.
func NewAPIKeyResource() resource.Resource {
	return &APIKeyResource{}
}

func (r *APIKeyResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_api_key"
}

func (r *APIKeyResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages an NLAG API key for programmatic access.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The unique identifier of the API key.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Description: "A descriptive name for the API key.",
				Required:    true,
			},
			"key": schema.StringAttribute{
				Description: "The API key value. Only available immediately after creation.",
				Computed:    true,
				Sensitive:   true,
			},
			"prefix": schema.StringAttribute{
				Description: "The prefix of the API key for identification.",
				Computed:    true,
			},
			"permissions": schema.ListAttribute{
				Description: "List of permissions for this API key.",
				Optional:    true,
				ElementType: types.StringType,
			},
			"expires_at": schema.StringAttribute{
				Description: "When the API key expires (RFC3339 format).",
				Optional:    true,
			},
		},
	}
}

func (r *APIKeyResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *APIKeyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data APIKeyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	apiKeyReq := APIKeyRequest{
		Name:      data.Name.ValueString(),
		ExpiresAt: data.ExpiresAt.ValueString(),
	}

	if !data.Permissions.IsNull() {
		var perms []string
		data.Permissions.ElementsAs(ctx, &perms, false)
		apiKeyReq.Permissions = perms
	}

	apiKey, err := r.client.CreateAPIKey(apiKeyReq)
	if err != nil {
		resp.Diagnostics.AddError("Failed to create API key", err.Error())
		return
	}

	data.ID = types.StringValue(apiKey.ID)
	data.Key = types.StringValue(apiKey.Key)
	data.Prefix = types.StringValue(apiKey.Prefix)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *APIKeyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data APIKeyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	apiKey, err := r.client.GetAPIKey(data.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Failed to read API key", err.Error())
		return
	}

	data.Name = types.StringValue(apiKey.Name)
	data.Prefix = types.StringValue(apiKey.Prefix)
	// Key is not returned on read, keep existing value

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *APIKeyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError("Update not supported", "API keys cannot be updated. Delete and recreate instead.")
}

func (r *APIKeyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data APIKeyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.client.DeleteAPIKey(data.ID.ValueString()); err != nil {
		resp.Diagnostics.AddError("Failed to delete API key", err.Error())
		return
	}
}

func (r *APIKeyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
