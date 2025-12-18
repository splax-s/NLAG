// Package provider implements the NLAG Terraform provider.
package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure NlagProvider satisfies the provider.Provider interface.
var _ provider.Provider = &NlagProvider{}

// NlagProvider defines the provider implementation.
type NlagProvider struct {
	version string
}

// NlagProviderModel describes the provider configuration.
type NlagProviderModel struct {
	APIUrl   types.String `tfsdk:"api_url"`
	APIToken types.String `tfsdk:"api_token"`
	Region   types.String `tfsdk:"region"`
}

// New creates a new provider instance.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &NlagProvider{
			version: version,
		}
	}
}

// Metadata returns the provider type name.
func (p *NlagProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "nlag"
	resp.Version = p.version
}

// Schema returns the provider schema.
func (p *NlagProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "The NLAG provider allows you to manage NLAG tunnels, domains, and other resources as infrastructure as code.",
		Attributes: map[string]schema.Attribute{
			"api_url": schema.StringAttribute{
				Description: "The NLAG API URL. Defaults to https://api.nlag.dev. Can also be set via the NLAG_API_URL environment variable.",
				Optional:    true,
			},
			"api_token": schema.StringAttribute{
				Description: "The NLAG API token. Can also be set via the NLAG_API_TOKEN environment variable.",
				Optional:    true,
				Sensitive:   true,
			},
			"region": schema.StringAttribute{
				Description: "The preferred region for resources. Can also be set via the NLAG_REGION environment variable.",
				Optional:    true,
			},
		},
	}
}

// Configure sets up the provider configuration.
func (p *NlagProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var config NlagProviderModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create API client
	client := NewAPIClient(
		config.APIUrl.ValueString(),
		config.APIToken.ValueString(),
		config.Region.ValueString(),
	)

	resp.DataSourceData = client
	resp.ResourceData = client
}

// Resources returns the provider's resources.
func (p *NlagProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewTunnelResource,
		NewDomainResource,
		NewAPIKeyResource,
		NewIPRestrictionResource,
	}
}

// DataSources returns the provider's data sources.
func (p *NlagProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewTunnelDataSource,
		NewDomainsDataSource,
		NewRegionsDataSource,
	}
}
