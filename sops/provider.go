package sops

import (
	"context"
	"os"
	"strconv"

	"github.com/getsops/sops/v3/keyservice"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/carlpett/terraform-provider-sops/sops/internal/azauth"
)

var _ provider.Provider = &SopsProvider{}

type SopsProvider struct{}

func New() provider.Provider {
	return &SopsProvider{}
}

type providerModel struct {
	AzureKeyVault *azureKeyVaultModel `tfsdk:"azure_keyvault"`
}

type azureKeyVaultModel struct {
	UseOIDC           types.Bool   `tfsdk:"use_oidc"`
	TenantID          types.String `tfsdk:"tenant_id"`
	ClientID          types.String `tfsdk:"client_id"`
	OIDCToken         types.String `tfsdk:"oidc_token"`
	OIDCTokenFilePath types.String `tfsdk:"oidc_token_file_path"`
	OIDCRequestURL    types.String `tfsdk:"oidc_request_url"`
	OIDCRequestToken  types.String `tfsdk:"oidc_request_token"`
}

func (p *SopsProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "sops"
}

func (p *SopsProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A Terraform plugin for using files encrypted with [SOPS](https://github.com/getsops/sops).",
		Attributes: map[string]schema.Attribute{
			"azure_keyvault": schema.SingleNestedAttribute{
				Description: "Authentication settings for files encrypted with an Azure Key Vault key. If omitted, " +
					"sops authenticates using its own default credential chain, which cannot use a federated identity " +
					"unless the assertion happens to be available as a file on disk.",
				Optional: true,
				Attributes: map[string]schema.Attribute{
					"use_oidc": schema.BoolAttribute{
						Description: "Authenticate using a federated OIDC assertion rather than the default credential " +
							"chain. Defaults to `false`, or the value of the `ARM_USE_OIDC` environment variable.",
						Optional: true,
					},
					"tenant_id": schema.StringAttribute{
						Description: "The Entra ID tenant to authenticate against. Defaults to the value of the " +
							"`ARM_TENANT_ID` or `AZURE_TENANT_ID` environment variable. Required when `use_oidc` is enabled.",
						Optional: true,
					},
					"client_id": schema.StringAttribute{
						Description: "The client ID of the application to authenticate as. Defaults to the value of the " +
							"`ARM_CLIENT_ID` or `AZURE_CLIENT_ID` environment variable. Required when `use_oidc` is enabled.",
						Optional: true,
					},
					"oidc_token": schema.StringAttribute{
						Description: "An OIDC assertion to authenticate with, supplied directly. Defaults to the value of " +
							"the `ARM_OIDC_TOKEN` environment variable, which is how HCP Terraform supplies dynamic " +
							"provider credentials.",
						Optional:  true,
						Sensitive: true,
					},
					"oidc_token_file_path": schema.StringAttribute{
						Description: "Path to a file containing an OIDC assertion to authenticate with. Defaults to the " +
							"value of the `ARM_OIDC_TOKEN_FILE_PATH` or `AZURE_FEDERATED_TOKEN_FILE` environment variable.",
						Optional: true,
					},
					"oidc_request_url": schema.StringAttribute{
						Description: "URL of an endpoint from which an OIDC assertion can be requested. Defaults to the " +
							"value of the `ARM_OIDC_REQUEST_URL` or `ACTIONS_ID_TOKEN_REQUEST_URL` environment variable, " +
							"the latter of which GitHub Actions sets for jobs granted the `id-token: write` permission. " +
							"The assertion is requested on demand and never written to disk.",
						Optional: true,
					},
					"oidc_request_token": schema.StringAttribute{
						Description: "Bearer token used to authenticate the request to `oidc_request_url`. Defaults to the " +
							"value of the `ARM_OIDC_REQUEST_TOKEN` or `ACTIONS_ID_TOKEN_REQUEST_TOKEN` environment variable.",
						Optional:  true,
						Sensitive: true,
					},
				},
			},
		},
	}
}

func (p *SopsProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var config providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// The block is optional: every setting can equally be supplied by an
	// environment variable, which is the common case in CI.
	azureConfig := azureKeyVaultModel{}
	if config.AzureKeyVault != nil {
		azureConfig = *config.AzureKeyVault
	}

	cred, err := azauth.Config{
		UseOIDC:           boolOrEnv(azureConfig.UseOIDC, "ARM_USE_OIDC"),
		TenantID:          stringOrEnv(azureConfig.TenantID, "ARM_TENANT_ID", "AZURE_TENANT_ID"),
		ClientID:          stringOrEnv(azureConfig.ClientID, "ARM_CLIENT_ID", "AZURE_CLIENT_ID"),
		OIDCToken:         stringOrEnv(azureConfig.OIDCToken, "ARM_OIDC_TOKEN"),
		OIDCTokenFilePath: stringOrEnv(azureConfig.OIDCTokenFilePath, "ARM_OIDC_TOKEN_FILE_PATH", "AZURE_FEDERATED_TOKEN_FILE"),
		OIDCRequestURL:    stringOrEnv(azureConfig.OIDCRequestURL, "ARM_OIDC_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_URL"),
		OIDCRequestToken:  stringOrEnv(azureConfig.OIDCRequestToken, "ARM_OIDC_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_TOKEN"),
	}.Credential()
	if err != nil {
		resp.Diagnostics.AddError("Invalid Azure Key Vault authentication settings", err.Error())
		return
	}

	// A nil credential leaves sops to build its own, preserving the behaviour
	// of releases before this setting existed.
	svc := newKeyServiceClient(cred)
	resp.DataSourceData = svc
	resp.EphemeralResourceData = svc
}

func (p *SopsProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		newFileDataSource,
		newExternalDataSource,
	}
}

func (p *SopsProvider) Resources(_ context.Context) []func() resource.Resource {
	return nil
}

func (p *SopsProvider) EphemeralResources(_ context.Context) []func() ephemeral.EphemeralResource {
	return []func() ephemeral.EphemeralResource{
		newFileEphemeralResource,
		newExternalEphemeral,
	}
}

// stringOrEnv resolves a configured value, falling back to the first of the
// given environment variables that is set to a non-empty value.
func stringOrEnv(value types.String, envVars ...string) string {
	if !value.IsNull() && !value.IsUnknown() {
		return value.ValueString()
	}
	for _, envVar := range envVars {
		if v := os.Getenv(envVar); v != "" {
			return v
		}
	}
	return ""
}

// boolOrEnv resolves a configured value, falling back to the first of the given
// environment variables that is set to a value Go recognises as a boolean.
func boolOrEnv(value types.Bool, envVars ...string) bool {
	if !value.IsNull() && !value.IsUnknown() {
		return value.ValueBool()
	}
	for _, envVar := range envVars {
		if v, err := strconv.ParseBool(os.Getenv(envVar)); err == nil {
			return v
		}
	}
	return false
}

// keyServiceFrom recovers the key service configured by the provider. Provider
// data is absent when Terraform configures a data source purely to read its
// schema, so a missing value falls back to the stock sops key service rather
// than being an error.
func keyServiceFrom(providerData any) keyservice.KeyServiceClient {
	if svc, ok := providerData.(keyservice.KeyServiceClient); ok {
		return svc
	}
	return keyservice.NewLocalClient()
}
