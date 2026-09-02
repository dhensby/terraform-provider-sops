package sops

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/echoprovider"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

var testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"sops": providerserver.NewProtocol6WithError(New()),
	"echo": echoprovider.NewProviderServer(),
}

func TestProvider_impl(t *testing.T) {
	var _ provider.Provider = New()
}

const configTestProviderAzureKeyVaultOIDC = `
provider "sops" {
  azure_keyvault = {
    use_oidc   = true
    tenant_id  = "00000000-0000-0000-0000-000000000000"
    client_id  = "11111111-1111-1111-1111-111111111111"
    oidc_token = "an-assertion"
  }
}

data "sops_file" "test_oidc" {
  source_file = "%s/test-fixtures/basic.yaml"
}`

// Configuring Azure authentication must not disturb files encrypted with any
// other key type.
func TestProvider_azureKeyVaultOIDC(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(configTestProviderAzureKeyVaultOIDC, wd),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.sops_file.test_oidc", "data.hello", "world"),
				),
			},
		},
	})
}

const configTestProviderAzureKeyVaultInvalid = `
provider "sops" {
  azure_keyvault = {
    use_oidc = true
%s
  }
}

data "sops_file" "test_invalid" {
  source_file = "%s/test-fixtures/basic.yaml"
}`

func TestProvider_azureKeyVaultOIDCConfigErrors(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]struct {
		settings    string
		expectError string
	}{
		"no tenant": {
			settings:    `    client_id = "11111111-1111-1111-1111-111111111111"`,
			expectError: "tenant_id is required",
		},
		"no client": {
			settings:    `    tenant_id = "00000000-0000-0000-0000-000000000000"`,
			expectError: "client_id is required",
		},
		"no token source": {
			settings: `    tenant_id = "00000000-0000-0000-0000-000000000000"
    client_id = "11111111-1111-1111-1111-111111111111"`,
			expectError: "no OIDC token source configured",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			// The settings under test must not be satisfied by the ambient
			// environment of whoever runs the suite.
			for _, envVar := range []string{
				"ARM_TENANT_ID", "AZURE_TENANT_ID", "ARM_CLIENT_ID", "AZURE_CLIENT_ID",
				"ARM_OIDC_TOKEN", "ARM_OIDC_TOKEN_FILE_PATH", "AZURE_FEDERATED_TOKEN_FILE",
				"ARM_OIDC_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_URL",
			} {
				t.Setenv(envVar, "")
			}

			resource.UnitTest(t, resource.TestCase{
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				Steps: []resource.TestStep{
					{
						Config:      fmt.Sprintf(configTestProviderAzureKeyVaultInvalid, test.settings, wd),
						ExpectError: regexp.MustCompile(test.expectError),
					},
				},
			})
		})
	}
}

func TestStringOrEnv(t *testing.T) {
	t.Setenv("SOPS_TEST_FIRST", "")
	t.Setenv("SOPS_TEST_SECOND", "from-second")

	if got := stringOrEnv(types.StringValue("configured"), "SOPS_TEST_SECOND"); got != "configured" {
		t.Errorf("configured value should win, got %q", got)
	}
	if got := stringOrEnv(types.StringNull(), "SOPS_TEST_FIRST", "SOPS_TEST_SECOND"); got != "from-second" {
		t.Errorf("should skip the empty variable, got %q", got)
	}
	if got := stringOrEnv(types.StringNull(), "SOPS_TEST_UNSET"); got != "" {
		t.Errorf("unset should yield empty, got %q", got)
	}
	if got := stringOrEnv(types.StringUnknown(), "SOPS_TEST_SECOND"); got != "from-second" {
		t.Errorf("unknown should fall back to the environment, got %q", got)
	}
}

func TestBoolOrEnv(t *testing.T) {
	t.Setenv("SOPS_TEST_BOOL", "true")
	t.Setenv("SOPS_TEST_JUNK", "not-a-bool")

	if got := boolOrEnv(types.BoolValue(false), "SOPS_TEST_BOOL"); got {
		t.Error("configured value should win")
	}
	if got := boolOrEnv(types.BoolNull(), "SOPS_TEST_BOOL"); !got {
		t.Error("should read the environment")
	}
	if got := boolOrEnv(types.BoolNull(), "SOPS_TEST_JUNK", "SOPS_TEST_BOOL"); !got {
		t.Error("should skip an unparseable value")
	}
	if got := boolOrEnv(types.BoolNull(), "SOPS_TEST_UNSET"); got {
		t.Error("unset should be false")
	}
}
