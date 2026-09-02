// Package azauth constructs Azure token credentials for decrypting sops files
// that are protected by an Azure Key Vault key.
//
// sops itself always builds an azidentity.DefaultAzureCredential, whose only
// assertion-based member reads the assertion from a file on disk. That makes
// federated (OIDC) authentication impossible on platforms which expose the
// assertion over HTTP or in an environment variable, such as GitHub Actions,
// Azure Pipelines and HCP Terraform. This package builds the credential the
// platform can actually satisfy, so it can be injected into sops instead.
package azauth

import (
	"context"
	"errors"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

// Config describes how an Azure token credential should be constructed. The
// zero value requests no explicit credential at all, which leaves sops to fall
// back to its own default credential chain.
type Config struct {
	// UseOIDC enables authentication using a federated OIDC assertion.
	UseOIDC bool

	// TenantID is the Entra ID tenant to authenticate against.
	TenantID string

	// ClientID is the client ID of the application to authenticate as.
	ClientID string

	// OIDCToken is an OIDC assertion supplied directly, as HCP Terraform's
	// dynamic provider credentials do.
	OIDCToken string

	// OIDCTokenFilePath is the path to a file containing an OIDC assertion,
	// as used by Kubernetes workload identity.
	OIDCTokenFilePath string

	// OIDCRequestURL and OIDCRequestToken locate an endpoint from which an
	// OIDC assertion can be requested, as used by GitHub Actions and Azure
	// Pipelines.
	OIDCRequestURL   string
	OIDCRequestToken string
}

// ErrNoOIDCSource is returned when OIDC authentication is requested but no
// means of obtaining an assertion was configured.
var ErrNoOIDCSource = errors.New("no OIDC token source configured: set one of oidc_token, oidc_token_file_path, or both oidc_request_url and oidc_request_token")

// Credential returns the credential described by c.
//
// It returns a nil credential when no explicit authentication method is
// configured, which callers must treat as "let sops decide". This keeps the
// default behaviour of the provider unchanged.
func (c Config) Credential() (azcore.TokenCredential, error) {
	if !c.UseOIDC {
		return nil, nil
	}

	if c.TenantID == "" {
		return nil, errors.New("tenant_id is required when use_oidc is enabled")
	}
	if c.ClientID == "" {
		return nil, errors.New("client_id is required when use_oidc is enabled")
	}

	var creds []azcore.TokenCredential

	// Ordering mirrors the Azure Terraform providers: an assertion supplied
	// directly is cheapest and most explicit, a file is next, and requesting
	// one over HTTP is the fallback.
	if c.OIDCToken != "" {
		cred, err := azidentity.NewClientAssertionCredential(c.TenantID, c.ClientID, staticAssertion(c.OIDCToken), nil)
		if err != nil {
			return nil, fmt.Errorf("creating client assertion credential: %w", err)
		}
		creds = append(creds, cred)
	}

	if c.OIDCTokenFilePath != "" {
		cred, err := azidentity.NewWorkloadIdentityCredential(&azidentity.WorkloadIdentityCredentialOptions{
			ClientID:      c.ClientID,
			TenantID:      c.TenantID,
			TokenFilePath: c.OIDCTokenFilePath,
		})
		if err != nil {
			return nil, fmt.Errorf("creating workload identity credential: %w", err)
		}
		creds = append(creds, cred)
	}

	if c.OIDCRequestURL != "" {
		cred, err := newRequestCredential(c.TenantID, c.ClientID, c.OIDCRequestURL, c.OIDCRequestToken)
		if err != nil {
			return nil, err
		}
		creds = append(creds, cred)
	}

	switch len(creds) {
	case 0:
		return nil, ErrNoOIDCSource
	case 1:
		return creds[0], nil
	default:
		// RetrySources lets a later source be tried on a subsequent call after
		// an earlier one has failed, so a stale token file does not
		// permanently disable requesting a fresh assertion.
		return azidentity.NewChainedTokenCredential(creds, &azidentity.ChainedTokenCredentialOptions{RetrySources: true})
	}
}

func staticAssertion(token string) func(context.Context) (string, error) {
	return func(context.Context) (string, error) {
		return token, nil
	}
}
