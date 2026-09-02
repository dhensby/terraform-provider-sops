package azauth

import (
	"errors"
	"strings"
	"testing"
)

func TestCredentialNotRequestedWhenOIDCDisabled(t *testing.T) {
	// Every other field is populated to show that use_oidc alone decides
	// whether the provider supplies a credential at all.
	cred, err := Config{
		TenantID:  "tenant",
		ClientID:  "client",
		OIDCToken: "assertion",
	}.Credential()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred != nil {
		t.Fatal("expected no credential so that sops uses its own default chain")
	}
}

func TestCredentialRequiresTenantAndClient(t *testing.T) {
	for name, config := range map[string]Config{
		"missing tenant": {UseOIDC: true, ClientID: "client", OIDCToken: "assertion"},
		"missing client": {UseOIDC: true, TenantID: "tenant", OIDCToken: "assertion"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := config.Credential(); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestCredentialRequiresATokenSource(t *testing.T) {
	_, err := Config{UseOIDC: true, TenantID: "tenant", ClientID: "client"}.Credential()
	if !errors.Is(err, ErrNoOIDCSource) {
		t.Fatalf("expected ErrNoOIDCSource, got %v", err)
	}
}

func TestCredentialRequestURLRequiresRequestToken(t *testing.T) {
	_, err := Config{
		UseOIDC:        true,
		TenantID:       "tenant",
		ClientID:       "client",
		OIDCRequestURL: "https://example.invalid/token",
	}.Credential()
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "oidc_request_token") {
		t.Fatalf("error should name the missing setting, got %v", err)
	}
}

func TestCredentialFromEachTokenSource(t *testing.T) {
	base := Config{UseOIDC: true, TenantID: "tenant", ClientID: "client"}

	sources := map[string]func(Config) Config{
		"token": func(c Config) Config {
			c.OIDCToken = "assertion"
			return c
		},
		"token file": func(c Config) Config {
			c.OIDCTokenFilePath = "/var/run/secrets/token"
			return c
		},
		"token request": func(c Config) Config {
			c.OIDCRequestURL = "https://example.invalid/token"
			c.OIDCRequestToken = "request-token"
			return c
		},
		"all three": func(c Config) Config {
			c.OIDCToken = "assertion"
			c.OIDCTokenFilePath = "/var/run/secrets/token"
			c.OIDCRequestURL = "https://example.invalid/token"
			c.OIDCRequestToken = "request-token"
			return c
		},
	}

	for name, apply := range sources {
		t.Run(name, func(t *testing.T) {
			cred, err := apply(base).Credential()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cred == nil {
				t.Fatal("expected a credential")
			}
		})
	}
}

func TestStaticAssertionReturnsTheConfiguredToken(t *testing.T) {
	assertion, err := staticAssertion("an-assertion")(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if assertion != "an-assertion" {
		t.Fatalf("got %q, want %q", assertion, "an-assertion")
	}
}
