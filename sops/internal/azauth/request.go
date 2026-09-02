package azauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

// exchangeAudience is the audience Entra ID expects for a federated identity
// assertion.
const exchangeAudience = "api://AzureADTokenExchange"

// maxAssertionSize bounds how much of the token endpoint's response is read,
// guarding against a misconfigured URL streaming an unbounded body.
const maxAssertionSize = 1 << 20

// assertionRequester fetches an OIDC assertion from an HTTP endpoint. GitHub
// Actions exposes exactly such an endpoint via ACTIONS_ID_TOKEN_REQUEST_URL,
// and never writes the assertion to disk.
type assertionRequester struct {
	requestURL   string
	requestToken string
	client       *http.Client
}

// newRequestCredential returns a credential which mints a fresh assertion from
// an OIDC token endpoint each time one is required. The assertion is held only
// in memory, and because it is requested on demand its short lifetime (five
// minutes on GitHub Actions) is never a problem.
func newRequestCredential(tenantID, clientID, requestURL, requestToken string) (azcore.TokenCredential, error) {
	requester, err := newAssertionRequester(requestURL, requestToken)
	if err != nil {
		return nil, err
	}

	cred, err := azidentity.NewClientAssertionCredential(tenantID, clientID, requester.assertion, nil)
	if err != nil {
		return nil, fmt.Errorf("creating client assertion credential: %w", err)
	}
	return cred, nil
}

func newAssertionRequester(requestURL, requestToken string) (*assertionRequester, error) {
	if requestToken == "" {
		return nil, errors.New("oidc_request_token is required when oidc_request_url is set")
	}

	parsed, err := url.Parse(requestURL)
	if err != nil {
		return nil, fmt.Errorf("parsing oidc_request_url: %w", err)
	}
	// The audience the endpoint is asked for must match the audience Entra ID
	// validates, but callers commonly supply a bare URL.
	query := parsed.Query()
	if query.Get("audience") == "" {
		query.Set("audience", exchangeAudience)
		parsed.RawQuery = query.Encode()
	}

	return &assertionRequester{
		requestURL:   parsed.String(),
		requestToken: requestToken,
		client:       http.DefaultClient,
	}, nil
}

func (a *assertionRequester) assertion(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.requestURL, nil)
	if err != nil {
		return "", fmt.Errorf("building OIDC token request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+a.requestToken)
	req.Header.Set("Accept", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("requesting OIDC token: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAssertionSize))
	if err != nil {
		return "", fmt.Errorf("reading OIDC token response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		// The body is deliberately not included: it may contain a token.
		return "", fmt.Errorf("requesting OIDC token: unexpected status %s", resp.Status)
	}

	var payload struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", fmt.Errorf("parsing OIDC token response: %w", err)
	}
	if payload.Value == "" {
		return "", errors.New("OIDC token response contained no token")
	}
	return payload.Value, nil
}
