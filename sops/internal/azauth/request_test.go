package azauth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestAssertionRequest(t *testing.T) {
	var gotAuthorization, gotAudience, gotMethod string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuthorization = r.Header.Get("Authorization")
		gotAudience = r.URL.Query().Get("audience")
		gotMethod = r.Method
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"value":"an-assertion","count":1}`))
	}))
	defer server.Close()

	requester, err := newAssertionRequester(server.URL, "request-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertion, err := requester.assertion(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if assertion != "an-assertion" {
		t.Errorf("assertion: got %q, want %q", assertion, "an-assertion")
	}
	if gotMethod != http.MethodGet {
		t.Errorf("method: got %q, want %q", gotMethod, http.MethodGet)
	}
	if gotAuthorization != "Bearer request-token" {
		t.Errorf("authorization: got %q, want %q", gotAuthorization, "Bearer request-token")
	}
	if gotAudience != exchangeAudience {
		t.Errorf("audience: got %q, want %q", gotAudience, exchangeAudience)
	}
}

func TestAssertionRequestKeepsAnExplicitAudience(t *testing.T) {
	requester, err := newAssertionRequester("https://example.invalid/token?audience=api://custom", "request-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	parsed, err := url.Parse(requester.requestURL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := parsed.Query().Get("audience"); got != "api://custom" {
		t.Fatalf("audience: got %q, want %q", got, "api://custom")
	}
}

func TestAssertionRequestErrors(t *testing.T) {
	tests := map[string]struct {
		status int
		body   string
		want   string
	}{
		"http error":     {status: http.StatusForbidden, body: `{"value":"leaked-assertion"}`, want: "403"},
		"empty value":    {status: http.StatusOK, body: `{"value":""}`, want: "no token"},
		"absent value":   {status: http.StatusOK, body: `{}`, want: "no token"},
		"malformed json": {status: http.StatusOK, body: `not json`, want: "parsing"},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()

			requester, err := newAssertionRequester(server.URL, "request-token")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			_, err = requester.assertion(t.Context())
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Errorf("error %q should contain %q", err, test.want)
			}
			// A failed response may carry a token; it must not reach logs or
			// Terraform diagnostics.
			if strings.Contains(err.Error(), "leaked-assertion") {
				t.Errorf("error must not include the response body: %v", err)
			}
		})
	}
}
