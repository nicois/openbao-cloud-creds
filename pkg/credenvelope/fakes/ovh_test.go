package fakes_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
)

func TestOVHFake_TokenEndpoint(t *testing.T) {
	srv := fakes.NewOVHServer()
	defer srv.Close()

	data := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"test-client-id"},
		"client_secret": {"test-client-secret"},
	}

	resp, err := http.Post(srv.TokenEndpointURL(), "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(body))
	}

	var result map[string]interface{}
	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if result["access_token"] == nil || result["access_token"] == "" {
		t.Fatal("expected access_token")
	}
	if result["token_type"] != "Bearer" {
		t.Fatalf("expected token_type=Bearer, got %v", result["token_type"])
	}
	if result["expires_in"] == nil {
		t.Fatal("expected expires_in")
	}
	expiresIn, ok := result["expires_in"].(float64)
	if !ok || expiresIn != 3600 {
		t.Fatalf("expected expires_in=3600, got %v", result["expires_in"])
	}
}

func TestOVHFake_InvalidClient(t *testing.T) {
	srv := fakes.NewOVHServer()
	defer srv.Close()

	data := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"wrong-id"},
		"client_secret": {"wrong-secret"},
	}

	resp, err := http.Post(srv.TokenEndpointURL(), "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 401 {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestOVHFake_InvalidGrantType(t *testing.T) {
	srv := fakes.NewOVHServer()
	defer srv.Close()

	data := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"test-client-id"},
		"client_secret": {"test-client-secret"},
	}

	resp, err := http.Post(srv.TokenEndpointURL(), "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 400 {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestOVHFake_ErrorInjection(t *testing.T) {
	srv := fakes.NewOVHServer()
	defer srv.Close()

	srv.SetNextStatus(429)

	data := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"test-client-id"},
		"client_secret": {"test-client-secret"},
	}

	resp, err := http.Post(srv.TokenEndpointURL(), "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 429 {
		t.Fatalf("expected 429, got %d", resp.StatusCode)
	}
}

func TestOVHFake_TokenCountIncreases(t *testing.T) {
	srv := fakes.NewOVHServer()
	defer srv.Close()

	if srv.TokenCount() != 0 {
		t.Fatalf("expected 0 tokens initially, got %d", srv.TokenCount())
	}

	data := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"test-client-id"},
		"client_secret": {"test-client-secret"},
	}

	for i := 0; i < 3; i++ {
		resp, err := http.Post(srv.TokenEndpointURL(), "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
		if err != nil {
			t.Fatalf("request %d failed: %v", i, err)
		}
		resp.Body.Close()
	}

	if srv.TokenCount() != 3 {
		t.Fatalf("expected 3 tokens, got %d", srv.TokenCount())
	}
}
