package fakes_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
)

func TestAzureFake_TokenEndpoint(t *testing.T) {
	srv := fakes.NewAzureServer()
	defer srv.Close()

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", "fake-client-id")
	form.Set("client_secret", "fake-client-secret")
	form.Set("scope", "https://graph.microsoft.com/.default")

	resp, err := http.PostForm(srv.URL+"/tenant-123/oauth2/v2.0/token", form)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var result map[string]any
	data, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if result["access_token"] == nil || result["access_token"] == "" {
		t.Fatal("expected access_token in response")
	}
	if result["token_type"] != "Bearer" {
		t.Fatalf("expected Bearer token_type, got %v", result["token_type"])
	}
}

func TestAzureFake_AddPassword(t *testing.T) {
	srv := fakes.NewAzureServer()
	defer srv.Close()

	body := `{"passwordCredential":{"displayName":"cloud-creds-test-lease1","endDateTime":"2026-06-01T00:00:00Z"}}`
	req, _ := http.NewRequest("POST", srv.URL+"/v1.0/applications/fake-app-object-id/addPassword", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer fake-token")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var result map[string]any
	data, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if result["keyId"] == nil {
		t.Fatal("expected keyId field")
	}
	if result["secretText"] == nil {
		t.Fatal("expected secretText field")
	}
	if result["displayName"] != "cloud-creds-test-lease1" {
		t.Fatalf("expected displayName cloud-creds-test-lease1, got %v", result["displayName"])
	}
}

func TestAzureFake_RemovePassword(t *testing.T) {
	srv := fakes.NewAzureServer()
	defer srv.Close()

	// Add a password first
	addBody := `{"passwordCredential":{"displayName":"cloud-creds-test-lease1","endDateTime":"2026-06-01T00:00:00Z"}}`
	addReq, _ := http.NewRequest("POST", srv.URL+"/v1.0/applications/fake-app-object-id/addPassword", strings.NewReader(addBody))
	addReq.Header.Set("Content-Type", "application/json")
	addReq.Header.Set("Authorization", "Bearer fake-token")
	addResp, _ := http.DefaultClient.Do(addReq)
	var addResult map[string]any
	data, _ := io.ReadAll(addResp.Body)
	if err := json.Unmarshal(data, &addResult); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	addResp.Body.Close()
	keyID := addResult["keyId"].(string)

	// Remove the password
	removeBody := `{"keyId":"` + keyID + `"}`
	removeReq, _ := http.NewRequest("POST", srv.URL+"/v1.0/applications/fake-app-object-id/removePassword", strings.NewReader(removeBody))
	removeReq.Header.Set("Content-Type", "application/json")
	removeReq.Header.Set("Authorization", "Bearer fake-token")

	resp, err := http.DefaultClient.Do(removeReq)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 204 {
		t.Fatalf("expected 204, got %d", resp.StatusCode)
	}
}

func TestAzureFake_GetApplication(t *testing.T) {
	srv := fakes.NewAzureServer()
	defer srv.Close()

	// Add a password first
	addBody := `{"passwordCredential":{"displayName":"cloud-creds-test-lease1","endDateTime":"2026-06-01T00:00:00Z"}}`
	addReq, _ := http.NewRequest("POST", srv.URL+"/v1.0/applications/fake-app-object-id/addPassword", strings.NewReader(addBody))
	addReq.Header.Set("Content-Type", "application/json")
	addReq.Header.Set("Authorization", "Bearer fake-token")
	addResp, _ := http.DefaultClient.Do(addReq)
	addResp.Body.Close()

	// Get application
	getReq, _ := http.NewRequest("GET", srv.URL+"/v1.0/applications/fake-app-object-id", http.NoBody)
	getReq.Header.Set("Authorization", "Bearer fake-token")
	resp, err := http.DefaultClient.Do(getReq)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var result map[string]any
	data, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	creds, ok := result["passwordCredentials"].([]any)
	if !ok {
		t.Fatalf("expected passwordCredentials array, got %T", result["passwordCredentials"])
	}
	if len(creds) != 1 {
		t.Fatalf("expected 1 password credential, got %d", len(creds))
	}

	cred := creds[0].(map[string]any)
	if cred["displayName"] != "cloud-creds-test-lease1" {
		t.Fatalf("expected displayName cloud-creds-test-lease1, got %v", cred["displayName"])
	}
	// secretText should NOT appear in list response
	if cred["secretText"] != nil {
		t.Fatal("secretText should not be in list response")
	}
}

func TestAzureFake_ErrorInjection(t *testing.T) {
	srv := fakes.NewAzureServer()
	defer srv.Close()

	srv.SetNextStatus(429)

	body := `{"passwordCredential":{"displayName":"test","endDateTime":"2026-06-01T00:00:00Z"}}`
	req, _ := http.NewRequest("POST", srv.URL+"/v1.0/applications/fake-app-object-id/addPassword", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer fake-token")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 429 {
		t.Fatalf("expected 429, got %d", resp.StatusCode)
	}
}

func TestAzureFake_AuthRequired(t *testing.T) {
	srv := fakes.NewAzureServer()
	defer srv.Close()

	// No auth header
	body := `{"passwordCredential":{"displayName":"test","endDateTime":"2026-06-01T00:00:00Z"}}`
	req, _ := http.NewRequest("POST", srv.URL+"/v1.0/applications/fake-app-object-id/addPassword", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 401 {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}
