package fakes_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
)

func TestAkamaiFake_CreateClient(t *testing.T) {
	srv := fakes.NewAkamaiServer()
	defer srv.Close()

	body := `{"clientName":"cloud-creds-test-lease1","authorizedUsers":[],"apiAccess":{"apis":[]},"groupAccess":{"groups":[]}}`
	req, _ := http.NewRequest("POST", srv.URL+"/identity-management/v3/api-clients?createCredential=true", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "EG1-HMAC-SHA256 client_token=xxx;access_token=yyy;timestamp=zzz;nonce=nnn;signature=sss")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 201 {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}

	var result map[string]any
	data, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if result["clientId"] == nil {
		t.Fatal("expected clientId")
	}
	if result["clientName"] != "cloud-creds-test-lease1" {
		t.Fatalf("expected clientName cloud-creds-test-lease1, got %v", result["clientName"])
	}

	creds, ok := result["credentials"].([]any)
	if !ok || len(creds) == 0 {
		t.Fatal("expected credentials array with at least one entry")
	}
	cred := creds[0].(map[string]any)
	if cred["clientToken"] == nil {
		t.Fatal("expected clientToken in credentials")
	}
	if cred["clientSecret"] == nil {
		t.Fatal("expected clientSecret in credentials")
	}
	if cred["accessToken"] == nil {
		t.Fatal("expected accessToken in credentials")
	}
}

func TestAkamaiFake_DeleteClient(t *testing.T) {
	srv := fakes.NewAkamaiServer()
	defer srv.Close()

	// Create first
	body := `{"clientName":"cloud-creds-test-lease1","authorizedUsers":[]}`
	createReq, _ := http.NewRequest("POST", srv.URL+"/identity-management/v3/api-clients?createCredential=true", bytes.NewBufferString(body))
	createReq.Header.Set("Content-Type", "application/json")
	createReq.Header.Set("Authorization", "EG1-HMAC-SHA256 client_token=xxx;access_token=yyy;timestamp=zzz;nonce=nnn;signature=sss")

	resp, _ := http.DefaultClient.Do(createReq)
	var createResult map[string]any
	data, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(data, &createResult); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	resp.Body.Close()
	clientID := createResult["clientId"].(string)

	// Delete
	req, _ := http.NewRequest("DELETE", srv.URL+"/identity-management/v3/api-clients/"+clientID, http.NoBody)
	req.Header.Set("Authorization", "EG1-HMAC-SHA256 client_token=xxx;access_token=yyy;timestamp=zzz;nonce=nnn;signature=sss")
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete failed: %v", err)
	}
	if resp2.StatusCode != 204 {
		t.Fatalf("expected 204, got %d", resp2.StatusCode)
	}
}

func TestAkamaiFake_ListClients(t *testing.T) {
	srv := fakes.NewAkamaiServer()
	defer srv.Close()

	// Create a client
	body := `{"clientName":"cloud-creds-test","authorizedUsers":[]}`
	createReq, _ := http.NewRequest("POST", srv.URL+"/identity-management/v3/api-clients?createCredential=true", bytes.NewBufferString(body))
	createReq.Header.Set("Content-Type", "application/json")
	createReq.Header.Set("Authorization", "EG1-HMAC-SHA256 client_token=xxx;access_token=yyy;timestamp=zzz;nonce=nnn;signature=sss")
	resp, _ := http.DefaultClient.Do(createReq)
	resp.Body.Close()

	// List clients
	listReq, _ := http.NewRequest("GET", srv.URL+"/identity-management/v3/api-clients", http.NoBody)
	listReq.Header.Set("Authorization", "EG1-HMAC-SHA256 client_token=xxx;access_token=yyy;timestamp=zzz;nonce=nnn;signature=sss")
	resp2, err := http.DefaultClient.Do(listReq)
	if err != nil {
		t.Fatalf("list failed: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp2.StatusCode)
	}

	var result []any
	data, _ := io.ReadAll(resp2.Body)
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("expected 1 client, got %d", len(result))
	}

	// List should NOT return credentials
	client := result[0].(map[string]any)
	if client["credentials"] != nil {
		t.Fatal("list should not return credentials")
	}
}

func TestAkamaiFake_HealthCheck(t *testing.T) {
	srv := fakes.NewAkamaiServer()
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL+"/identity-management/v3/api-clients/self", http.NoBody)
	req.Header.Set("Authorization", "EG1-HMAC-SHA256 client_token=xxx;access_token=yyy;timestamp=zzz;nonce=nnn;signature=sss")

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
	if result["clientId"] == nil {
		t.Fatal("expected clientId in self response")
	}
}

func TestAkamaiFake_ErrorInjection(t *testing.T) {
	srv := fakes.NewAkamaiServer()
	defer srv.Close()

	srv.SetNextStatus(429)

	body := `{"clientName":"test","authorizedUsers":[]}`
	req, _ := http.NewRequest("POST", srv.URL+"/identity-management/v3/api-clients?createCredential=true", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "EG1-HMAC-SHA256 client_token=xxx;access_token=yyy;timestamp=zzz;nonce=nnn;signature=sss")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 429 {
		t.Fatalf("expected 429, got %d", resp.StatusCode)
	}
}

func TestAkamaiFake_Unauthorized(t *testing.T) {
	srv := fakes.NewAkamaiServer()
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL+"/identity-management/v3/api-clients/self", http.NoBody)
	// No auth header
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 401 {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

// TestAkamaiFake_RejectsBadSignature proves the fake validates the
// EG1-HMAC-SHA256 signature: a request signed with a registered client_token
// but a wrong signature is rejected with 401. This is the guard that catches
// body-hash and canonical-request signing bugs.
func TestAkamaiFake_RejectsBadSignature(t *testing.T) {
	srv := fakes.NewAkamaiServer()
	defer srv.Close()
	srv.RegisterCredential("ct-test", "cs-test")

	req, _ := http.NewRequest(http.MethodPost,
		srv.URL+"/identity-management/v3/api-clients?createCredential=true",
		strings.NewReader(`{"clientName":"x"}`))
	req.Header.Set("Authorization",
		"EG1-HMAC-SHA256 client_token=ct-test;access_token=at;timestamp=20260101T00:00:00+0000;nonce=n;signature=WRONG")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for bad signature, got %d", resp.StatusCode)
	}
}
