package fakes_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
)

func TestExoscaleFake_CreateAPIKey(t *testing.T) {
	srv := fakes.NewExoscaleServer()
	defer srv.Close()

	body := `{"name":"cloud-creds-test-lease1","role-id":"role-uuid-123"}`
	req, _ := http.NewRequest("POST", srv.URL+"/v2/api-key", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-api-key")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var result map[string]interface{}
	data, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if result["key-id"] == nil {
		t.Fatal("expected key-id field")
	}
	if result["key"] == nil {
		t.Fatal("expected key field (secret)")
	}
	if result["name"] != "cloud-creds-test-lease1" {
		t.Fatalf("expected name cloud-creds-test-lease1, got %v", result["name"])
	}
	if result["role-id"] != "role-uuid-123" {
		t.Fatalf("expected role-id role-uuid-123, got %v", result["role-id"])
	}
}

func TestExoscaleFake_DeleteAPIKey(t *testing.T) {
	srv := fakes.NewExoscaleServer()
	defer srv.Close()

	// Create first
	body := `{"name":"cloud-creds-test-lease1","role-id":"role-uuid-123"}`
	req, _ := http.NewRequest("POST", srv.URL+"/v2/api-key", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-api-key")
	resp, _ := http.DefaultClient.Do(req)
	var createResult map[string]interface{}
	data, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(data, &createResult); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	resp.Body.Close()
	keyID := createResult["key-id"].(string)

	// Delete
	delReq, _ := http.NewRequest("DELETE", srv.URL+"/v2/api-key/"+keyID, http.NoBody)
	delReq.Header.Set("Authorization", "Bearer test-api-key")
	resp2, err := http.DefaultClient.Do(delReq)
	if err != nil {
		t.Fatalf("delete failed: %v", err)
	}
	if resp2.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp2.StatusCode)
	}
}

func TestExoscaleFake_ListAPIKeys(t *testing.T) {
	srv := fakes.NewExoscaleServer()
	defer srv.Close()

	// Create an API key
	body := `{"name":"cloud-creds-test-lease1","role-id":"role-uuid-123"}`
	req, _ := http.NewRequest("POST", srv.URL+"/v2/api-key", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-api-key")
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()

	// List
	listReq, _ := http.NewRequest("GET", srv.URL+"/v2/api-key", http.NoBody)
	listReq.Header.Set("Authorization", "Bearer test-api-key")
	resp2, err := http.DefaultClient.Do(listReq)
	if err != nil {
		t.Fatalf("list failed: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp2.StatusCode)
	}

	var result map[string]interface{}
	data, _ := io.ReadAll(resp2.Body)
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	keys, ok := result["api-keys"].([]interface{})
	if !ok {
		t.Fatalf("expected api-keys array, got %T", result["api-keys"])
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
}

func TestExoscaleFake_ErrorInjection(t *testing.T) {
	srv := fakes.NewExoscaleServer()
	defer srv.Close()

	srv.SetNextStatus(429)

	body := `{"name":"test","role-id":"role-uuid-123"}`
	req, _ := http.NewRequest("POST", srv.URL+"/v2/api-key", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-api-key")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 429 {
		t.Fatalf("expected 429, got %d", resp.StatusCode)
	}
}

func TestExoscaleFake_AuthRequired(t *testing.T) {
	srv := fakes.NewExoscaleServer()
	defer srv.Close()

	// No auth header
	body := `{"name":"test","role-id":"role-uuid-123"}`
	resp, err := http.Post(srv.URL+"/v2/api-key", "application/json", bytes.NewBufferString(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 401 {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}
