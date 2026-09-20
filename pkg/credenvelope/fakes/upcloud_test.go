package fakes_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
)

func TestUpCloudFake_CreateToken(t *testing.T) {
	srv := fakes.NewUpCloudServer()
	defer srv.Close()

	body := `{"name":"cloud-creds-test-lease1","expires_in":"1h","can_create_tokens":false}`
	req, _ := http.NewRequest("POST", srv.URL+"/1.3/account/tokens", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("testuser", "testtoken")

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

	if result["id"] == nil {
		t.Fatal("expected id field")
	}
	if result["token"] == nil {
		t.Fatal("expected token field")
	}
	if result["name"] != "cloud-creds-test-lease1" {
		t.Fatalf("expected name cloud-creds-test-lease1, got %v", result["name"])
	}
	if result["expires_at"] == nil {
		t.Fatal("expected expires_at field")
	}
}

func TestUpCloudFake_DeleteToken(t *testing.T) {
	srv := fakes.NewUpCloudServer()
	defer srv.Close()

	// Create first
	body := `{"name":"cloud-creds-test-lease1","expires_in":"1h"}`
	req, _ := http.NewRequest("POST", srv.URL+"/1.3/account/tokens", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("testuser", "testtoken")
	resp, _ := http.DefaultClient.Do(req)
	var createResult map[string]any
	data, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(data, &createResult); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	resp.Body.Close()
	tokenID := createResult["id"].(string)

	// Delete
	delReq, _ := http.NewRequest("DELETE", srv.URL+"/1.3/account/tokens/"+tokenID, http.NoBody)
	delReq.SetBasicAuth("testuser", "testtoken")
	resp2, err := http.DefaultClient.Do(delReq)
	if err != nil {
		t.Fatalf("delete failed: %v", err)
	}
	if resp2.StatusCode != 204 {
		t.Fatalf("expected 204, got %d", resp2.StatusCode)
	}
}

func TestUpCloudFake_ListTokens(t *testing.T) {
	srv := fakes.NewUpCloudServer()
	defer srv.Close()

	// Create a token
	body := `{"name":"cloud-creds-test-lease1","expires_in":"1h"}`
	req, _ := http.NewRequest("POST", srv.URL+"/1.3/account/tokens", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("testuser", "testtoken")
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()

	// List
	listReq, _ := http.NewRequest("GET", srv.URL+"/1.3/account/tokens", http.NoBody)
	listReq.SetBasicAuth("testuser", "testtoken")
	resp2, err := http.DefaultClient.Do(listReq)
	if err != nil {
		t.Fatalf("list failed: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp2.StatusCode)
	}

	// UpCloud returns a bare JSON array of tokens (verified against the live
	// API), not an object with a "tokens" key.
	var tokens []any
	data, _ := io.ReadAll(resp2.Body)
	if err := json.Unmarshal(data, &tokens); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if len(tokens) != 1 {
		t.Fatalf("expected 1 token, got %d", len(tokens))
	}
}

func TestUpCloudFake_ErrorInjection(t *testing.T) {
	srv := fakes.NewUpCloudServer()
	defer srv.Close()

	srv.SetNextStatus(429)

	body := `{"name":"test","expires_in":"1h"}`
	req, _ := http.NewRequest("POST", srv.URL+"/1.3/account/tokens", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("testuser", "testtoken")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 429 {
		t.Fatalf("expected 429, got %d", resp.StatusCode)
	}
}

func TestUpCloudFake_AuthRequired(t *testing.T) {
	srv := fakes.NewUpCloudServer()
	defer srv.Close()

	// No auth header
	body := `{"name":"test","expires_in":"1h"}`
	resp, err := http.Post(srv.URL+"/1.3/account/tokens", "application/json", bytes.NewBufferString(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 401 {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}
