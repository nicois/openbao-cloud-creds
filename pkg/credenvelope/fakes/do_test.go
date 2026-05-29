package fakes_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
)

func TestDOFake_CreateToken(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()

	body := `{"name":"cloud-creds-test-lease1","scopes":["read","write"]}`
	resp, err := http.Post(srv.URL+"/v2/tokens", "application/json", bytes.NewBufferString(body))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 201 {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}

	var result map[string]interface{}
	data, _ := io.ReadAll(resp.Body)
	json.Unmarshal(data, &result)

	token, ok := result["token"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected token object, got %v", result)
	}
	if token["id"] == nil {
		t.Fatal("expected token.id")
	}
	if token["name"] != "cloud-creds-test-lease1" {
		t.Fatalf("expected name cloud-creds-test-lease1, got %v", token["name"])
	}
}

func TestDOFake_DeleteToken(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()

	// Create first
	body := `{"name":"cloud-creds-test-lease1","scopes":["read"]}`
	resp, _ := http.Post(srv.URL+"/v2/tokens", "application/json", bytes.NewBufferString(body))
	var createResult map[string]interface{}
	data, _ := io.ReadAll(resp.Body)
	json.Unmarshal(data, &createResult)
	resp.Body.Close()
	tokenID := createResult["token"].(map[string]interface{})["id"].(string)

	// Delete
	req, _ := http.NewRequest("DELETE", srv.URL+"/v2/tokens/"+tokenID, nil)
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete failed: %v", err)
	}
	if resp2.StatusCode != 204 {
		t.Fatalf("expected 204, got %d", resp2.StatusCode)
	}
}

func TestDOFake_ErrorInjection(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()

	srv.SetNextStatus(429)

	body := `{"name":"test","scopes":["read"]}`
	resp, err := http.Post(srv.URL+"/v2/tokens", "application/json", bytes.NewBufferString(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 429 {
		t.Fatalf("expected 429, got %d", resp.StatusCode)
	}
}
