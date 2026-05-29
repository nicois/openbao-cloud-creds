package fakes_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
)

func TestVultrFake_CreateUser(t *testing.T) {
	srv := fakes.NewVultrServer()
	defer srv.Close()

	body := `{"email":"cloud-creds-test-lease1@managed.local","name":"cloud-creds-test-lease1","api_enabled":true,"acls":["subscriptions","provisioning"]}`
	req, _ := http.NewRequest("POST", srv.URL+"/v2/users", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-token")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 201 {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}

	var result map[string]interface{}
	data, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	user, ok := result["user"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected user object, got %v", result)
	}
	if user["id"] == nil {
		t.Fatal("expected user.id")
	}
	if user["name"] != "cloud-creds-test-lease1" {
		t.Fatalf("expected name cloud-creds-test-lease1, got %v", user["name"])
	}
	if user["api_key"] == nil {
		t.Fatal("expected user.api_key")
	}
}

func TestVultrFake_DeleteUser(t *testing.T) {
	srv := fakes.NewVultrServer()
	defer srv.Close()

	// Create first
	body := `{"email":"cloud-creds-test-lease1@managed.local","name":"cloud-creds-test-lease1","api_enabled":true,"acls":["subscriptions"]}`
	createReq, _ := http.NewRequest("POST", srv.URL+"/v2/users", bytes.NewBufferString(body))
	createReq.Header.Set("Content-Type", "application/json")
	createReq.Header.Set("Authorization", "Bearer test-token")

	resp, _ := http.DefaultClient.Do(createReq)
	var createResult map[string]interface{}
	data, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(data, &createResult); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	resp.Body.Close()
	userID := createResult["user"].(map[string]interface{})["id"].(string)

	// Delete
	req, _ := http.NewRequest("DELETE", srv.URL+"/v2/users/"+userID, nil)
	req.Header.Set("Authorization", "Bearer test-token")
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete failed: %v", err)
	}
	if resp2.StatusCode != 204 {
		t.Fatalf("expected 204, got %d", resp2.StatusCode)
	}
}

func TestVultrFake_ListUsers(t *testing.T) {
	srv := fakes.NewVultrServer()
	defer srv.Close()

	// Create a user
	body := `{"email":"cloud-creds-test@managed.local","name":"cloud-creds-test","api_enabled":true,"acls":["subscriptions"]}`
	createReq, _ := http.NewRequest("POST", srv.URL+"/v2/users", bytes.NewBufferString(body))
	createReq.Header.Set("Content-Type", "application/json")
	createReq.Header.Set("Authorization", "Bearer test-token")
	resp, _ := http.DefaultClient.Do(createReq)
	resp.Body.Close()

	// List users
	listReq, _ := http.NewRequest("GET", srv.URL+"/v2/users", nil)
	listReq.Header.Set("Authorization", "Bearer test-token")
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

	users, ok := result["users"].([]interface{})
	if !ok {
		t.Fatalf("expected users array, got %v", result)
	}
	if len(users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(users))
	}

	// List should NOT return api_key
	user := users[0].(map[string]interface{})
	if user["api_key"] != nil {
		t.Fatal("list should not return api_key")
	}
}

func TestVultrFake_ErrorInjection(t *testing.T) {
	srv := fakes.NewVultrServer()
	defer srv.Close()

	srv.SetNextStatus(429)

	body := `{"email":"test@managed.local","name":"test","api_enabled":true,"acls":["subscriptions"]}`
	req, _ := http.NewRequest("POST", srv.URL+"/v2/users", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-token")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 429 {
		t.Fatalf("expected 429, got %d", resp.StatusCode)
	}
}

func TestVultrFake_Unauthorized(t *testing.T) {
	srv := fakes.NewVultrServer()
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL+"/v2/account", nil)
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
