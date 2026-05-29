package credenvelope_test

import (
	"testing"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
)

func TestNewEnvelope(t *testing.T) {
	expiresAt := time.Now().Add(15 * time.Minute)
	env := credenvelope.NewEnvelope(credenvelope.EnvelopeParams{
		Cloud:        "do",
		Role:         "snapshot-rw",
		Credential:   map[string]interface{}{"token": "dop_v1_abc", "scopes": []string{"read", "write"}},
		ExpiresAt:    expiresAt,
		TTLSeconds:   900,
		Renewable:    true,
		CredentialID: "do-tok-abc123",
		Scope:        "read write",
		IssuedBy:     "cloud-creds-do/v0.1",
	})

	if env.Cloud != "do" {
		t.Fatalf("expected cloud=do, got %s", env.Cloud)
	}
	if env.Role != "snapshot-rw" {
		t.Fatalf("expected role=snapshot-rw, got %s", env.Role)
	}
	if env.TTLSeconds != 900 {
		t.Fatalf("expected ttl=900, got %d", env.TTLSeconds)
	}
	if env.Metadata.APIVersion != "1" {
		t.Fatalf("expected api_version=1, got %s", env.Metadata.APIVersion)
	}
}

func TestEnvelopeToMap(t *testing.T) {
	expiresAt := time.Date(2026, 5, 29, 14, 30, 0, 0, time.UTC)
	env := credenvelope.NewEnvelope(credenvelope.EnvelopeParams{
		Cloud:        "do",
		Role:         "snapshot-rw",
		Credential:   map[string]interface{}{"token": "dop_v1_abc"},
		ExpiresAt:    expiresAt,
		TTLSeconds:   900,
		Renewable:    true,
		CredentialID: "do-tok-abc123",
		Scope:        "read write",
		IssuedBy:     "cloud-creds-do/v0.1",
	})

	m := env.ToMap()
	if m["cloud"] != "do" {
		t.Fatalf("expected cloud=do in map, got %v", m["cloud"])
	}
	if m["expires_at"] != "2026-05-29T14:30:00Z" {
		t.Fatalf("unexpected expires_at: %v", m["expires_at"])
	}
	meta, ok := m["metadata"].(map[string]interface{})
	if !ok {
		t.Fatalf("metadata not a map")
	}
	if meta["api_version"] != "1" {
		t.Fatalf("expected api_version=1, got %v", meta["api_version"])
	}
}

func TestPluginError(t *testing.T) {
	err := credenvelope.NewError(credenvelope.ErrUpstreamAuthFailed, 502, "minter rejected")
	if err.Code != credenvelope.ErrUpstreamAuthFailed {
		t.Fatalf("unexpected code: %s", err.Code)
	}
	if err.StatusCode != 502 {
		t.Fatalf("unexpected status: %d", err.StatusCode)
	}
	expected := "upstream_auth_failed: minter rejected"
	if err.Error() != expected {
		t.Fatalf("unexpected error string: %s", err.Error())
	}
}
