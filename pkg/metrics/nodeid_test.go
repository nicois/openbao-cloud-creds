package metrics_test

import (
	"os"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/metrics"
)

func TestResolveNodeID_EnvWins(t *testing.T) {
	t.Setenv("OPENBAO_CLOUD_CREDS_NODE_ID", "node-42")
	if got := metrics.ResolveNodeID(); got != "node-42" {
		t.Fatalf("env override: got %q, want node-42", got)
	}
}

func TestResolveNodeID_FallsBackToHostname(t *testing.T) {
	t.Setenv("OPENBAO_CLOUD_CREDS_NODE_ID", "")
	host, _ := os.Hostname()
	got := metrics.ResolveNodeID()
	// On any normal machine Hostname() is non-empty, so ResolveNodeID must
	// return it. (The empty-hostname path falls through to the documented
	// "unknown-node" constant; it cannot be forced in-process.)
	if host != "" && got != host {
		t.Fatalf("hostname fallback: got %q, want %q", got, host)
	}
	if got == "" {
		t.Fatal("ResolveNodeID must never return empty")
	}
}
