//go:build e2e

package e2e

import (
	"os"
	"strings"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/baotest"
)

// e2eCase is one cloud's translation of the shared end-to-end scenario: the
// three configuration writes, what the resulting lease must look like, and how
// to see the upstream side of it. It is the e2e analogue of
// plugintest.Harness — a translation, not a second implementation.
type e2eCase struct {
	// Cloud is the plugin's cloud name; the mount path and binary name derive
	// from it.
	Cloud string

	// Config, MinterSet and Role are the three writes, in that order. Config
	// must point the plugin at this case's fake.
	Config    map[string]interface{}
	MinterSet map[string]interface{}
	Role      map[string]interface{}

	// TTLSeconds is the role's default TTL, and therefore the lease duration
	// OpenBao must report. A mismatch means the plugin did not set
	// resp.Secret.TTL, or core clamped it against a mount/system max.
	TTLSeconds int

	// Renewable is the cloud's renewability contract (docs/ttl-semantics.md):
	// false wherever the credential's expiry is fixed at mint. It is asserted
	// against the LEASE, which is what a client acts on, and against the
	// envelope's own renewable field, which must agree.
	Renewable bool

	// HardRevoke is true when lease revocation must delete the upstream
	// credential, so the fake's count must fall back.
	HardRevoke bool

	// Upstream reports how many credentials the fake currently holds. On the
	// clouds whose credentials cannot be revoked it is a monotonic count of
	// mints instead; HardRevoke says which.
	Upstream func() int
}

// e2ePlugin is a registry row: either a case constructor or a declared reason
// the cloud cannot be driven end-to-end. Exactly one, never both.
type e2ePlugin struct {
	Cloud string
	New   func(t *testing.T) e2eCase
	Skip  string
}

// registry is the single table of every plugin. A plugin on disk that is absent
// here fails TestEveryPluginIsRegistered; a plugin here with neither New nor
// Skip fails TestE2EMatrix. Skip reasons must be facts about the cloud's wiring
// — see docs/openbao-integration-gaps.md (G8).
var registry = []e2ePlugin{
	{Cloud: "do", New: doCase},
	{Cloud: "upcloud", New: upcloudCase},
	{Cloud: "azure", New: azureCase},
	{Cloud: "exoscale", New: exoscaleCase},
	{Cloud: "vultr", New: vultrCase},
	{Cloud: "akamai", New: akamaiCase},
	{Cloud: "ovh", New: ovhCase},

	{Cloud: "aws", Skip: "AWS reaches STS through an injected in-process client; a plugin " +
		"running as a child process has no fake to point at. It is the closest of the three: " +
		"`sts_endpoint` already exists as a config field, so this needs a SigV4-accepting fake " +
		"STS in pkg/credenvelope/fakes/ and nothing else"},
	{Cloud: "gcp", Skip: "GCP has no endpoint override at all (no equivalent of sts_endpoint), " +
		"so the impersonation and OAuth2 token endpoints cannot be redirected at a fake from " +
		"configuration; the injected client is the only seam and it is in-process"},
	{Cloud: "oci", Skip: "OCI has no endpoint override, and its request signing is a stub — " +
		"signingOCIClient returns \"OCI request signing not implemented in this build\" — so the " +
		"plugin cannot talk to a real or fake endpoint at all until that is implemented"},
}

// TestE2E drives every registered, non-skipped plugin through the full scenario
// against one live dev server.
func TestE2E(t *testing.T) {
	// The package to build is named here rather than derived inside the harness, so a
	// caller in another repository (or another module path) supplies its own.
	driven := make([]baotest.Plugin, 0, len(registry))
	for _, p := range registry {
		if p.Skip == "" {
			name := pluginBinary(p.Cloud)
			driven = append(driven, baotest.Plugin{
				Name:    name,
				Package: modulePrefix + "/plugins/" + name + "/cmd",
			})
		}
	}
	cluster := baotest.Start(t, driven...)

	for _, p := range registry {
		if p.Skip != "" {
			continue
		}
		t.Run(p.Cloud, func(t *testing.T) {
			runCase(t, cluster, p)
		})
	}
}

// TestEveryPluginIsRegistered fails if a plugin exists on disk but not in the
// table, or vice versa — the same disk-reading gate the conformance table uses,
// for the same reason: a new plugin must not be able to arrive uncovered.
func TestEveryPluginIsRegistered(t *testing.T) {
	entries, err := os.ReadDir("../plugins")
	if err != nil {
		t.Fatalf("reading ../plugins failed: %v", err)
	}

	registered := make(map[string]bool, len(registry))
	for _, p := range registry {
		registered[p.Cloud] = true
	}

	onDisk := make(map[string]bool, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "credential-") {
			continue
		}
		if _, err := os.Stat("../plugins/" + entry.Name() + "/cmd/main.go"); err != nil {
			continue
		}
		cloud := strings.TrimPrefix(entry.Name(), "credential-")
		onDisk[cloud] = true
		if !registered[cloud] {
			t.Errorf("plugin %q builds a binary but is not in the e2e registry: add it to "+
				"`registry` in e2e/e2e_test.go, with a case or a declared reason it cannot be "+
				"driven end-to-end", cloud)
		}
	}
	for cloud := range registered {
		if !onDisk[cloud] {
			t.Errorf("the e2e registry names %q, which has no plugins/credential-%s/cmd/main.go",
				cloud, cloud)
		}
	}
}

// TestE2EMatrix prints what this layer covers and what it declares, so the gaps
// are reviewable in one place rather than inferred from which subtests ran.
func TestE2EMatrix(t *testing.T) {
	t.Logf("%-10s %-8s %s", "CLOUD", "E2E", "DECLARED GAP")
	for _, p := range registry {
		switch {
		case p.New != nil && p.Skip != "":
			t.Errorf("%s has both a case and a skip reason; it must have exactly one", p.Cloud)
		case p.New == nil && p.Skip == "":
			t.Errorf("%s has neither a case nor a skip reason: wire it, or declare why the "+
				"cloud cannot be driven end-to-end", p.Cloud)
		case p.New != nil:
			t.Logf("%-10s %-8s %s", p.Cloud, "driven", "-")
		default:
			t.Logf("%-10s %-8s %s", p.Cloud, "GAP", p.Skip)
		}
	}
}
