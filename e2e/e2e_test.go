//go:build e2e

package e2e

import (
	"os"
	"strings"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/baotest"
)

// e2ePlugin is a registry row: either a case constructor or a declared reason
// the cloud cannot be driven end-to-end. Exactly one, never both.
type e2ePlugin struct {
	// Cloud is the plugin DIRECTORY/binary name (credential-<Cloud>). Rows may share it.
	Cloud string
	// Variant distinguishes two SUBJECTS driven through one plugin binary, and is empty for
	// the plugins that serve a single credential type. A variant row is another scenario run
	// against the same binary and the same mount — so it needs no second binary built, and it
	// must not count towards "every plugin on disk is registered", or adding one could mask a
	// cloud that has no row at all.
	Variant string
	New     func(t *testing.T) e2eCase
	Skip    string
}

// Subject names a row for subtest names and the coverage matrix.
func (p e2ePlugin) Subject() string {
	if p.Variant == "" {
		return p.Cloud
	}
	return p.Cloud + "-" + p.Variant
}

// registry is the single table of every plugin. A plugin on disk that is absent
// here fails TestEveryPluginIsRegistered; a plugin here with neither New nor
// Skip fails TestE2EMatrix. Skip reasons must be facts about the cloud's wiring
// — see docs/openbao-integration-gaps.md (G8).
var registry = []e2ePlugin{
	{Cloud: "do", New: doCase},
	// A second SUBJECT from the same plugin binary, not a second plugin: credential-do serves two
	// credential types selected per role, and each has its own secret type and revoke path.
	{Cloud: "do", Variant: "spaces", New: doSpacesCase},
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
	// One binary per CLOUD, however many subjects it serves: registering the same plugin twice
	// with OpenBao would fail the mount, and a variant is another scenario against the binary
	// that is already there.
	built := make(map[string]bool, len(registry))
	for _, p := range registry {
		if p.Skip != "" || built[p.Cloud] {
			continue
		}
		built[p.Cloud] = true
		name := pluginBinary(p.Cloud)
		driven = append(driven, baotest.Plugin{
			Name:    name,
			Package: modulePrefix + "/plugins/" + name + "/cmd",
		})
	}
	cluster := baotest.Start(t, driven...)

	for _, p := range registry {
		if p.Skip != "" {
			continue
		}
		t.Run(p.Subject(), func(t *testing.T) {
			baotest.RunScenario(t, cluster, p.New(t))
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
			t.Errorf("%s has both a case and a skip reason; it must have exactly one", p.Subject())
		case p.New == nil && p.Skip == "":
			t.Errorf("%s has neither a case nor a skip reason: wire it, or declare why the "+
				"cloud cannot be driven end-to-end", p.Subject())
		case p.New != nil:
			t.Logf("%-10s %-8s %s", p.Subject(), "driven", "-")
		default:
			t.Logf("%-10s %-8s %s", p.Subject(), "GAP", p.Skip)
		}
	}
}
