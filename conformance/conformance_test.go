package conformance

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/plugintest"
)

// pluginsDir is where the plugin modules live, relative to this module.
const pluginsDir = "../plugins"

// pluginPrefix is the directory-name prefix every credential plugin uses.
const pluginPrefix = "credential-"

// registry is THE table: one entry per credential plugin. Adding a plugin without
// adding it here fails TestEveryPluginIsRegistered.
var registry = []plugintest.Plugin{
	{Cloud: "akamai", New: akamaiHarness},
	{Cloud: "aws", New: awsHarness},
	{Cloud: "azure", New: azureHarness},
	{Cloud: "do", New: doHarness},
	{Cloud: "exoscale", New: exoscaleHarness},
	{Cloud: "gcp", New: gcpHarness},
	{Cloud: "oci", New: ociHarness},
	{Cloud: "ovh", New: ovhHarness},
	{Cloud: "upcloud", New: upcloudHarness},
	{Cloud: "vultr", New: vultrHarness},
}

// TestConformance runs every shared category against every plugin.
func TestConformance(t *testing.T) {
	for _, p := range registry {
		plugintest.RunConformance(t, p)
	}
}

// TestEveryPluginIsRegistered fails when a plugin module exists on disk but is
// absent from the table above — the drift this module exists to prevent.
func TestEveryPluginIsRegistered(t *testing.T) {
	entries, err := os.ReadDir(pluginsDir)
	if err != nil {
		t.Fatalf("cannot read %s: %v", pluginsDir, err)
	}
	registered := make(map[string]bool, len(registry))
	for _, p := range registry {
		registered[p.Cloud] = true
	}
	var onDisk []string
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), pluginPrefix) {
			continue
		}
		cloud := strings.TrimPrefix(e.Name(), pluginPrefix)
		onDisk = append(onDisk, cloud)
		if !registered[cloud] {
			t.Errorf("plugin %q is not in the conformance registry: add it to `registry` in "+
				"conformance/conformance_test.go with a harness, or the shared suites will never "+
				"run against it", e.Name())
		}
	}
	for _, p := range registry {
		found := false
		for _, cloud := range onDisk {
			if cloud == p.Cloud {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("conformance registry names %q but %s/%s%s does not exist", p.Cloud, pluginsDir, pluginPrefix, p.Cloud)
		}
	}
}

// TestConformanceMatrix validates every harness and prints the cloud × category
// coverage matrix, so a declared gap is a line in one table rather than a
// t.Skip buried in one of ten plugin test files.
func TestConformanceMatrix(t *testing.T) {
	categories := plugintest.AllCategories()

	header := make([]string, 0, len(categories))
	for _, c := range categories {
		header = append(header, shortName(string(c)))
	}
	t.Logf("%-10s %s", "cloud", strings.Join(header, " "))

	var gaps []string
	for _, p := range registry {
		h := p.New(t)
		if err := plugintest.ValidateHarness(h); err != nil {
			t.Errorf("%s: invalid conformance harness: %v", p.Cloud, err)
			continue
		}
		cells := make([]string, 0, len(categories))
		for _, c := range categories {
			reason, skipped := h.Skips[c]
			if skipped {
				cells = append(cells, pad("SKIP", shortName(string(c))))
				gaps = append(gaps, fmt.Sprintf("%s/%s: %s", p.Cloud, c, reason))
				continue
			}
			cells = append(cells, pad("run", shortName(string(c))))
		}
		t.Logf("%-10s %s", p.Cloud, strings.Join(cells, " "))
	}

	sort.Strings(gaps)
	for _, g := range gaps {
		t.Logf("declared gap  %s", g)
	}
}

// shortName abbreviates a category for the matrix header.
func shortName(category string) string {
	if len(category) <= 8 {
		return category
	}
	return category[:8]
}

// pad right-pads cell to the width of the column it sits under.
func pad(cell, column string) string {
	for len(cell) < len(column) {
		cell += " "
	}
	return cell
}
