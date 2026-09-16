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

// subjectColumn is wide enough for the longest SUBJECT name, which is longer than the longest
// cloud name: a variant is printed as cloud-variant, and a matrix whose rows do not line up is
// read wrongly by exactly the person scanning it for a gap.
const subjectColumn = 18

// registry is THE table: one entry per credential plugin. Adding a plugin without
// adding it here fails TestEveryPluginIsRegistered.
var registry = []plugintest.Plugin{
	{Cloud: "akamai", New: akamaiHarness},
	{Cloud: "aws", New: awsHarness},
	{Cloud: "azure", New: azureHarness},
	{Cloud: "do", New: doHarness},
	// A second SUBJECT from the same plugin directory, not a second plugin: credential-do serves
	// two credential types selected per role, so one harness cannot declare both.
	{Cloud: "do", Variant: "spaces", New: doSpacesHarness},
	// A third, for the same reason again: this one shares the Spaces payload with the subject
	// above and differs in who owns the credential, which is the dimension every shared suite
	// reads as "one credential per read".
	{Cloud: "do", Variant: "spaces-rotated", New: doSpacesRotatedHarness},
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
	t.Logf("%-*s %s", subjectColumn, "cloud", strings.Join(header, " "))

	var gaps []string
	for _, p := range registry {
		h := p.New(t)
		if err := plugintest.ValidateHarness(h); err != nil {
			t.Errorf("%s: invalid conformance harness: %v", p.Subject(), err)
			continue
		}
		cells := make([]string, 0, len(categories))
		for _, c := range categories {
			reason, skipped := h.Skips[c]
			if skipped {
				cells = append(cells, pad("SKIP", shortName(string(c))))
				gaps = append(gaps, fmt.Sprintf("%s/%s: %s", p.Subject(), c, reason))
				continue
			}
			cells = append(cells, pad("run", shortName(string(c))))
		}
		t.Logf("%-*s %s", subjectColumn, p.Subject(), strings.Join(cells, " "))
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

// TestOneCredentialKindMeansOneKeySet enforces the promise that makes shape pinning
// useful: a kind names a PAYLOAD, not a cloud.
//
// GCP and OVH both emit `{access_token, token_type}` and both declare
// `oauth2_bearer`, so a client that can parse one can parse the other — and pinning
// `oauth2_bearer` is a statement about what it can parse rather than about which
// cloud it happens to be talking to. That only holds if two clouds sharing a kind
// really do emit the same keys, which is a claim about ten separate plugins and
// therefore worth a test rather than a comment.
//
// It also catches the likelier mistake in the other direction: reusing an existing
// kind for a payload that differs by one field, which would silently break every
// client that pinned it.
func TestOneCredentialKindMeansOneKeySet(t *testing.T) {
	type declaration struct {
		cloud    string
		required []string
		optional []string
	}
	byKind := map[string][]declaration{}

	for _, entry := range registry {
		h := entry.New(t)
		if h.CredentialKind == "" {
			t.Errorf("%s declares no CredentialKind", h.Cloud)
			continue
		}
		byKind[h.CredentialKind] = append(byKind[h.CredentialKind], declaration{
			cloud:    h.Cloud,
			required: sortedCopy(h.CredentialKeys),
			optional: sortedCopy(h.OptionalCredentialKeys),
		})
	}

	for kind, declarations := range byKind {
		first := declarations[0]
		for _, other := range declarations[1:] {
			if strings.Join(first.required, ",") != strings.Join(other.required, ",") ||
				strings.Join(first.optional, ",") != strings.Join(other.optional, ",") {
				t.Errorf("credential_kind %q is declared by %s as required=%v optional=%v and by %s as "+
					"required=%v optional=%v. A kind names a payload, so a client pinning it must get "+
					"the same keys whichever cloud answers — either the payloads should match or the "+
					"kinds should differ",
					kind, first.cloud, first.required, first.optional,
					other.cloud, other.required, other.optional)
			}
		}
	}
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}
