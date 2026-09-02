//go:build e2e

package e2e

import (
	"fmt"
	"strings"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/baotest"
)

// TestShardKeyIsDiscoverableAtRuntime: the field description is the documentation a client
// developer reaches without a repo checkout, via `bao path-help`. Asserting it means the
// operator-facing text cannot quietly stop being rendered.
func TestShardKeyIsDiscoverableAtRuntime(t *testing.T) {
	c := baotest.Start(t, baotest.Plugin{
		Name: "credential-do", Package: modulePrefix + "/plugins/credential-do/cmd",
	})
	mount := "cloud-creds/do-help"
	c.Enable("credential-do", mount)
	t.Cleanup(func() { c.Unmount(mount) })

	help, err := c.Client().Help(mount + "/creds/anything")
	if err != nil {
		t.Fatalf("path-help failed: %v", err)
	}
	// The prose help and the generated OpenAPI both matter: the first is what `bao path-help`
	// prints, the second is what a generated client or a UI reads.
	rendered := help.Help
	if help.OpenAPI != nil {
		rendered += fmt.Sprintf("%v", help.OpenAPI)
	}
	for _, want := range []string{"shard_key", "credential_kind"} {
		if !strings.Contains(rendered, want) {
			t.Errorf("`bao path-help` on the issue path does not mention %q, so a client developer "+
				"cannot discover it at runtime. Rendered:\n%s", want, rendered)
		}
	}
}
