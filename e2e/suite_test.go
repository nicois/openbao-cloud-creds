//go:build e2e

package e2e

import (
	"strings"
	"testing"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/openbao/openbao/api/v2"
)

// upstreamPollAttempts bounds how long an upstream count is given to settle.
// Revocation through sys/leases/revoke is synchronous, but the plugin's own
// bookkeeping is not, so a bounded poll beats a sleep.
const upstreamPollAttempts = 40

// runCase drives one cloud through the whole scenario. Each step is a named
// helper so a failure names the property that broke, not a line number.
func runCase(t *testing.T, c *cluster, p e2ePlugin) {
	tc := p.New(t)
	mount := mountFor(p.Cloud)
	c.enable(pluginBinary(p.Cloud), mount)
	t.Cleanup(func() { c.unmount(mount) })

	c.write(mount+"/"+configPath, tc.Config)
	c.write(mount+"/"+setPath, tc.MinterSet)
	c.write(mount+"/"+rolePath, tc.Role)

	// Baseline AFTER configuration: a minter-set write and a role write each run
	// a capability probe, which mints and deletes.
	want := upstreamCount(tc)

	first := c.read(mount + "/" + issuePath)
	assertLease(t, tc, mount, first)
	assertEnvelope(t, tc, first)
	want++
	assertUpstream(t, tc, want)

	second := c.read(mount + "/" + issuePath)
	assertDistinctIssuance(t, first, second)
	want++
	assertUpstream(t, tc, want)

	assertLeaseIsTracked(t, c, first.LeaseID)
	assertRenewContract(t, c, tc, first.LeaseID)

	if tc.HardRevoke {
		want--
	}
	assertRevoke(t, c, tc, first.LeaseID, want)

	want++
	assertReloadThenIssue(t, c, tc, mount, want)
}

// assertLease checks the lease OpenBao actually created. None of this is
// observable in-process: the in-memory tests read resp.Secret's fields straight
// back out of the struct the plugin populated.
func assertLease(t *testing.T, tc e2eCase, mount string, secret *api.Secret) {
	t.Helper()
	if secret.LeaseID == "" {
		t.Fatalf("OpenBao created no lease for the issued credential; without one nothing "+
			"revokes it (secret: %+v)", secret)
	}
	if prefix := mount + "/" + issuePath; !strings.HasPrefix(secret.LeaseID, prefix+"/") {
		t.Errorf("lease id %q is not under %q", secret.LeaseID, prefix)
	}
	if secret.LeaseDuration != tc.TTLSeconds {
		t.Errorf("lease duration is %ds, want the role's %ds: either the plugin left "+
			"resp.Secret.TTL unset or core clamped it against a mount/system max_lease_ttl "+
			"(docs/openbao-integration-gaps.md G5)", secret.LeaseDuration, tc.TTLSeconds)
	}
	if secret.Renewable != tc.Renewable {
		t.Errorf("lease says renewable=%v, want %v: renewability must be false wherever the "+
			"credential's expiry is fixed at mint, and the LEASE is what a client renews "+
			"(docs/ttl-semantics.md)", secret.Renewable, tc.Renewable)
	}
}

// assertEnvelope checks the response envelope after a round trip through the
// plugin RPC boundary and the HTTP API — where an int becomes json.Number and a
// time.Time would become a string.
func assertEnvelope(t *testing.T, tc e2eCase, secret *api.Secret) {
	t.Helper()
	data := secret.Data
	if code, ok := data["error_code"]; ok {
		t.Fatalf("issuance returned an error envelope: error_code=%v data=%v", code, data)
	}
	if got := str(t, data, "cloud"); got != tc.Cloud {
		t.Errorf("envelope cloud is %q, want %q", got, tc.Cloud)
	}
	if got := str(t, data, "role"); got != roleName {
		t.Errorf("envelope role is %q, want %q", got, roleName)
	}
	if credential := nested(t, data, "credential"); len(credential) == 0 {
		t.Errorf("envelope carries an empty credential")
	}
	expiresAt, err := time.Parse(time.RFC3339, str(t, data, "expires_at"))
	if err != nil {
		t.Errorf("envelope expires_at did not survive the round trip as RFC3339: %v", err)
	} else if !expiresAt.After(time.Now()) {
		t.Errorf("envelope expires_at %s is not in the future", expiresAt)
	}
	if got := jsonInt(t, data["ttl_seconds"]); got != tc.TTLSeconds {
		t.Errorf("envelope ttl_seconds is %d, want %d", got, tc.TTLSeconds)
	}
	if got, ok := data["renewable"].(bool); !ok || got != secret.Renewable {
		t.Errorf("envelope says renewable=%v but the lease says %v: a client reading one and "+
			"acting on the other is the failure this disagreement produces", data["renewable"],
			secret.Renewable)
	}

	metadata := nested(t, data, "metadata")
	if got := str(t, metadata, "api_version"); got != credenvelope.APIVersion {
		t.Errorf("envelope api_version is %q, want %q", got, credenvelope.APIVersion)
	}
	if got := str(t, metadata, "minter_set"); got != defaultSet {
		t.Errorf("envelope metadata.minter_set is %q, want %q", got, defaultSet)
	}
	if got := str(t, metadata, "minter_id"); got != liveMinterID {
		t.Errorf("envelope metadata.minter_id is %q, want %q", got, liveMinterID)
	}
}

// assertDistinctIssuance proves two reads produce two credentials. The upstream
// name is built from req.ID, which ONLY core populates — in-process tests either
// leave it empty or invent it (docs/openbao-integration-gaps.md G4).
func assertDistinctIssuance(t *testing.T, first, second *api.Secret) {
	t.Helper()
	if first.LeaseID == second.LeaseID {
		t.Errorf("two reads produced one lease id %q", first.LeaseID)
	}
	if first.Data["credential_id"] == second.Data["credential_id"] {
		t.Errorf("two reads produced the same upstream credential id %v: the name is derived "+
			"from req.ID, so this is core's request id not varying — or not reaching the plugin",
			first.Data["credential_id"])
	}
}

func assertLeaseIsTracked(t *testing.T, c *cluster, leaseID string) {
	t.Helper()
	secret, err := c.client.Sys().Lookup(leaseID)
	if err != nil {
		t.Fatalf("the expiration manager does not know lease %q: %v", leaseID, err)
	}
	if secret.Data["expire_time"] == nil {
		t.Errorf("lease %q has no expire_time: %v", leaseID, secret.Data)
	}
}

func assertRenewContract(t *testing.T, c *cluster, tc e2eCase, leaseID string) {
	t.Helper()
	renewed, err := c.client.Sys().Renew(leaseID, 0)
	if tc.Renewable {
		if err != nil {
			t.Errorf("renewing a renewable lease failed: %v", err)
			return
		}
		if renewed.LeaseID != leaseID {
			t.Errorf("renew returned lease %q, want %q", renewed.LeaseID, leaseID)
		}
		return
	}
	if err == nil {
		t.Errorf("renew succeeded on %q, whose credential expiry is fixed at mint: the lease "+
			"would then outlive the credential (techrfc OBC-002)", leaseID)
	}
}

// assertRevoke revokes through the expiration manager — the production path,
// where in-process tests call the plugin's revoke callback directly.
func assertRevoke(t *testing.T, c *cluster, tc e2eCase, leaseID string, want int) {
	t.Helper()
	if err := c.client.Sys().Revoke(leaseID); err != nil {
		t.Fatalf("revoking lease %q failed: %v", leaseID, err)
	}
	if _, err := c.client.Sys().Lookup(leaseID); err == nil {
		t.Errorf("lease %q still resolves after revocation", leaseID)
	}
	assertUpstream(t, tc, want)

	// A second revoke must be a clean no-op. KI-002 was exactly this wedging
	// forever, and the retry that wedged was the expiration manager's, which
	// only exists at this layer.
	if err := c.client.Sys().Revoke(leaseID); err != nil {
		t.Errorf("revoking lease %q a second time errored (KI-002 class): %v", leaseID, err)
	}
}

// assertReloadThenIssue is KI-001 through core: the backend is rebuilt from
// storage alone, with no config write, and must still issue.
func assertReloadThenIssue(t *testing.T, c *cluster, tc e2eCase, mount string, want int) {
	t.Helper()
	c.reload(pluginBinary(tc.Cloud))

	role := c.read(mount + "/" + rolePath)
	if got := str(t, role.Data, fieldMinterSet); got != defaultSet {
		t.Errorf("after reload the role's minter_set is %q, want %q", got, defaultSet)
	}

	secret := c.read(mount + "/" + issuePath)
	assertLease(t, tc, mount, secret)
	assertEnvelope(t, tc, secret)
	assertUpstream(t, tc, want)
}

func upstreamCount(tc e2eCase) int {
	if tc.Upstream == nil {
		return 0
	}
	return tc.Upstream()
}

// assertUpstream polls the fake until it holds the expected number of
// credentials. The fake runs in this process while the plugin runs in its own,
// so this is a direct read of upstream state rather than an inference.
func assertUpstream(t *testing.T, tc e2eCase, want int) {
	t.Helper()
	if tc.Upstream == nil {
		return
	}
	got := 0
	for range upstreamPollAttempts {
		got = tc.Upstream()
		if got == want {
			return
		}
		time.Sleep(pollInterval)
	}
	t.Errorf("the fake holds %d credentials, want %d", got, want)
}
