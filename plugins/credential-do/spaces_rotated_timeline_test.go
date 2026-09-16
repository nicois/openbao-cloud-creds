package credentialdo

import (
	"net/http"
	"testing"
	"testing/synctest"
	"time"

	gometrics "github.com/hashicorp/go-metrics"
	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// The rotated Spaces lifecycle is measured in DAYS — ninety to a rotation, forty-eight hours of
// overlap — and every other test here reaches it by backdating the stored deadlines, which is
// deliberate: the seams exercise the same durable state a restart rehydrates, where a fake clock
// would prove the suite's own arithmetic instead (AGENTS.md).
//
// What backdating cannot express is a TIMELINE: many rotations in sequence, each scheduled from
// the previous one's mint with a jitter rolled once, and the retiring population as it actually
// evolves. That is what this covers, in a testing/synctest bubble where ninety days pass in
// microseconds.
//
// Two constraints of the bubble shape the setup, both learned by measurement rather than read:
//
//   - The fake is started OUTSIDE the bubble. Its goroutines are then not in the bubble, so they
//     cannot stop it idling. A request in flight simply means the clock waits, which is harmless.
//   - Keep-alives are disabled, via the httpTransport seam. A pooled idle connection leaves a
//     readLoop blocked on a real socket, and a goroutine blocked on I/O is never "durably
//     blocked", so the bubble never idles and the clock never advances. With pooling left on this
//     test hangs at the first sleep rather than failing — which is how it was diagnosed.
func TestRotatedSpacesTimeline_RotationsComposeAcrossASequence(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()
	// go-metrics' global sink is a PROCESS global, and the read path emits on it. Inside a bubble
	// its interval bookkeeping creates a channel that belongs to the bubble, which a later test
	// emitting from outside then touches — "close of synctest channel from outside bubble", a fatal
	// error found by running the package under -race. A sink that allocates nothing avoids it
	// entirely. Left installed: every test here that asserts on metrics installs its own sink as
	// its first act, so none of them depends on this one.
	mcfg := gometrics.DefaultConfig("timeline")
	mcfg.EnableHostname = false
	if _, err := gometrics.NewGlobal(mcfg, &gometrics.BlackholeSink{}); err != nil {
		t.Fatalf("installing a blackhole metrics sink: %v", err)
	}

	original := httpTransport
	httpTransport = &http.Transport{DisableKeepAlives: true}
	t.Cleanup(func() { httpTransport = original })

	// Pinned, so the rotation dates are arithmetic rather than a distribution: a 90-day period
	// less half of a 24-hour jitter puts every rotation 89.5 days after the last mint, and 730
	// days holds exactly eight of them.
	originalJitter := jitterFraction
	jitterFraction = func() float64 { return 0.5 }
	t.Cleanup(func() { jitterFraction = originalJitter })

	synctest.Test(t, func(t *testing.T) {
		b, storage := timelineBackend(t, srv.URL)
		// The config write starts the background workers, and this bubble OWNS them: their
		// goroutines must exit before the root does or the bubble panics with blocked goroutines
		// remaining. They are stopped immediately rather than left running, for cost: the sweeper
		// ticks every five minutes of virtual time, so leaving it on makes the bubble step through
		// ~58,000 wakeups for a 200-day span and the test takes 30s under -race instead of 1s. The
		// sweeper's own correctness is already asserted by the rotation conformance category, which
		// drives it through Harness.SweepRetiredCredentials; what a timeline adds is composition,
		// and that needs a sequence rather than a live ticker.
		b.stopWorkers()

		const (
			period  = 90 * 24 * time.Hour
			overlap = 48 * time.Hour
			// Two years, which holds eight rotations at the pinned 89.5-day effective period.
			// Affordable because the bubble steps once per simulated day rather than once per
			// five simulated minutes: the whole span runs in tens of milliseconds.
			days = 2 * 365
		)

		read := func() string {
			t.Helper()
			resp, err := b.HandleRequest(t.Context(), &logical.Request{
				Operation: logical.ReadOperation, Path: "creds/timeline", Storage: storage,
			})
			if err != nil || resp == nil || resp.IsError() {
				t.Fatalf("read at %v: err=%v resp=%v", time.Now(), err, resp)
			}
			cred, ok := resp.Data["credential"].(map[string]interface{})
			if !ok {
				t.Fatalf("no credential object at %v: %v", time.Now(), resp.Data)
			}
			return cred["access_key_id"].(string)
		}

		// A client that polls daily for two years, as a droplet does.
		seen := map[string]bool{}
		var rotations int
		current := read()
		seen[current] = true
		for day := range days {
			time.Sleep(24 * time.Hour)
			// The lifecycle advanced by hand, once per simulated day, exactly as the conformance
			// seam does it.
			if err := b.sweepSharedSpacesKeys(t.Context(), storage); err != nil {
				t.Fatalf("sweep on day %d: %v", day, err)
			}
			got := read()
			if got != current {
				rotations++
				if seen[got] {
					t.Fatalf("day %d: rotation re-served a key already retired (%s)", day, got)
				}
				seen[got] = true
				current = got
			}
		}

		// 730 days at an effective 89.5-day period (90 less half the pinned jitter) holds exactly
		// eight rotations, each detected by the first daily read after it comes due.
		const wantRotations = 8
		if rotations != wantRotations {
			t.Errorf("%d rotations across %d days at a %v period less a pinned half-jitter; want %d",
				rotations, days, period, wantRotations)
		}

		// Every key but the current one should be gone upstream: each was retired, its overlap
		// elapsed long ago, and the sweep ran on every simulated day since. This is what a
		// timeline buys that backdating cannot — it holds across the whole sequence rather than
		// for one hand-placed deadline.
		state, err := loadSharedSpacesState(t.Context(), storage, "timeline")
		if err != nil {
			t.Fatalf("loading the record: %v", err)
		}
		if state.Current == nil || state.Current.AccessKey != current {
			t.Errorf("the record serves %v, want the key the client last read (%s)", state.Current, current)
		}
		if len(state.Retiring) != 0 {
			t.Errorf("%d keys still recorded as retiring after %d days of daily sweeps; every "+
				"overlap in this span elapsed long ago: %+v", len(state.Retiring), days, state.Retiring)
		}
		// The assertion that actually matters, and the one a record-only check misses: the retired
		// keys are gone UPSTREAM. A Spaces key has no expiry, so a key we stopped tracking but
		// never deleted is an orphan forever, and it is the record that would look clean.
		if got := srv.ProvisionedSpacesKeyCount(); got != 1 {
			t.Errorf("%d Spaces keys exist upstream after %d rotations; want 1, the one being "+
				"served — the rest were retired and should have been deleted", got, rotations)
		}
		for k := range seen {
			if k == current {
				continue
			}
			if srv.HasSpacesKey(k) {
				t.Errorf("retired key %s still exists upstream", k)
			}
		}
		if len(seen) != rotations+1 {
			t.Errorf("saw %d distinct keys across %d rotations", len(seen), rotations)
		}
		t.Logf("%d simulated days: %d rotations, %d distinct keys, %d still retiring", days,
			rotations, len(seen), len(state.Retiring))
	})
}

func timelineBackend(t *testing.T, apiURL string) (*backend, logical.Storage) {
	t.Helper()
	cfg := logical.TestBackendConfig()
	cfg.StorageView = &logical.InmemStorage{}
	raw, err := Factory(t.Context(), cfg)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	storage := cfg.StorageView
	for _, w := range []struct {
		path string
		data map[string]interface{}
	}{
		{"config", map[string]interface{}{fieldDOAPIURLKey: apiURL, fieldVerifyCapability: false}},
		{"minter-sets/default", map[string]interface{}{fieldMintersKey: []interface{}{
			map[string]interface{}{
				"id": "timeline-minter", minterTokenKey: "dop_v1_timeline", neverExpiresKey: true,
			},
		}}},
		{"roles/timeline", map[string]interface{}{
			"credential_type": credentialTypeSpacesKeyRotated,
			"grants":          "timeline-bucket:read",
			"region":          "nyc3",
			"rotation_period": int((90 * 24 * time.Hour).Seconds()),
			"rotation_jitter": int((24 * time.Hour).Seconds()),
			"overlap_ttl":     int((48 * time.Hour).Seconds()),
			"minter_set":      "default",
			"default_ttl":     900,
			"max_ttl":         3600,
		}},
	} {
		resp, err := raw.HandleRequest(t.Context(), &logical.Request{
			Operation: logical.UpdateOperation, Path: w.path, Storage: storage, Data: w.data,
		})
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("write %s: err=%v resp=%v", w.path, err, resp)
		}
	}
	return raw.(*backend), storage
}
