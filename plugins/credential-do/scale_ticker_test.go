//go:build scale

package credentialdo

import (
	"net/http"
	"os"
	"runtime"
	"strconv"
	"testing"
	"testing/synctest"
	"time"

	gometrics "github.com/hashicorp/go-metrics"
	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// What the five-minute lifecycle tick actually costs, with the real worker running, at fleet
// scale — and what it costs in memory to keep it running.
//
// Tagged `scale` because it is seconds-to-minutes rather than milliseconds and has no place in the
// default suite. It is deliberately NOT a skipped test: run it on purpose (`make test-scale`) and
// TRACK the numbers, because whether the sweeper needs an index is a question about this
// measurement rather than about the shape of the loop.
//
// A testing/synctest bubble is what makes it possible at all: the tick fires every five minutes of
// VIRTUAL time, so a day of ticks — 288 of them — costs only the real work each one does. Outside
// a bubble, measuring a day of ticking takes a day.
//
// The measurement is arranged so the clock can be read honestly. time.Now() inside a bubble is
// virtual, so the roles are seeded OUTSIDE it and only the ticking happens within, timed from
// outside by the ordinary clock.

const (
	defaultScaleRoles = 100_000
	// Advance is measured in TICKS rather than days so a large fleet can be measured without a
	// long run: the per-tick cost is what scales, and the log extrapolates a full day from it.
	defaultScaleTicks = 288
	ticksPerDay       = int(24 * time.Hour / sharedSpacesSweepInterval)
)

func scaleEnvInt(t *testing.T, name string, def int) int {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		t.Fatalf("%s=%q is not a number: %v", name, v, err)
	}
	return n
}

func TestScale_TickerCostWithTheWorkerRunning(t *testing.T) {
	roles := scaleEnvInt(t, "SCALE_ROLES", defaultScaleRoles)
	ticks := scaleEnvInt(t, "SCALE_TICKS", defaultScaleTicks)

	srv := fakes.NewDOServer()
	defer srv.Close()

	// go-metrics' global sink allocates bubble-owned interval channels when emitted to from
	// inside one; a sink that allocates nothing avoids the cross-test fatal that causes.
	mcfg := gometrics.DefaultConfig("scale")
	mcfg.EnableHostname = false
	if _, err := gometrics.NewGlobal(mcfg, &gometrics.BlackholeSink{}); err != nil {
		t.Fatalf("installing a blackhole metrics sink: %v", err)
	}
	// A pooled idle connection leaves a readLoop blocked on a real socket, which is never durably
	// blocked, so the bubble would never idle and its clock would never advance.
	originalTransport := httpTransport
	httpTransport = &http.Transport{DisableKeepAlives: true}
	t.Cleanup(func() { httpTransport = originalTransport })

	storage := &logical.InmemStorage{}

	var beforeSeed, afterSeed runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&beforeSeed)
	seedStart := time.Now()
	// The retiring fraction the lifecycle actually produces: a key spends overlap_ttl of every
	// rotation_period in retirement, so one role in period/overlap has something retiring at any
	// moment. Seeding a made-up fraction would measure a fleet that does not exist.
	retiringEvery := int((90 * 24 * time.Hour) / (48 * time.Hour))
	seedRotatedRoles(t, storage, roles, retiringEvery)
	seedWall := time.Since(seedStart)
	runtime.GC()
	runtime.ReadMemStats(&afterSeed)

	var afterRun runtime.MemStats

	// Timed from OUT here, where the clock is real. Everything inside is virtual.
	runStart := time.Now()
	synctest.Test(t, func(t *testing.T) {
		b := scaleBackendOn(t, storage, srv.URL)
		// The workers stay RUNNING — they are the subject. Stopped at the end because the bubble
		// owns them and every goroutine it owns must exit before its root returns.
		defer b.stopWorkers()

		time.Sleep(time.Duration(ticks) * sharedSpacesSweepInterval)
		synctest.Wait()
		runtime.ReadMemStats(&afterRun)
	})
	runWall := time.Since(runStart)

	perTick := runWall / time.Duration(max(ticks, 1))
	perTickPerRole := float64(perTick.Nanoseconds()) / float64(roles)
	dayOfTicks := time.Duration(ticksPerDay) * perTick

	t.Logf("roles=%d seeded in %v; storage heap %.0f MiB (%.0f B/role, harness storage included)",
		roles, seedWall.Round(time.Millisecond),
		float64(afterSeed.HeapAlloc-beforeSeed.HeapAlloc)/1024/1024,
		float64(afterSeed.HeapAlloc-beforeSeed.HeapAlloc)/float64(roles))
	t.Logf("%d ticks (%v of virtual time) in %v real: %v per tick, %.1f ns per tick per role",
		ticks, (time.Duration(ticks) * sharedSpacesSweepInterval).Round(time.Minute),
		runWall.Round(time.Millisecond), perTick.Round(time.Microsecond), perTickPerRole)
	t.Logf("a REAL day of ticking (%d ticks) would cost %v of CPU = %.3f%% of one core",
		ticksPerDay, dayOfTicks.Round(time.Millisecond),
		float64(dayOfTicks)/float64(24*time.Hour)*100)
	t.Logf("heap after the run %.0f MiB (peak sys %.0f MiB)",
		float64(afterRun.HeapAlloc)/1024/1024, float64(afterRun.HeapSys)/1024/1024)

	// A floor under the measurement itself: a run where the worker never fired would report a
	// flattering zero rather than failing.
	if ticks == 0 || runWall <= 0 {
		t.Fatalf("no ticks measured (ticks=%d wall=%v): the worker did not run", ticks, runWall)
	}
}

// scaleBackendOn builds a backend over storage that has ALREADY been seeded, writing only the two
// entries that must go through the API because they are what start the workers.
func scaleBackendOn(t *testing.T, storage logical.Storage, apiURL string) *backend {
	t.Helper()
	cfg := logical.TestBackendConfig()
	cfg.StorageView = storage
	raw, err := Factory(t.Context(), cfg)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	for _, w := range []struct {
		path string
		data map[string]interface{}
	}{
		{"config", map[string]interface{}{fieldDOAPIURLKey: apiURL, fieldVerifyCapability: false}},
		{"minter-sets/default", map[string]interface{}{fieldMintersKey: []interface{}{
			map[string]interface{}{
				"id": benchMinterID, minterTokenKey: "dop_v1_scale", neverExpiresKey: true,
			},
		}}},
	} {
		resp, err := raw.HandleRequest(t.Context(), &logical.Request{
			Operation: logical.UpdateOperation, Path: w.path, Storage: storage, Data: w.data,
		})
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("write %s: err=%v resp=%v", w.path, err, resp)
		}
	}
	return raw.(*backend)
}
