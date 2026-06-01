package credentialdo

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	gometrics "github.com/hashicorp/go-metrics"
	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// Local keys for the request paths/fields this test repeats, so the package-wide
// goconst count for these literals stays below threshold.
const (
	pathConfigKey      = "config"
	fieldDOAPIURLKey   = "do_api_url"
	fieldMintersKey    = "minters"
	pathMinterSetWrite = "minter-sets/default"
)

// newObservabilityBackend builds a DO backend via Factory with a buffer-backed
// logger (so warn-logs are assertable) and the given minter-set written through
// the API. minterExpiryWarnSecs is the config threshold in seconds (0 = omit, use default).
func newObservabilityBackend(t *testing.T, minters []interface{}, minterExpiryWarnSecs int) (*backend, *strings.Builder, *gometrics.InmemSink, logical.Storage) {
	t.Helper()
	// capturing metrics sink
	sink := gometrics.NewInmemSink(time.Minute, time.Minute)
	mcfg := gometrics.DefaultConfig("test")
	mcfg.EnableHostname = false
	if _, err := gometrics.NewGlobal(mcfg, sink); err != nil {
		t.Fatalf("install sink: %v", err)
	}

	srv := fakes.NewDOServer()
	t.Cleanup(srv.Close)

	logBuf := &strings.Builder{}
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	config.Logger = hclog.New(&hclog.LoggerOptions{Output: logBuf, Level: hclog.Warn})

	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	bk := b.(*backend)
	storage := config.StorageView

	cfgData := map[string]interface{}{fieldDOAPIURLKey: srv.URL}
	if minterExpiryWarnSecs > 0 {
		cfgData["minter_expiry_warn"] = minterExpiryWarnSecs
	}
	if resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation, Path: pathConfigKey, Storage: storage, Data: cfgData,
	}); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("config write: err=%v resp=%v", err, resp)
	}

	if resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation, Path: pathMinterSetWrite, Storage: storage,
		Data: map[string]interface{}{fieldMintersKey: minters},
	}); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("minter-set write: err=%v resp=%v", err, resp)
	}
	return bk, logBuf, sink, storage
}

func gaugePresent(sink *gometrics.InmemSink, suffix string) bool {
	for _, iv := range sink.Data() {
		for name := range iv.Gauges {
			if strings.Contains(name, suffix) {
				return true
			}
		}
	}
	return false
}

func TestEmitMinterMetrics_AgeGaugeForNeverExpires(t *testing.T) {
	bk, logBuf, sink, _ := newObservabilityBackend(t, []interface{}{
		map[string]interface{}{"id": "m1", minterTokenKey: "dop_v1_x", "never_expires": true},
	}, 0)

	bk.emitMinterMetrics()

	if !gaugePresent(sink, "minter_age_seconds") {
		t.Fatalf("minter_age_seconds gauge not emitted for never_expires minter; gauges: %v", sink.Data())
	}
	if strings.Contains(logBuf.String(), "nearing expiry") {
		t.Fatalf("never_expires minter must not warn; log: %s", logBuf.String())
	}
}

func TestEmitMinterMetrics_WarnsWithinThreshold(t *testing.T) {
	// Two minters >=7d apart so the set validates (>=2 expiring, >=7d gap);
	// the nearer one (3d) is within the 7d warn threshold.
	soon := time.Now().Add(3 * 24 * time.Hour).UTC().Format(time.RFC3339)
	later := time.Now().Add(40 * 24 * time.Hour).UTC().Format(time.RFC3339)
	bk, logBuf, _, _ := newObservabilityBackend(t, []interface{}{
		map[string]interface{}{"id": "m1", minterTokenKey: "dop_v1_x", "expires_at": soon},
		map[string]interface{}{"id": "m2", minterTokenKey: "dop_v1_y", "expires_at": later},
	}, 0) // default 7d threshold

	bk.emitMinterMetrics()

	if !strings.Contains(logBuf.String(), "nearing expiry") {
		t.Fatalf("expected 'nearing expiry' warn for minter expiring in 3d; log: %s", logBuf.String())
	}
}

func TestEmitMinterMetrics_NoWarnOutsideThreshold(t *testing.T) {
	// Both minters far out (>7d), so neither is within the default threshold.
	a := time.Now().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339)
	bExpiry := time.Now().Add(60 * 24 * time.Hour).UTC().Format(time.RFC3339)
	bk, logBuf, _, _ := newObservabilityBackend(t, []interface{}{
		map[string]interface{}{"id": "m1", minterTokenKey: "dop_v1_x", "expires_at": a},
		map[string]interface{}{"id": "m2", minterTokenKey: "dop_v1_y", "expires_at": bExpiry},
	}, 0)

	bk.emitMinterMetrics()

	if strings.Contains(logBuf.String(), "nearing expiry") {
		t.Fatalf("minters expiring in 30d/60d must not warn at 7d threshold; log: %s", logBuf.String())
	}
}

func TestConfig_MinterExpiryWarnRoundTrip(t *testing.T) {
	bk, _, _, storage := newObservabilityBackend(t, []interface{}{
		map[string]interface{}{"id": "m1", minterTokenKey: "dop_v1_x", "never_expires": true},
	}, 86400) // write 1d

	resp, err := bk.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation, Path: pathConfigKey, Storage: storage,
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("config read: err=%v resp=%v", err, resp)
	}
	if got := resp.Data["minter_expiry_warn"]; got != 86400 {
		t.Fatalf("minter_expiry_warn = %v, want 86400", got)
	}
}
