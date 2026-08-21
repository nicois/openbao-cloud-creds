package credentialgcp

import (
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	gometrics "github.com/hashicorp/go-metrics"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// Local keys for the request paths/fields this test repeats, so the package-wide
// goconst count for these literals stays below threshold.
const (
	pathConfigKey      = "config"
	fieldMintersKey    = "minters"
	pathMinterSetWrite = "minter-sets/default"
	fieldExpiresAt     = "expires_at"
	minterCredsJSONA   = "{\"k\":1}"
	minterCredsJSONB   = "{\"k\":2}"
)

// newObservabilityBackend builds a GCP backend via Factory with a buffer-backed
// logger (so warn-logs are assertable) and the given minter-set written through the
// API. GCP is an injected-client plugin with no HTTP fake: a nil IAM client is
// injected and the minter-set write path does not call GCP, so minters load into
// b.minterSets directly and emitMinterMetrics can run without a live endpoint.
// minterExpiryWarnSecs is the config threshold in seconds (0 = omit, use default).
func newObservabilityBackend(t *testing.T, minters []interface{}, minterExpiryWarnSecs int) (*backend, *strings.Builder, *gometrics.InmemSink, logical.Storage) {
	t.Helper()
	sink := gometrics.NewInmemSink(time.Minute, time.Minute)
	mcfg := gometrics.DefaultConfig("test")
	mcfg.EnableHostname = false
	if _, err := gometrics.NewGlobal(mcfg, sink); err != nil {
		t.Fatalf("install sink: %v", err)
	}

	logBuf := &strings.Builder{}
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	config.Logger = hclog.New(&hclog.LoggerOptions{Output: logBuf, Level: hclog.Warn})

	b, err := Factory(t.Context(), config)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	bk := b.(*backend)
	// Inject a fake IAM client so selection does not build a real GCP client.
	bk.iamClientFn = func(string) IAMCredentialsClient { return nil }
	storage := config.StorageView

	cfgData := map[string]interface{}{}
	if minterExpiryWarnSecs > 0 {
		cfgData["minter_expiry_warn"] = minterExpiryWarnSecs
	}
	if resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: pathConfigKey, Storage: storage, Data: cfgData,
	}); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("config write: err=%v resp=%v", err, resp)
	}

	if resp, err := b.HandleRequest(t.Context(), &logical.Request{
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
		map[string]interface{}{"id": "m1", minterCredentialsJSONKey: minterCredsJSONA, "never_expires": true},
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
		map[string]interface{}{"id": "m1", minterCredentialsJSONKey: minterCredsJSONA, fieldExpiresAt: soon},
		map[string]interface{}{"id": "m2", minterCredentialsJSONKey: minterCredsJSONB, fieldExpiresAt: later},
	}, 0)

	bk.emitMinterMetrics()

	if !strings.Contains(logBuf.String(), "nearing expiry") {
		t.Fatalf("expected 'nearing expiry' warn for minter expiring in 3d; log: %s", logBuf.String())
	}
}

func TestEmitMinterMetrics_NoWarnOutsideThreshold(t *testing.T) {
	a := time.Now().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339)
	bExpiry := time.Now().Add(60 * 24 * time.Hour).UTC().Format(time.RFC3339)
	bk, logBuf, _, _ := newObservabilityBackend(t, []interface{}{
		map[string]interface{}{"id": "m1", minterCredentialsJSONKey: minterCredsJSONA, fieldExpiresAt: a},
		map[string]interface{}{"id": "m2", minterCredentialsJSONKey: minterCredsJSONB, fieldExpiresAt: bExpiry},
	}, 0)

	bk.emitMinterMetrics()

	if strings.Contains(logBuf.String(), "nearing expiry") {
		t.Fatalf("minters expiring in 30d/60d must not warn at 7d threshold; log: %s", logBuf.String())
	}
}

func TestConfig_MinterExpiryWarnRoundTrip(t *testing.T) {
	bk, _, _, storage := newObservabilityBackend(t, []interface{}{
		map[string]interface{}{"id": "m1", minterCredentialsJSONKey: minterCredsJSONA, "never_expires": true},
	}, 86400)

	resp, err := bk.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.ReadOperation, Path: pathConfigKey, Storage: storage,
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("config read: err=%v resp=%v", err, resp)
	}
	if got := resp.Data["minter_expiry_warn"]; got != 86400 {
		t.Fatalf("minter_expiry_warn = %v, want 86400", got)
	}
}
