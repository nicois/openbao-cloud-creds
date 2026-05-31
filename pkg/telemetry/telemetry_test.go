package telemetry_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	gometrics "github.com/hashicorp/go-metrics"

	"github.com/nicois/openbao-cloud-creds/pkg/telemetry"
)

func newCapturingSink(t *testing.T) *gometrics.InmemSink {
	t.Helper()
	sink := gometrics.NewInmemSink(time.Minute, time.Minute)
	cfg := gometrics.DefaultConfig("test")
	cfg.EnableHostname = false
	if _, err := gometrics.NewGlobal(cfg, sink); err != nil {
		t.Fatalf("install sink: %v", err)
	}
	return sink
}

func assertLabel(t *testing.T, labels []gometrics.Label, name, val string) {
	t.Helper()
	for _, l := range labels {
		if l.Name == name {
			if l.Value != val {
				t.Fatalf("label %q: want %q, got %q", name, val, l.Value)
			}
			return
		}
	}
	t.Fatalf("label %q not present in %v", name, labels)
}

func TestEmitter_Counter(t *testing.T) {
	sink := newCapturingSink(t)
	e := telemetry.Emitter{Cloud: "do", Namespace: "cloud_creds"}
	e.LeaseIssued("role-a")
	found := false
	for _, iv := range sink.Data() {
		for name, sample := range iv.Counters {
			if strings.Contains(name, "cloud_creds.lease_issued_total") {
				found = true
				assertLabel(t, sample.Labels, "cloud", "do")
				assertLabel(t, sample.Labels, "role", "role-a")
			}
		}
	}
	if !found {
		t.Fatalf("lease_issued_total counter not found in %v", sink.Data())
	}
}

func TestEmitter_Gauge(t *testing.T) {
	sink := newCapturingSink(t)
	e := telemetry.Emitter{Cloud: "aws", Namespace: "cloud_creds"}
	e.OrphansFound(3)
	found := false
	for _, iv := range sink.Data() {
		for name, sample := range iv.Gauges {
			if strings.Contains(name, "cloud_creds.orphans_found") {
				found = true
				if sample.Value != 3 {
					t.Fatalf("orphans_found: want 3, got %v", sample.Value)
				}
				assertLabel(t, sample.Labels, "cloud", "aws")
			}
		}
	}
	if !found {
		t.Fatal("orphans_found gauge not found")
	}
}

func TestEmitter_WorkerError(t *testing.T) {
	sink := newCapturingSink(t)
	e := telemetry.Emitter{Cloud: "oci", Namespace: "cloud_creds"}
	e.WorkerError("rotation", errors.New("boom"))
	found := false
	for _, iv := range sink.Data() {
		for name, sample := range iv.Counters {
			if strings.Contains(name, "cloud_creds.worker_errors_total") {
				found = true
				assertLabel(t, sample.Labels, "cloud", "oci")
				assertLabel(t, sample.Labels, "worker", "rotation")
			}
		}
	}
	if !found {
		t.Fatal("worker_errors_total counter not found")
	}
}
