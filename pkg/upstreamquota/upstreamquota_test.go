package upstreamquota_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/upstreamquota"
)

func headers(pairs ...string) http.Header {
	h := http.Header{}
	for i := 0; i+1 < len(pairs); i += 2 {
		h.Set(pairs[i], pairs[i+1])
	}
	return h
}

var now = time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)

// TestObserveReadsTheHeadersActuallySeen uses the exact spelling and values recorded from a real
// response, so a change in what we parse fails against evidence rather than against a guess.
func TestObserveReadsTheHeadersActuallySeen(t *testing.T) {
	// Verbatim from probe/testdata: Ratelimit-Limit 10000, Ratelimit-Remaining 9943,
	// Ratelimit-Reset 1788340528. Note the vendor's capitalisation differs from the draft's; Go
	// canonicalises both, and this test exists partly to pin that it does.
	o := upstreamquota.Observe(headers(
		"Ratelimit-Limit", "10000", "Ratelimit-Remaining", "9943", "Ratelimit-Reset", "1788340528"))
	if !o.Found {
		t.Fatal("the recorded headers were not recognised at all")
	}
	if o.Limit != 10000 || o.Remaining != 9943 {
		t.Errorf("read limit=%d remaining=%d, want 10000/9943", o.Limit, o.Remaining)
	}
	if o.ResetAt.IsZero() {
		t.Error("the reset was not parsed")
	}
}

// TestNoHeadersMeansNoInformation: most clouds send nothing, and that must never read as "no quota".
func TestNoHeadersMeansNoInformation(t *testing.T) {
	o := upstreamquota.Observe(http.Header{})
	if o.Found {
		t.Error("an empty response reported a quota observation")
	}
	if o.Low(0.5) {
		t.Error("an absent observation reported a low quota, which would warn about every cloud " +
			"that does not send these headers")
	}
	if got := o.Describe(now); !strings.Contains(got, "no quota headers") {
		t.Errorf("Describe() = %q, which does not say the information is missing", got)
	}
}

// TestLowNeedsALimitToBeMeaningful: an absolute count says nothing on its own — 500 remaining is
// nearly nothing out of 600 and nearly everything out of 600000.
func TestLowNeedsALimitToBeMeaningful(t *testing.T) {
	o := upstreamquota.Observe(headers("Ratelimit-Remaining", "5"))
	if !o.Found {
		t.Fatal("Remaining alone should still count as an observation")
	}
	if o.Low(0.2) {
		t.Error("reported a low quota with no limit to compare against; a threshold on an absolute " +
			"count fires constantly on a small quota and never on a large one")
	}
	if got := o.Describe(now); !strings.Contains(got, "did not say of how many") {
		t.Errorf("Describe() = %q, which does not admit the limit is unknown", got)
	}
}

func TestLowFiresBelowTheFraction(t *testing.T) {
	cases := map[string]struct {
		remaining string
		want      bool
	}{
		"plenty":      {"9000", false},
		"exactly at":  {"2000", false},
		"just below":  {"1999", true},
		"nearly gone": {"3", true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			o := upstreamquota.Observe(headers("Ratelimit-Limit", "10000", "Ratelimit-Remaining", tc.remaining))
			if got := o.Low(0.2); got != tc.want {
				t.Errorf("Low(0.2) with %s/10000 = %v, want %v", tc.remaining, got, tc.want)
			}
		})
	}
}

// TestTheReporterWarnsOncePerWindow is what makes this usable. A mount running near its ceiling
// would otherwise log on every request, and an alert that fires continuously gets switched off.
func TestTheReporterWarnsOncePerWindow(t *testing.T) {
	reporter := &upstreamquota.Reporter{}
	low := upstreamquota.Observe(headers(
		"Ratelimit-Limit", "1000", "Ratelimit-Remaining", "5", "Ratelimit-Reset", "1788340528"))

	if first := reporter.Report(low, now); first == "" {
		t.Fatal("the first low observation produced no warning")
	}
	for i := range 50 {
		if again := reporter.Report(low, now); again != "" {
			t.Fatalf("warned again within the same window on call %d: %q", i+2, again)
		}
	}

	// A new window is a new warning: the quota reset and is being consumed again.
	next := upstreamquota.Observe(headers(
		"Ratelimit-Limit", "1000", "Ratelimit-Remaining", "5", "Ratelimit-Reset", "1788344128"))
	if got := reporter.Report(next, now); got == "" {
		t.Error("did not warn in a NEW window; a quota exhausted window after window would be " +
			"reported once ever")
	}
}

// TestAHealthyQuotaSaysNothing: silence is the common case and must stay silent.
func TestAHealthyQuotaSaysNothing(t *testing.T) {
	reporter := &upstreamquota.Reporter{}
	healthy := upstreamquota.Observe(headers("Ratelimit-Limit", "10000", "Ratelimit-Remaining", "9900"))
	for range 10 {
		if got := reporter.Report(healthy, now); got != "" {
			t.Fatalf("warned about a healthy quota: %q", got)
		}
	}
}

// TestAPastResetIsReportedNotReinterpreted: the draft permits the reset to be a delta in seconds
// rather than an epoch. Guessing between the two would silently mislead, so an implausible value is
// described as implausible.
func TestAPastResetIsReportedNotReinterpreted(t *testing.T) {
	o := upstreamquota.Observe(headers(
		"Ratelimit-Limit", "100", "Ratelimit-Remaining", "1", "Ratelimit-Reset", "60"))
	got := o.Describe(now)
	if !strings.Contains(got, "already past") || !strings.Contains(got, "delta") {
		t.Errorf("Describe() = %q; a reset in 1970 should be called out rather than shown as a "+
			"reset time", got)
	}
	if o.Window(now) != 0 {
		t.Errorf("Window() = %v for a reset in the past, want 0", o.Window(now))
	}
}
