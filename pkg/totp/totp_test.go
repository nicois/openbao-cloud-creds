package totp

import (
	"strings"
	"testing"
	"time"
)

// RFC 6238's own test vectors, so a wrong second-factor code is a test failure here rather
// than a mysterious rejection while holding real credentials — and a burned single-use window.
func TestTOTPMatchesRFC6238(t *testing.T) {
	// The RFC's SHA-1 key is the ASCII "12345678901234567890", base32-encoded.
	const seed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

	cases := map[int64]string{
		59:         "287082",
		1111111109: "081804",
		1111111111: "050471",
		1234567890: "005924",
		2000000000: "279037",
	}
	for unix, want := range cases {
		got, err := Code(seed, time.Unix(unix, 0))
		if err != nil {
			t.Fatalf("at T=%d: %v", unix, err)
		}
		if got != want {
			t.Errorf("at T=%d: got %s, want %s", unix, got, want)
		}
	}
}

// A seed pasted from an enrolment screen arrives with spaces and in either case.
func TestTOTPToleratesHowSeedsAreActuallyPasted(t *testing.T) {
	const canonical = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	at := time.Unix(59, 0)
	want, err := Code(canonical, at)
	if err != nil {
		t.Fatalf("canonical seed failed: %v", err)
	}
	for _, variant := range []string{
		strings.ToLower(canonical),
		"gezd gnbv gy3t qojq gezd gnbv gy3t qojq",
		"  " + canonical + "  ",
	} {
		got, err := Code(variant, at)
		if err != nil {
			t.Errorf("seed %q was rejected: %v", variant, err)
			continue
		}
		if got != want {
			t.Errorf("seed %q produced %s, want %s", variant, got, want)
		}
	}
}

// The probe waits for a fresh window rather than replaying a code the server will reject.
func TestSecondsUntilNextWindow(t *testing.T) {
	if got := SecondsUntilNextWindow(time.Unix(30, 0)); got != Step {
		t.Errorf("at the start of a window, got %s, want %s", got, Step)
	}
	if got := SecondsUntilNextWindow(time.Unix(59, 0)); got != time.Second {
		t.Errorf("one second before a boundary, got %s, want 1s", got)
	}
}
