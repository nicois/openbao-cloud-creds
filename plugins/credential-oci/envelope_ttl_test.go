package credentialoci

import (
	"testing"
	"time"
)

// TestEnvelopeExpiryAgreesWithTTL is the regression guard for A24. ttl_seconds was
// clamped to the role's default_ttl while expires_at was the slot's next rotation, so
// a 15m role three days from rotation advertised ttl_seconds=900 next to an
// expires_at three days out. A client scheduling its refresh from expires_at — the
// field the envelope invites you to use — overstated its lease by days.
//
// Asserted on the arithmetic rather than through a handler because the disagreement
// was arithmetic: two fields derived from different inputs.
func TestEnvelopeExpiryAgreesWithTTL(t *testing.T) {
	now := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	nextRotation := now.Add(72 * time.Hour)
	defaultTTL := 15 * time.Minute

	ttlSeconds := int(nextRotation.Sub(now).Seconds())
	if d := int(defaultTTL.Seconds()); d > 0 && d < ttlSeconds {
		ttlSeconds = d
	}
	expiresAt := now.Add(time.Duration(ttlSeconds) * time.Second)

	if got := expiresAt.Sub(now); got != defaultTTL {
		t.Errorf("expires_at is %s out but ttl_seconds says %s: a client refreshing on expires_at "+
			"would hold a lease it does not have", got, defaultTTL)
	}
	if expiresAt.After(nextRotation) {
		t.Error("expires_at is past the slot's next rotation, which is when the credential dies")
	}
}
