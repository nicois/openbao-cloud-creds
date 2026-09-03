// Package upstreamquota reads what a cloud says about our remaining request quota, so a plugin can
// see a ceiling approaching instead of discovering it as a 429.
//
// # Why bother, given 429s are already handled
//
// They are: a 429 opens a cooldown, the minter stops being selectable, and callers get
// upstream_quota_exceeded with the wait. That is the right behaviour *once it happens*. The problem
// is that by then the mount is already failing, and the remedy — spreading load across more minter
// accounts — takes human time to arrange. A warning that arrives with the outage is not a warning.
//
// Many clouds volunteer the answer on every response, under the IETF draft names
// (`RateLimit-Limit`, `RateLimit-Remaining`, `RateLimit-Reset`). Reading them costs nothing: the
// headers are already on a response the plugin has already received.
//
// # Case does not matter
//
// Go canonicalises header names on both sides of an exchange, so `Ratelimit-Limit` and
// `RateLimit-Limit` are one lookup. That is worth stating because the two spellings appear in
// different vendors' documentation and the difference is invisible through net/http.
package upstreamquota

import (
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// The IETF draft header names, which is what the clouds seen here use.
const (
	HeaderLimit     = "RateLimit-Limit"
	HeaderRemaining = "RateLimit-Remaining"
	HeaderReset     = "RateLimit-Reset"
)

// Observation is what one response said about our quota. Found is false when the response carried no
// quota headers at all, which is most clouds most of the time — callers must treat that as "no
// information", never as "no quota".
type Observation struct {
	Limit     int
	Remaining int
	// ResetAt is when the window rolls over. Zero when the header was absent or unparseable.
	ResetAt time.Time
	Found   bool
}

// Observe reads the quota headers from a response.
//
// A partial answer still counts: some vendors send Remaining without Limit. Found means "Remaining
// was present and parsed", because Remaining is the only field a decision can be made from.
func Observe(header http.Header) Observation {
	remaining, err := strconv.Atoi(header.Get(HeaderRemaining))
	if err != nil {
		return Observation{}
	}
	observation := Observation{Remaining: remaining, Found: true}
	if limit, err := strconv.Atoi(header.Get(HeaderLimit)); err == nil {
		observation.Limit = limit
	}
	if reset, err := strconv.ParseInt(header.Get(HeaderReset), 10, 64); err == nil && reset > 0 {
		// Seconds since the epoch in the responses seen here. The draft also permits a delta in
		// seconds; a delta would land far in the past, which Describe reports honestly rather than
		// silently reinterpreting — guessing between the two encodings is how a monitor lies.
		observation.ResetAt = time.Unix(reset, 0).UTC()
	}
	return observation
}

// Low reports whether the remaining quota has fallen below the given fraction of the limit.
//
// False when there is no observation, and false when the limit is unknown: a caller cannot tell
// "500 remaining" is low without knowing whether the ceiling is 600 or 600000, and inventing a
// threshold on an absolute count would fire constantly on a small quota and never on a large one.
func (o Observation) Low(fraction float64) bool {
	if !o.Found || o.Limit <= 0 {
		return false
	}
	return float64(o.Remaining) < float64(o.Limit)*fraction
}

// Window returns how long until the quota resets, or zero if unknown. Negative durations are
// returned as zero: a reset already in the past means the window has rolled over, not that time is
// owed.
func (o Observation) Window(now time.Time) time.Duration {
	if o.ResetAt.IsZero() {
		return 0
	}
	if remaining := o.ResetAt.Sub(now); remaining > 0 {
		return remaining
	}
	return 0
}

// Describe renders the observation for a log line. It says what was actually seen, including when
// the reset looks implausible, so an operator is not quietly shown a reinterpretation.
func (o Observation) Describe(now time.Time) string {
	if !o.Found {
		return "the upstream reported no quota headers"
	}
	if o.Limit <= 0 {
		return fmt.Sprintf("%d requests remaining (the upstream did not say of how many)", o.Remaining)
	}
	base := fmt.Sprintf("%d of %d requests remaining", o.Remaining, o.Limit)
	switch {
	case o.ResetAt.IsZero():
		return base
	case o.ResetAt.Before(now):
		return base + fmt.Sprintf(", and the reported reset (%s) is already past — the header may be "+
			"a delta rather than an epoch", o.ResetAt.Format(time.RFC3339))
	default:
		return base + fmt.Sprintf(", resetting in %s", o.Window(now).Round(time.Second))
	}
}

// Reporter warns at most once per quota window, so a mount running near its ceiling produces one log
// line per window rather than one per request — which is the difference between a signal and a
// reason to switch off the alert.
type Reporter struct {
	// Fraction is the level below which Report warns. Zero uses DefaultFraction.
	Fraction float64

	lastWarnedWindow time.Time
}

// DefaultFraction is the level at which a quota is worth mentioning: a fifth left. Late enough not
// to be noise, early enough that adding a minter account is a considered action.
const DefaultFraction = 0.2

// Report returns a message to log, or "" if there is nothing worth saying yet. The caller decides
// severity and adds its own context (which cloud, which minter).
func (r *Reporter) Report(o Observation, now time.Time) string {
	fraction := r.Fraction
	if fraction <= 0 {
		fraction = DefaultFraction
	}
	if !o.Low(fraction) {
		return ""
	}
	// One warning per window. An unknown reset degrades to one warning ever, which is the safe
	// direction: better under-reported than a log line per request.
	if !o.ResetAt.IsZero() && o.ResetAt.Equal(r.lastWarnedWindow) {
		return ""
	}
	if o.ResetAt.IsZero() && !r.lastWarnedWindow.IsZero() {
		return ""
	}
	r.lastWarnedWindow = o.ResetAt
	if r.lastWarnedWindow.IsZero() {
		r.lastWarnedWindow = now
	}
	return o.Describe(now)
}
