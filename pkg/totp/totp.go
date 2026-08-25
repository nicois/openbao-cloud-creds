// Package totp generates RFC 6238 time-based one-time passwords, and parses the
// `otpauth://` enrolment URLs seeds are commonly stored as.
//
// Hand-rolled rather than pulled in as a dependency: it is twenty lines of stdlib, it is
// auditable at a glance, and a package that handles a second-factor seed is not somewhere to
// add a transitive dependency tree for convenience. That matches the choice this project
// already made for AWS and GCP request signing.
//
// It lives here rather than in whichever plugin needs it because nothing about it is
// cloud-specific: a cloud whose credential is an interactive login needs a second factor, and
// the algorithm is the same one everywhere. Correctness is checked against RFC 6238's own
// published vectors, which matters more than usual — a wrong code is indistinguishable from a
// wrong password at the far end, and on some clouds a rejected second factor counts towards a
// lockout.
package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

const (
	// Step is the window length: a code is single-use inside it.
	Step   = 30 * time.Second
	digits = 6

	// RFC 4226 dynamic truncation: the low four bits of the last byte give the offset, and
	// the high bit of the extracted word is masked off.
	offsetMask  = 0x0f
	signMask    = 0x7fffffff
	wordLen     = 4
	decimalBase = 10
)

// TOTPCode derives the current code from a base32 seed, as issued by an authenticator
// enrolment. Spaces and lowercase are tolerated because that is how seeds are pasted.
func Code(seed string, at time.Time) (string, error) {
	normalised := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(seed), " ", ""))
	// Authenticator seeds are usually unpadded base32.
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(normalised)
	if err != nil {
		return "", fmt.Errorf("the second-factor seed is not valid base32: %w", err)
	}

	counter := uint64(at.UTC().Unix()) / uint64(Step.Seconds())
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)

	mac := hmac.New(sha1.New, key)
	// hash.Hash.Write never returns an error, by the interface's own contract.
	_, _ = mac.Write(buf[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & offsetMask
	truncated := binary.BigEndian.Uint32(sum[offset:offset+wordLen]) & signMask

	mod := uint32(1)
	for range digits {
		mod *= decimalBase
	}
	return fmt.Sprintf("%0*d", digits, truncated%mod), nil
}

// SecondsUntilNextTOTPWindow reports how long until the current code expires. A probe that
// burns its window on a failed request should wait rather than retry immediately with the
// same code, which the server will reject as replayed.
func SecondsUntilNextWindow(at time.Time) time.Duration {
	step := int64(Step.Seconds())
	elapsed := at.UTC().Unix() % step
	return time.Duration(step-elapsed) * time.Second
}
