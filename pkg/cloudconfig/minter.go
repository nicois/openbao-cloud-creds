package cloudconfig

import (
	"fmt"
	"regexp"
	"sort"
	"time"
)

const MinMinterGap = 7 * 24 * time.Hour

type Minter struct {
	ID            string    `json:"id"`
	Token         string    `json:"token"`
	ExpiresAt     time.Time `json:"expires_at,omitempty"`
	ExpiresSource string    `json:"expires_at_source,omitempty"`
	NeverExpires  bool      `json:"never_expires,omitempty"`
	CreatedAt     time.Time `json:"created_at"`

	Retired        bool              `json:"retired,omitempty"`
	RetiredAt      time.Time         `json:"retired_at,omitempty"`
	RotationParams map[string]string `json:"rotation_params,omitempty"`
}

// MinterSet is a named, independently-validated group of minter credentials.
// Roles bind to exactly one set; the plugin mints only from that set's minters.
type MinterSet struct {
	Versioned
	Name    string   `json:"name"`
	Minters []Minter `json:"minters"`
}

var setNameRe = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// ValidateSetName checks that a minter-set name is non-empty and uses only
// the characters permitted in an OpenBao path segment.
func ValidateSetName(name string) error {
	if name == "" {
		return fmt.Errorf("minter set name must not be empty")
	}
	if !setNameRe.MatchString(name) {
		return fmt.Errorf("minter set name %q must match [a-zA-Z0-9_-]+", name)
	}
	return nil
}

// ActiveMinters returns the non-retired minters. Retirement is a soft state set
// by rotation; retired minters stay in the set (and upstream-alive) during the
// grace window but are excluded from validation and new-issuance selection.
func ActiveMinters(minters []Minter) []Minter {
	active := make([]Minter, 0, len(minters))
	for i := range minters {
		if !minters[i].Retired {
			active = append(active, minters[i])
		}
	}
	return active
}

func ValidateMinterSet(minters []Minter) error {
	active := ActiveMinters(minters)
	if len(active) == 0 {
		return fmt.Errorf("minter set must not be empty")
	}

	hasNeverExpires := false
	var expiring []Minter

	for i := range active {
		m := active[i]
		switch {
		case m.NeverExpires:
			hasNeverExpires = true
		case !m.ExpiresAt.IsZero():
			expiring = append(expiring, m)
		default:
			return fmt.Errorf("minter %s has neither expires_at nor never_expires=true", m.ID)
		}
	}

	if hasNeverExpires {
		return nil
	}

	if len(expiring) < 2 {
		return fmt.Errorf("minter set with expiring minters must have >=2 minters (or include a never_expires minter)")
	}

	sort.Slice(expiring, func(i, j int) bool {
		return expiring[i].ExpiresAt.Before(expiring[j].ExpiresAt)
	})

	for i := 1; i < len(expiring); i++ {
		gap := expiring[i].ExpiresAt.Sub(expiring[i-1].ExpiresAt)
		if gap < MinMinterGap {
			return fmt.Errorf("minters %s and %s have expiry gap %v, minimum is %v",
				expiring[i-1].ID, expiring[i].ID, gap, MinMinterGap)
		}
	}

	return nil
}
