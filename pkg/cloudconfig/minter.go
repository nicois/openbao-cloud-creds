package cloudconfig

import (
	"fmt"
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
}

func ValidateMinterSet(minters []Minter) error {
	if len(minters) == 0 {
		return fmt.Errorf("minter set must not be empty")
	}

	hasNeverExpires := false
	var expiring []Minter

	for _, m := range minters {
		if m.NeverExpires {
			hasNeverExpires = true
		} else if !m.ExpiresAt.IsZero() {
			expiring = append(expiring, m)
		} else {
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
