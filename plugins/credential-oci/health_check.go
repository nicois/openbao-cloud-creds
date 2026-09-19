package credentialoci

import (
	"context"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/nicois/openbao-cloud-creds/pkg/recovery"
)

func (b *backend) healthCheckWorker(ctx context.Context) error {
	b.mu.RLock()
	type probe struct {
		set, id, token string
		sm             *recovery.StateMachine
	}
	var probes []probe
	for setName, states := range b.minterSets {
		for id, ms := range states {
			if ms.sm.NeedsHealthCheck(time.Now()) {
				probes = append(probes, probe{setName, id, ms.minter.Token, ms.sm})
			}
		}
	}
	b.mu.RUnlock()

	now := time.Now()
	for _, p := range probes {
		client := b.newOCIClient(p.token)
		// GetUser verifies the minter credentials are valid. The minter ID is the
		// configured credential identifier, used as a stand-in user reference.
		//
		// RecordUpstream, not RecordError(401). Every failure here used to be recorded as a rejected
		// login, whatever it was. This worker only probes a minter NeedsHealthCheck already found
		// auth-failing, so that never blocked a write the minter's state was not blocking anyway -- but
		// it did keep the minter indicted on evidence about the network, and inflate the count an
		// operator reads to decide whether the credential itself needs replacing. Now the classifier
		// decides: a rejected login counts, an unreachable upstream does not.
		// StatusNone is what this plugin already passes elsewhere (path_roles.go, path_rotate_slot.go):
		// the OCI client surfaces errors without an HTTP status, so the classifier works from the error.
		if err := client.GetUser(ctx, p.id); err != nil {
			p.sm.RecordUpstream(credenvelope.StatusNone, err, now)
		} else {
			p.sm.RecordSuccess(now)
		}
	}

	b.emitMinterMetrics()

	return nil
}
