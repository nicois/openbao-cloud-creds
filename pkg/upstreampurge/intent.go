package upstreampurge

import (
	"context"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// Arm records an operator's decision to purge a role and returns the fresh intent, replacing
// any earlier one — the operator is asking about the leak they have now, so this call's
// cutoff is the one that applies.
//
// It persists before anything is deleted. A purge that deleted first and recorded afterwards
// would, on a node that died in between, leave credentials destroyed and nothing saying a
// purge had ever been asked for.
func Arm(ctx context.Context, storage logical.Storage, prefix, role string, now time.Time) (*Intent, error) {
	cutoff := now.UTC()
	records, err := Scan(ctx, storage, prefix, role, cutoff)
	if err != nil {
		return nil, err
	}
	intent := &Intent{
		Role:    role,
		ArmedAt: cutoff,
		// The same instant: the operator's question is "destroy what has been issued", and
		// what has been issued is what exists as they ask.
		Cutoff:  cutoff,
		Tracked: len(records),
		// A role with nothing outstanding is already in the state the operator asked for.
		Complete: len(records) == 0,
	}
	if err := SaveIntent(ctx, storage, intent); err != nil {
		return nil, err
	}
	return intent, nil
}

// Advance runs one bounded pass for an armed intent, updates the intent in place and in
// storage, and returns what the pass did. A finished purge is left alone: the intent is kept
// after completion so the outcome stays readable, and a worker sweeping every stored intent
// must not read that record as work.
//
// The role and the cutoff come from the intent rather than from the caller, so a pass can only
// ever cover what the operator armed — a caller cannot widen the scope of a purge already
// under way, which is what makes it terminate.
func (i *Intent) Advance(ctx context.Context, storage logical.Storage, prefix string, maxDeletes int, del Deleter) (Result, error) {
	if i.Complete {
		return Result{}, nil
	}
	result, err := Pass(ctx, storage, Config{
		Prefix:     prefix,
		Role:       i.Role,
		Cutoff:     i.Cutoff,
		MaxDeletes: maxDeletes,
	}, del)
	if err != nil {
		return result, err
	}
	i.Deleted += result.Deleted
	// This pass's failures, not a running total: the question progress answers is whether it
	// is STILL going wrong, which a total stops answering after the first successful retry.
	i.Failed = result.Failed
	i.Complete = result.Complete()
	if err := SaveIntent(ctx, storage, i); err != nil {
		return result, err
	}
	return result, nil
}

// Progress renders a role's purge for a reader, deriving what is left in scope rather than
// trusting a stored count. That is what keeps a finished purge finished on a mount that has
// gone on issuing: the new credentials are past the cutoff, so they are not remaining work.
func Progress(ctx context.Context, storage logical.Storage, prefix, role string) (map[string]any, error) {
	intent, err := LoadIntent(ctx, storage, role)
	if err != nil {
		return nil, err
	}
	if intent == nil {
		return NoIntentReport(role), nil
	}
	records, err := Scan(ctx, storage, prefix, role, intent.Cutoff)
	if err != nil {
		return nil, err
	}
	return intent.Report(len(records)), nil
}
