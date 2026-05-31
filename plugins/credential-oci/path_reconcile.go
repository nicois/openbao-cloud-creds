package credentialoci

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const ociTokenPrefix = "cloud-creds-"

func (b *backend) reconcilePaths() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "reconcile",
			Fields: map[string]*framework.FieldSchema{
				"mode": {
					Type:        framework.TypeString,
					Default:     "normal",
					Description: "Run mode: normal or dry_run",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{Callback: b.pathReconcile},
			},
		},
	}
}

// maxDeletesForPass returns the per-pass orphan-delete cap, honoring the
// configured override when present.
func (b *backend) maxDeletesForPass() int {
	maxDeletes := maxDeletesPerPass
	b.mu.RLock()
	if b.config != nil {
		maxDeletes = b.config.MaxDeletesPerPass
	}
	b.mu.RUnlock()
	return maxDeletes
}

// loadRole reads and unmarshals a role by name. Returns (nil, false) for any
// read/parse error or a missing entry, matching the callers' skip-on-error
// behavior.
func loadRole(ctx context.Context, storage logical.Storage, roleName string) (*ociRole, bool) {
	roleEntry, err := storage.Get(ctx, "roles/"+roleName)
	if err != nil || roleEntry == nil {
		return nil, false
	}
	var role ociRole
	if err := json.Unmarshal(roleEntry.Value, &role); err != nil {
		return nil, false
	}
	return &role, true
}

// collectKnownTokenIDs builds the set of token IDs currently recorded in slot
// storage across all given roles.
func collectKnownTokenIDs(ctx context.Context, storage logical.Storage, roleNames []string) map[string]bool {
	knownTokenIDs := make(map[string]bool)
	for _, roleName := range roleNames {
		role, ok := loadRole(ctx, storage, roleName)
		if !ok {
			continue
		}
		slots, err := loadAllSlots(ctx, storage, roleName, role.SlotCount)
		if err != nil {
			continue
		}
		for _, s := range slots {
			if s.TokenID != "" {
				knownTokenIDs[s.TokenID] = true
			}
		}
	}
	return knownTokenIDs
}

// reconcileResult tallies a reconcile pass.
type reconcileResult struct {
	orphansFound int
	deleted      int
}

// reconcilePass bundles the inputs and running tally of a single reconcile
// sweep so the per-role/per-token helpers stay within the argument limit.
type reconcilePass struct {
	knownTokenIDs map[string]bool
	dryRun        bool
	maxDeletes    int
	result        reconcileResult
}

// reconcileOrphans lists upstream tokens for every role and deletes those that
// carry our owner prefix but are not recorded in slot storage. When dryRun is
// true no deletes are issued, but orphans are still counted. deleted never
// exceeds maxDeletes.
func (b *backend) reconcileOrphans(ctx context.Context, storage logical.Storage, roleNames []string, pass *reconcilePass) reconcileResult {
	for _, roleName := range roleNames {
		role, ok := loadRole(ctx, storage, roleName)
		if !ok {
			continue
		}

		// List/delete via a healthy minter from the role's bound set.
		_, client, selErr := b.selectMinterForSet(role.MinterSet)
		if selErr != nil {
			continue
		}

		tokens, err := client.ListAuthTokens(ctx, role.UserOCID)
		if err != nil {
			continue
		}

		pass.reconcileRoleTokens(ctx, client, role, tokens)
	}
	return pass.result
}

// reconcileRoleTokens scans one role's upstream tokens, counting orphans (ours
// by prefix, not recorded in slot storage) and deleting them unless the pass is
// a dry run, up to maxDeletes total across the pass.
func (p *reconcilePass) reconcileRoleTokens(ctx context.Context, client OCIIAMClient, role *ociRole, tokens []AuthTokenInfo) {
	for _, t := range tokens {
		// Only consider tokens with our prefix.
		if !strings.HasPrefix(t.Description, ociTokenPrefix) {
			continue
		}
		// If not in our known set, it's an orphan.
		if p.knownTokenIDs[t.ID] {
			continue
		}
		p.result.orphansFound++
		if !p.dryRun && p.result.deleted < p.maxDeletes {
			if err := client.DeleteAuthToken(ctx, role.UserOCID, t.ID); err == nil {
				p.result.deleted++
			}
		}
	}
}

func (b *backend) pathReconcile(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	mode := d.Get("mode").(string)
	dryRun := mode == "dry_run"

	if b.anyHealthyMinter() == nil {
		return logical.ErrorResponse("cannot reconcile: no healthy minter available"), nil
	}

	roleNames, err := req.Storage.List(ctx, "roles/")
	if err != nil {
		return nil, err
	}

	maxDeletes := b.maxDeletesForPass()
	pass := &reconcilePass{
		knownTokenIDs: collectKnownTokenIDs(ctx, req.Storage, roleNames),
		dryRun:        dryRun,
		maxDeletes:    maxDeletes,
	}
	res := b.reconcileOrphans(ctx, req.Storage, roleNames, pass)

	emitOrphansFound(res.orphansFound)

	return &logical.Response{
		Data: map[string]interface{}{
			"mode":          mode,
			"dry_run":       dryRun,
			"orphans_found": res.orphansFound,
			"deleted":       res.deleted,
			"hit_limit":     res.deleted >= maxDeletes,
		},
	}, nil
}
