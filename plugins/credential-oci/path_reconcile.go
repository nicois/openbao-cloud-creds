package credentialoci

import (
	"context"
	"encoding/json"
	"strings"
	"time"

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

func (b *backend) pathReconcile(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	mode := d.Get("mode").(string)
	dryRun := mode == "dry_run"

	if b.anyHealthyMinter() == nil {
		return logical.ErrorResponse("cannot reconcile: no healthy minter available"), nil
	}

	// List all roles
	roleNames, err := req.Storage.List(ctx, "roles/")
	if err != nil {
		return nil, err
	}

	// Collect all known token IDs from slot storage
	knownTokenIDs := make(map[string]bool)
	for _, roleName := range roleNames {
		roleEntry, err := req.Storage.Get(ctx, "roles/"+roleName)
		if err != nil {
			continue
		}
		if roleEntry == nil {
			continue
		}
		var role ociRole
		if err := json.Unmarshal(roleEntry.Value, &role); err != nil {
			continue
		}
		slots, err := loadAllSlots(ctx, req.Storage, roleName, role.SlotCount)
		if err != nil {
			continue
		}
		for _, s := range slots {
			if s.TokenID != "" {
				knownTokenIDs[s.TokenID] = true
			}
		}
	}

	// For each role, list upstream tokens and find orphans
	orphansFound := 0
	deleted := 0
	maxDeletes := 10

	b.mu.RLock()
	if b.config != nil {
		maxDeletes = b.config.MaxDeletesPerPass
	}
	b.mu.RUnlock()

	for _, roleName := range roleNames {
		roleEntry, err := req.Storage.Get(ctx, "roles/"+roleName)
		if err != nil {
			continue
		}
		if roleEntry == nil {
			continue
		}
		var role ociRole
		if err := json.Unmarshal(roleEntry.Value, &role); err != nil {
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

		for _, t := range tokens {
			// Only consider tokens with our prefix
			if !strings.HasPrefix(t.Description, ociTokenPrefix) {
				continue
			}
			// If not in our known set, it's an orphan
			if !knownTokenIDs[t.ID] {
				orphansFound++
				if !dryRun && deleted < maxDeletes {
					if err := client.DeleteAuthToken(ctx, role.UserOCID, t.ID); err == nil {
						deleted++
					}
				}
			}
		}
	}

	now := time.Now()
	_ = now

	emitOrphansFound(orphansFound)

	return &logical.Response{
		Data: map[string]interface{}{
			"mode":          mode,
			"dry_run":       dryRun,
			"orphans_found": orphansFound,
			"deleted":       deleted,
			"hit_limit":     deleted >= maxDeletes,
		},
	}, nil
}
