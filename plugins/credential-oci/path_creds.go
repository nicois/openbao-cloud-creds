package credentialoci

import (
	"context"
	"encoding/json"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func (b *backend) credsPaths() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "creds/" + framework.GenericNameRegex("role"),
			Fields: map[string]*framework.FieldSchema{
				"role": {
					Type:        framework.TypeString,
					Description: "Name of the role",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{Callback: b.pathCredsRead},
			},
		},
	}
}

func (b *backend) secretOCI() *framework.Secret {
	return &framework.Secret{
		Type:   "oci_auth_token",
		Revoke: b.pathCredsRevoke,
		Renew:  b.pathCredsRenew,
	}
}

func (b *backend) pathCredsRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get("role").(string)

	// Load role from storage
	entry, err := req.Storage.Get(ctx, "roles/"+roleName)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return logical.ErrorResponse("role_not_found: role %q does not exist", roleName), nil
	}

	var role ociRole
	if err := json.Unmarshal(entry.Value, &role); err != nil {
		return nil, err
	}

	if role.Disabled {
		return logical.ErrorResponse("role_disabled: role %q is disabled", roleName), nil
	}

	// Load all slots and find the freshest active one
	slots, err := loadAllSlots(ctx, req.Storage, roleName, role.SlotCount)
	if err != nil {
		return nil, err
	}

	best := freshestSlot(slots)
	if best == nil {
		return logical.ErrorResponse("no_active_slots: role %q has no active credential slots", roleName), nil
	}

	now := time.Now()

	// TTL = time until this slot's next rotation
	ttlSeconds := int(best.NextRotationAt.Sub(now).Seconds())
	if ttlSeconds < 0 {
		// Slot is overdue for rotation but still usable until rotated
		ttlSeconds = 0
	}

	// Use the configured default_ttl if it's smaller than remaining time
	defaultTTLSec := int(role.DefaultTTL.Seconds())
	if defaultTTLSec > 0 && defaultTTLSec < ttlSeconds {
		ttlSeconds = defaultTTLSec
	}

	expiresAt := best.NextRotationAt

	if b.accessTracker != nil {
		b.mu.RLock()
		var minterID string
		for id := range b.minters {
			minterID = id
			break
		}
		b.mu.RUnlock()
		if minterID != "" {
			b.accessTracker.RecordAccess(minterID, roleName, now)
		}
	}

	emitLeaseIssued(roleName)

	env := credenvelope.NewEnvelope(credenvelope.EnvelopeParams{
		Cloud: "oci",
		Role:  roleName,
		Credential: map[string]interface{}{
			"auth_token": best.TokenValue,
			"user_id":    role.UserOCID,
		},
		ExpiresAt:    expiresAt,
		TTLSeconds:   ttlSeconds,
		Renewable:    false,
		CredentialID: best.TokenID,
		Scope:        role.UserOCID,
		IssuedBy:     "cloud-creds-oci/v0.1",
	})

	resp := b.Secret("oci_auth_token").Response(env.ToMap(), map[string]interface{}{
		"role":       roleName,
		"slot_index": best.SlotIndex,
		"token_id":   best.TokenID,
	})
	resp.Secret.TTL = time.Duration(ttlSeconds) * time.Second
	resp.Secret.MaxTTL = role.MaxTTL

	return resp, nil
}

// pathCredsRevoke is a soft revoke — the plugin forgets the lease but the auth token
// lives until its slot is rotated. This is by design: OCI auth tokens can't be
// individually revoked without breaking other consumers of the same slot.
func (b *backend) pathCredsRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Soft revoke: just forget the lease. The token remains valid until rotation.
	// This is documented behavior — the auth token lives until its slot's next rotation.
	return nil, nil
}

// pathCredsRenew denies renewal — phased rotation credentials are not renewable.
func (b *backend) pathCredsRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return logical.ErrorResponse("oci credentials are not renewable; re-read from creds/ endpoint after rotation"), nil
}
