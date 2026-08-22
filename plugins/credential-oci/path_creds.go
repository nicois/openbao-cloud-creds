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
			Pattern: "creds/" + framework.GenericNameRegex(fieldRole),
			Fields: map[string]*framework.FieldSchema{
				fieldRole: {
					Type:        framework.TypeString,
					Description: descRoleName,
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
		// No Renew callback, deliberately: framework.Secret.Renewable() is (Renew
		// != nil) and that is the flag the LEASE carries, so a callback that only
		// ever returns an error would still advertise renewable=true — and OpenBao
		// REVOKES a lease whose renewal fails, destroying the credential the
		// client was trying to keep. A slot's credential lives until that slot's
		// next scheduled rotation, so the lease is non-renewable and core refuses
		// renewal before the plugin is reached (docs/ttl-semantics.md).
	}
}

func (b *backend) pathCredsRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get(fieldRole).(string)

	// Load role from storage
	entry, err := req.Storage.Get(ctx, "roles/"+roleName)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return credenvelope.ErrorResponse(credenvelope.ErrRoleNotFound, "role %q does not exist", roleName), nil
	}

	var role ociRole
	if err := json.Unmarshal(entry.Value, &role); err != nil {
		return nil, err
	}

	if role.Disabled {
		return credenvelope.ErrorResponse(credenvelope.ErrRoleDisabled, "role %q is disabled", roleName), nil
	}

	// Load all slots and find the freshest active one
	slots, err := loadAllSlots(ctx, req.Storage, roleName, role.SlotCount)
	if err != nil {
		return nil, err
	}

	now := time.Now()

	best := freshestSlot(slots, now)
	if best == nil {
		return credenvelope.ErrorResponse(credenvelope.ErrPoolExhausted, "role %q has no active credential slots", roleName), nil
	}

	// TTL = time until this slot's next rotation. freshestSlot has already
	// excluded overdue slots, so NextRotationAt is guaranteed in the future.
	ttlSeconds := int(best.NextRotationAt.Sub(now).Seconds())

	// Use the configured default_ttl if it's smaller than remaining time
	defaultTTLSec := int(role.DefaultTTL.Seconds())
	if defaultTTLSec > 0 && defaultTTLSec < ttlSeconds {
		ttlSeconds = defaultTTLSec
	}

	// expires_at MUST agree with ttl_seconds. It used to be the slot's next
	// rotation unconditionally while ttl_seconds was clamped to default_ttl, so a
	// 15m role with three days to rotation returned ttl_seconds=900 alongside an
	// expires_at three days out — and a client that schedules its refresh from
	// expires_at (which the envelope invites: it is the field README points at)
	// overstated its lease by days (A24 in docs/audit-2026-08-22.md).
	expiresAt := now.Add(time.Duration(ttlSeconds) * time.Second)

	// Provenance comes from the slot itself — the read does not call the cloud.
	if b.accessTracker != nil && best.MinterSet != "" && best.MinterID != "" {
		b.accessTracker.RecordAccess(best.MinterSet+"/"+best.MinterID, roleName, now)
	}

	emitLeaseIssued(roleName)

	env := credenvelope.NewEnvelope(credenvelope.EnvelopeParams{
		Cloud: cloudName,
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
		MinterSet:    best.MinterSet,
		MinterID:     best.MinterID,
	})

	resp := b.Secret("oci_auth_token").Response(env.ToMap(), map[string]interface{}{
		fieldRole:      roleName,
		fieldSlotIndex: best.SlotIndex,
		"token_id":     best.TokenID,
		fieldMinterSet: best.MinterSet,
		"minter_id":    best.MinterID,
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
